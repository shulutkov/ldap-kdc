package ldapsrv

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/glauth/ldap"
	"github.com/go-krb5/krb5/gssapi"
	"github.com/go-krb5/krb5/keytab"
	"github.com/go-krb5/krb5/service"
	"github.com/go-krb5/krb5/spnego"

	"github.com/shulutkov/ldap-kdc/internal/krbkeys"
	"github.com/shulutkov/ldap-kdc/internal/store"
)

// SASL GSSAPI binds: a client that already holds a Kerberos ticket presents it instead of a
// password. RFC 4752.
//
// This directory is in an unusual position for an acceptor, and it is what makes this cheap: it IS
// the KDC. The key of its own service principal is in its own store, so there is no keytab file to
// write, distribute or rotate, and AcceptSecContext is a local lookup.
//
// The exchange takes three legs, and the middle one surprises people:
//
//  1. the client sends an AP-REQ; the directory verifies it and answers with an AP-REP, which is
//     what proves to the CLIENT that it reached the directory and not something wearing its name;
//  2. the client, having nothing more to establish, sends an EMPTY token; the directory answers
//     with the security layers it offers, wrapped;
//  3. the client sends back the one layer it selected, wrapped; the directory checks it and the
//     bind completes.
//
// Only "no security layer" is offered. SASL protection of the messages would duplicate what
// StartTLS and LDAPS already do, Active Directory refuses the combination outright (MS-ADTS
// 5.1.1.1), and a layer this directory offered but could not honour would be worse than none.

// saslMechanism is the one mechanism this directory speaks. GSS-SPNEGO would wrap the same tokens
// in a mechanism list, which buys nothing when there is one mechanism to choose from.
const saslMechanism = "GSSAPI"

// saslHandshakeTimeout is how long an unfinished handshake is remembered. A client that starts one
// and goes away leaves state behind, so the state is swept rather than kept.
const saslHandshakeTimeout = time.Minute

// saslExchange is one handshake in progress, kept between legs on the connection that owns it.
type saslExchange struct {
	started time.Time
	// principal is the client's Kerberos name, known from leg one onwards.
	principal string
	// sess protects the per-message tokens of legs two and three. Integrity, not none: the
	// negotiation tokens are integrity-protected wrap tokens even though the layer being
	// negotiated is none.
	sess *gssapi.SecurityLayerSession
	// challenged reports whether the security layers have been offered, which is what separates
	// leg two from leg three.
	challenged bool
}

// BindSASL implements ldap.SASLBinder: one leg of a SASL bind per call.
func (h *Handler) BindSASL(mechanism string, credentials []byte, conn net.Conn) (ldap.LDAPResultCode, []byte, string, error) {
	start := time.Now()
	defer func() { h.metrics.LDAPDuration.WithLabelValues("bind").Observe(time.Since(start).Seconds()) }()

	ctx := context.Background()
	src := sourceAddr(conn)

	if h.limiter.Blocked(src) {
		h.result("bind", "blocked")

		return ldap.LDAPResultUnwillingToPerform, nil, "", nil
	}

	if len(h.cfg.SPN) == 0 {
		h.log.Info().Str("src", src).Str("mechanism", mechanism).
			Msg("SASL bind refused: this directory has no service principal configured (server.ldap_spn)")
		h.result("bind", "sasl-disabled")

		return ldap.LDAPResultAuthMethodNotSupported, nil, "", nil
	}

	if !strings.EqualFold(mechanism, saslMechanism) {
		h.log.Info().Str("src", src).Str("mechanism", mechanism).Msg("SASL bind refused: unknown mechanism")
		h.result("bind", "sasl-mechanism")

		return ldap.LDAPResultAuthMethodNotSupported, nil, "", nil
	}

	ex := h.exchange(conn)

	switch {
	case ex == nil:
		return h.saslAccept(ctx, conn, credentials, src)
	case !ex.challenged:
		return h.saslOfferLayers(conn, ex, src)
	default:
		return h.saslComplete(ctx, conn, ex, credentials, src)
	}
}

// saslAccept is leg one: the client's AP-REQ, answered with an AP-REP.
func (h *Handler) saslAccept(ctx context.Context, conn net.Conn, credentials []byte, src string) (ldap.LDAPResultCode, []byte, string, error) {
	kt, err := h.serviceKeytab(ctx)
	if err != nil {
		h.log.Error().Err(err).Str("spn", h.cfg.SPN).Msg("SASL bind: cannot build the service keytab")
		h.result("bind", "sasl-keytab")

		return ldap.LDAPResultOperationsError, nil, "", nil
	}

	var tok spnego.KRB5Token
	if err := tok.Unmarshal(credentials); err != nil {
		h.log.Info().Err(err).Str("src", src).Msg("SASL bind refused: the token is not a Kerberos token")
		h.limiter.NoteFailure(src)
		h.result("bind", "sasl-malformed")

		return ldap.LDAPResultInvalidCredentials, nil, "", nil
	}
	if !tok.IsAPReq() {
		h.log.Info().Str("src", src).Msg("SASL bind refused: the first token is not an AP-REQ")
		h.limiter.NoteFailure(src)
		h.result("bind", "sasl-malformed")

		return ldap.LDAPResultInvalidCredentials, nil, "", nil
	}

	settings := service.NewSettings(kt, service.KeytabPrincipal(h.cfg.SPN))

	ok, creds, err := service.VerifyAPREQ(&tok.APReq, settings)
	if err != nil || !ok {
		// The client is told invalid credentials and nothing more; the operator is told which
		// ticket failed and why, because a clock skew and a wrong service key look identical from
		// the outside and differ entirely in what to do about them.
		h.log.Info().Err(err).Str("src", src).Str("spn", h.cfg.SPN).
			Msg("SASL bind refused: the ticket did not verify")
		h.limiter.NoteFailure(src)
		h.result("bind", "sasl-bad-ticket")

		return ldap.LDAPResultInvalidCredentials, nil, "", nil
	}

	// The AP-REP proves to the client that this side could decrypt the ticket, which only the
	// holder of the service key can do. Mutual authentication is not optional here: a client that
	// asked for it and got nothing back would be right to refuse the exchange.
	rep, err := tok.APRepToken()
	if err != nil {
		h.log.Error().Err(err).Str("src", src).Msg("SASL bind: cannot answer the AP-REQ")
		h.result("bind", "sasl-reply")

		return ldap.LDAPResultOperationsError, nil, "", nil
	}

	sess, err := h.saslSession(&tok)
	if err != nil {
		h.log.Error().Err(err).Str("src", src).Msg("SASL bind: cannot protect the exchange")
		h.result("bind", "sasl-session")

		return ldap.LDAPResultOperationsError, nil, "", nil
	}

	h.rememberExchange(conn, &saslExchange{
		started:   time.Now(),
		principal: creds.UserName(),
		sess:      sess,
	})

	return ldap.LDAPResultSaslBindInProgress, rep, "", nil
}

// saslOfferLayers is leg two: the client sent an empty token, and the directory answers with the
// security layers it offers and the largest buffer it would accept.
func (h *Handler) saslOfferLayers(conn net.Conn, ex *saslExchange, src string) (ldap.LDAPResultCode, []byte, string, error) {
	// One octet of offered layers, then three of maximum buffer. Only "none" is offered, so the
	// buffer is zero: there is nothing to buffer.
	challenge, err := ex.sess.Wrap([]byte{byte(gssapi.SecurityLayerNone), 0, 0, 0})
	if err != nil {
		h.forgetExchange(conn)
		h.log.Error().Err(err).Str("src", src).Msg("SASL bind: cannot offer the security layers")
		h.result("bind", "sasl-session")

		return ldap.LDAPResultOperationsError, nil, "", nil
	}
	ex.challenged = true

	return ldap.LDAPResultSaslBindInProgress, challenge, "", nil
}

// saslComplete is leg three: the client's selection, and the identity it bound as.
func (h *Handler) saslComplete(ctx context.Context, conn net.Conn, ex *saslExchange, credentials []byte, src string) (ldap.LDAPResultCode, []byte, string, error) {
	defer h.forgetExchange(conn)

	reply, err := ex.sess.Unwrap(credentials)
	if err != nil {
		h.log.Info().Err(err).Str("src", src).Str("principal", ex.principal).
			Msg("SASL bind refused: the client's selection does not verify")
		h.limiter.NoteFailure(src)
		h.result("bind", "sasl-malformed")

		return ldap.LDAPResultInvalidCredentials, nil, "", nil
	}
	if len(reply) < 4 {
		h.log.Info().Str("src", src).Int("bytes", len(reply)).Msg("SASL bind refused: the selection is too short")
		h.result("bind", "sasl-malformed")

		return ldap.LDAPResultProtocolError, nil, "", nil
	}
	if gssapi.SecurityLayer(reply[0])&gssapi.SecurityLayerNone == 0 {
		h.log.Info().Str("src", src).Str("principal", ex.principal).
			Msgf("SASL bind refused: the client selected layers %#02x, and this directory offers none but %s",
				reply[0], gssapi.SecurityLayerNone)
		h.result("bind", "sasl-layer")

		return ldap.LDAPResultInappropriateAuthentication, nil, "", nil
	}
	// An authorization identity asks to act as somebody else, which this directory has no model
	// for. Ignoring it would bind the caller as itself while the caller believes otherwise.
	if authzid := strings.TrimSpace(string(reply[4:])); len(authzid) > 0 {
		h.log.Info().Str("src", src).Str("principal", ex.principal).Str("authzid", authzid).
			Msg("SASL bind refused: this directory does not let a caller act as another account")
		h.result("bind", "sasl-authzid")

		return ldap.LDAPResultInappropriateAuthentication, nil, "", nil
	}

	user, dn, err := h.accountForPrincipal(ctx, ex.principal)
	if err != nil {
		h.log.Error().Err(err).Str("principal", ex.principal).Msg("SASL bind: the directory could not be read")
		h.result("bind", "sasl-store")

		return ldap.LDAPResultOperationsError, nil, "", nil
	}
	if user == nil {
		// The ticket is genuine and the principal is this realm's; it simply corresponds to no
		// account here, so there is no authorization state to bind to. Said plainly in the
		// journal, because the fix is a directory change and not a client one.
		h.log.Info().Str("src", src).Str("principal", ex.principal).
			Msg("SASL bind refused: the principal authenticated but names no account in this directory")
		h.result("bind", "sasl-no-account")

		return ldap.LDAPResultInvalidCredentials, nil, "", nil
	}

	h.limiter.NoteSuccess(src)
	h.log.Info().Str("src", src).Str("principal", ex.principal).Str("dn", dn).Msg("SASL bind")
	h.result("bind", "sasl-ok")

	return ldap.LDAPResultSuccess, nil, dn, nil
}

// EnsureServicePrincipal makes sure the directory holds the key a SASL bind is verified against.
//
// It is created here rather than expected of an operator because this directory is its own KDC:
// the principal is a row in the same store, keyed randomly, and nothing has to leave the process.
// A deployment that names a principal it never created would otherwise fail every SASL bind with
// "the ticket did not verify", which reads as a client fault and is not one.
func (h *Handler) EnsureServicePrincipal(ctx context.Context) error {
	if len(h.cfg.SPN) == 0 {
		return nil
	}

	name, err := krbkeys.ParseName(h.cfg.SPN, h.cfg.Realm)
	if err != nil {
		return fmt.Errorf("ldap: spn: %w", err)
	}
	if len(name.Components) != 2 || !strings.EqualFold(name.Components[0], "ldap") {
		return fmt.Errorf("ldap: spn %q must be ldap/<host name the directory is reached by>", h.cfg.SPN)
	}
	if !strings.EqualFold(name.Realm, h.cfg.Realm) {
		return fmt.Errorf("ldap: spn %s is not in realm %s", name, h.cfg.Realm)
	}

	p, err := h.st.GetPrincipal(ctx, name)
	switch {
	case err == nil:
		// A principal that IS an account would make the directory's own service key a credential
		// somebody can be given, which is a different thing from a service key.
		if p.UserID != nil {
			return fmt.Errorf("ldap: spn %s names a directory account, not a service", name)
		}

		return nil
	case !errors.Is(err, store.ErrNotFound):
		return err
	}

	keys, err := krbkeys.RandomKeys(h.cfg.EncTypes)
	if err != nil {
		return err
	}

	if err := h.st.CreatePrincipal(ctx, &store.Principal{
		Name: name.Principal(), Realm: name.Realm, Enabled: true, RequiresPreAuth: true,
	}, keys); err != nil {
		return fmt.Errorf("ldap: creating %s: %w", name, err)
	}

	h.log.Info().Str("spn", name.String()).Msg("created the service principal SASL GSSAPI binds are accepted for")

	return nil
}

// saslSession builds the per-message session of the established context.
//
// The key is the authenticator's subkey when the client sent one and the ticket's session key
// otherwise, which is RFC 4121 section 4.2.2. The acceptor's own message sequence starts at the
// number the AP-REP carries, which is the number the client's authenticator named.
func (h *Handler) saslSession(tok *spnego.KRB5Token) (*gssapi.SecurityLayerSession, error) {
	key := tok.APReq.Ticket.DecryptedEncPart.Key
	if sub := tok.APReq.Authenticator.SubKey; len(sub.KeyValue) > 0 {
		key = sub
	}
	if len(key.KeyValue) == 0 {
		return nil, fmt.Errorf("the verified ticket carries no session key")
	}

	var seq uint64
	if n := tok.APReq.Authenticator.SeqNumber; n > 0 {
		seq = uint64(n)
	}

	return gssapi.NewSecurityLayerSession(key, gssapi.SecurityLayerIntegrity, false, 0,
		gssapi.InitialSendSequenceNumber(seq))
}

// accountForPrincipal maps an authenticated Kerberos name to the directory account it binds as, and
// to that account's DN.
//
// A user principal is its own account. A SERVICE principal — a machine's, say — is one only if it
// was linked to an account, which is the directory's way of saying "this service acts as this
// account". An unlinked service principal authenticates and binds as nobody, on purpose: the
// authorization state a bind establishes belongs to an account, and inventing one for a service
// would be inventing its capabilities too.
func (h *Handler) accountForPrincipal(ctx context.Context, principal string) (*store.User, string, error) {
	name, err := krbkeys.ParseName(principal, h.cfg.Realm)
	if err != nil {
		return nil, "", nil //nolint:nilerr // an unparseable name is not this directory's account
	}

	account := strings.Join(name.Components, "/")
	if len(name.Components) > 1 {
		// A service principal: the account is whatever it was linked to.
		p, err := h.st.GetPrincipal(ctx, name)
		if err != nil {
			return nil, "", nil //nolint:nilerr // no such principal here
		}
		if len(p.UserName) == 0 {
			return nil, "", nil
		}
		account = p.UserName
	}

	user, err := h.st.GetUser(ctx, account)
	if err != nil {
		return nil, "", nil //nolint:nilerr // no such account
	}
	if user.Disabled {
		return nil, "", nil
	}

	group, err := h.st.GetGroupByGID(ctx, user.PrimaryGroup)
	if err != nil {
		return nil, "", err
	}

	return user, strings.ToLower(h.entries.UserDN(user, group.Name)), nil
}

// serviceKeytab builds the keytab of this directory's own LDAP service principal from the store.
//
// Built per handshake, for the same reason the console builds its own per sign-in: a re-keyed
// principal is honoured at once, and the previous key version is included so a ticket issued just
// before the change still verifies.
func (h *Handler) serviceKeytab(ctx context.Context) (*keytab.Keytab, error) {
	name, err := krbkeys.ParseName(h.cfg.SPN, h.cfg.Realm)
	if err != nil {
		return nil, fmt.Errorf("ldap: spn: %w", err)
	}

	p, err := h.st.GetPrincipal(ctx, name)
	if err != nil {
		return nil, err
	}

	generations := [][]krbkeys.Key{p.Keys}
	kvnos := []int{p.KVNO}

	if p.KVNO > 1 {
		if prev, err := h.st.GetPrincipalKVNO(ctx, name, p.KVNO-1); err == nil && len(prev.Keys) > 0 {
			generations = append(generations, prev.Keys)
			kvnos = append(kvnos, p.KVNO-1)
		}
	}

	var entries []krbkeys.KeytabEntry

	for i, keys := range generations {
		for _, k := range keys {
			entries = append(entries, krbkeys.KeytabEntry{Name: name, KVNO: kvnos[i], Key: k, Timestamp: time.Now()})
		}
	}

	raw, err := krbkeys.MarshalKeytab(entries)
	if err != nil {
		return nil, err
	}

	kt := keytab.New()
	if err := kt.Unmarshal(raw); err != nil {
		return nil, err
	}

	return kt, nil
}

// The handshakes in flight, one per connection. A SASL bind is several requests on one connection,
// and nothing else in this handler has state that outlives a request.
var (
	saslMu        sync.Mutex
	saslExchanges = map[net.Conn]*saslExchange{}
)

func (h *Handler) exchange(conn net.Conn) *saslExchange {
	saslMu.Lock()
	defer saslMu.Unlock()

	// A client that starts a handshake and goes away leaves an entry behind; they are swept here
	// rather than on a timer, because a handshake is the only thing that creates one.
	for c, ex := range saslExchanges {
		if time.Since(ex.started) > saslHandshakeTimeout {
			delete(saslExchanges, c)
		}
	}

	return saslExchanges[conn]
}

func (h *Handler) rememberExchange(conn net.Conn, ex *saslExchange) {
	saslMu.Lock()
	defer saslMu.Unlock()
	saslExchanges[conn] = ex
}

func (h *Handler) forgetExchange(conn net.Conn) {
	saslMu.Lock()
	defer saslMu.Unlock()
	delete(saslExchanges, conn)
}
