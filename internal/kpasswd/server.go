// Package kpasswd implements the Kerberos change password protocol of RFC 3244, so users can
// change their own password with the standard kpasswd tool and administrators can set another
// principal's password with a ticket for kadmin/changepw.
package kpasswd

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/go-krb5/krb5/crypto"
	"github.com/go-krb5/krb5/iana"
	"github.com/go-krb5/krb5/iana/errorcode"
	"github.com/go-krb5/krb5/iana/flags"
	"github.com/go-krb5/krb5/iana/keyusage"
	"github.com/go-krb5/krb5/iana/msgtype"
	"github.com/go-krb5/krb5/messages"
	"github.com/go-krb5/krb5/types"
	"github.com/go-krb5/x/encoding/asn1"
	"github.com/rs/zerolog"

	"github.com/shulutkov/ldap-kdc/internal/krbkeys"
	"github.com/shulutkov/ldap-kdc/internal/metrics"
	"github.com/shulutkov/ldap-kdc/internal/store"
)

// Result codes from RFC 3244 section 2.
const (
	resultSuccess           uint16 = 0
	resultMalformed         uint16 = 1
	resultHardError         uint16 = 2
	resultAuthError         uint16 = 3
	resultSoftError         uint16 = 4
	resultAccessDenied      uint16 = 5
	resultBadVersion        uint16 = 6
	resultInitialFlagNeeded uint16 = 7
)

// Protocol versions: 1 changes the sender's own password, 0xff80 is the RFC 3244 set-password
// extension that can name another principal.
const (
	versionChangePassword uint16 = 0x0001
	versionSetPassword    uint16 = 0xff80
)

// Config is what the password service needs to know about the realm.
type Config struct {
	Realm             string
	Listen            string
	ClockSkew         time.Duration
	EncTypes          []int32
	MinPasswordLength int
}

// Server is a running kpasswd service.
type Server struct {
	cfg     Config
	st      *store.Store
	log     zerolog.Logger
	metrics *metrics.Metrics

	tcp net.Listener
	udp net.PacketConn

	wg      sync.WaitGroup
	closing atomic.Bool
}

// New builds a password change service over the given store.
func New(cfg Config, st *store.Store, log zerolog.Logger, m *metrics.Metrics) (*Server, error) {
	if len(cfg.Realm) == 0 {
		return nil, errors.New("kpasswd: realm is required")
	}
	if len(cfg.EncTypes) == 0 {
		return nil, errors.New("kpasswd: at least one enctype is required")
	}

	return &Server{
		cfg:     cfg,
		st:      st,
		log:     log.With().Str("component", "kpasswd").Logger(),
		metrics: m,
	}, nil
}

// Start binds the listeners.
func (s *Server) Start(ctx context.Context) error {
	var err error

	if s.tcp, err = net.Listen("tcp", s.cfg.Listen); err != nil {
		return fmt.Errorf("kpasswd: listening on tcp %s: %w", s.cfg.Listen, err)
	}

	udpAddr := s.cfg.Listen
	if _, port, err := net.SplitHostPort(s.cfg.Listen); err == nil && port == "0" {
		udpAddr = s.tcp.Addr().String()
	}

	if s.udp, err = net.ListenPacket("udp", udpAddr); err != nil {
		_ = s.tcp.Close()

		return fmt.Errorf("kpasswd: listening on udp %s: %w", udpAddr, err)
	}

	s.log.Info().Str("address", s.cfg.Listen).Msg("password service listening")

	s.wg.Add(2)
	go s.serveTCP(ctx)
	go s.serveUDP(ctx)

	return nil
}

// Shutdown stops the listeners and waits for in-flight requests.
func (s *Server) Shutdown(ctx context.Context) error {
	if !s.closing.CompareAndSwap(false, true) {
		return nil
	}

	if s.tcp != nil {
		_ = s.tcp.Close()
	}
	if s.udp != nil {
		_ = s.udp.Close()
	}

	done := make(chan struct{})
	go func() {
		s.wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// Addr reports the bound TCP address.
func (s *Server) Addr() net.Addr {
	if s.tcp == nil {
		return nil
	}

	return s.tcp.Addr()
}

func (s *Server) serveTCP(ctx context.Context) {
	defer s.wg.Done()

	for {
		conn, err := s.tcp.Accept()
		if err != nil {
			if s.closing.Load() {
				return
			}
			s.log.Error().Err(err).Msg("accept failed")

			continue
		}

		s.wg.Go(func() {
			defer func() { _ = conn.Close() }()

			if err := conn.SetDeadline(time.Now().Add(30 * time.Second)); err != nil {
				return
			}

			// Over TCP the RFC 3244 message is preceded by a four byte length, as with the
			// KDC protocol itself.
			var lenBuf [4]byte
			if _, err := io.ReadFull(conn, lenBuf[:]); err != nil {
				return
			}

			size := binary.BigEndian.Uint32(lenBuf[:])
			if size == 0 || size > 64*1024 {
				return
			}

			req := make([]byte, size)
			if _, err := io.ReadFull(conn, req); err != nil {
				return
			}

			reply := s.Handle(ctx, req, conn.RemoteAddr(), conn.LocalAddr())

			out := make([]byte, 4+len(reply))
			binary.BigEndian.PutUint32(out[:4], uint32(len(reply)))
			copy(out[4:], reply)

			_, _ = conn.Write(out)
		})
	}
}

func (s *Server) serveUDP(ctx context.Context) {
	defer s.wg.Done()

	buf := make([]byte, 65535)

	for {
		n, addr, err := s.udp.ReadFrom(buf)
		if err != nil {
			if s.closing.Load() {
				return
			}
			s.log.Error().Err(err).Msg("UDP read failed")

			continue
		}

		req := make([]byte, n)
		copy(req, buf[:n])

		s.wg.Go(func() {

			reply := s.Handle(ctx, req, addr, s.udp.LocalAddr())
			if len(reply) > 0 {
				_, _ = s.udp.WriteTo(reply, addr)
			}
		})
	}
}

// Handle processes one change or set password request and returns the reply message.
func (s *Server) Handle(ctx context.Context, req []byte, from, to net.Addr) []byte {
	version, apReqBytes, privBytes, err := parseRequest(req)
	if err != nil {
		s.metrics.KPasswdRequests.WithLabelValues("malformed").Inc()

		return s.errorMessage(resultMalformed, err.Error())
	}

	if version != versionChangePassword && version != versionSetPassword {
		s.metrics.KPasswdRequests.WithLabelValues("bad-version").Inc()

		return s.errorMessage(resultBadVersion,
			fmt.Sprintf("unsupported protocol version 0x%04x", version))
	}

	code, msg, apRep, privKey, seq := s.process(ctx, version, apReqBytes, privBytes, from, to)

	if code != resultSuccess {
		s.metrics.KPasswdRequests.WithLabelValues(resultName(code)).Inc()
		s.log.Info().Str("from", from.String()).Str("result", resultName(code)).Str("detail", msg).
			Msg("password change refused")

		if apRep == nil {
			return s.errorMessage(code, msg)
		}
	} else {
		s.metrics.KPasswdRequests.WithLabelValues("ok").Inc()
	}

	reply, err := s.successMessage(code, msg, apRep, privKey, seq, to)
	if err != nil {
		s.log.Error().Err(err).Msg("could not build reply")

		return s.errorMessage(resultHardError, "internal error")
	}

	return reply
}

// process authenticates the request and applies the password change, returning the result code and
// the material needed to seal the reply.
func (s *Server) process(
	ctx context.Context,
	version uint16,
	apReqBytes, privBytes []byte,
	from, to net.Addr,
) (code uint16, detail string, apRep []byte, privKey types.EncryptionKey, seq int64) {
	var (
		apReq messages.APReq
		err   error
	)

	if err = apReq.Unmarshal(apReqBytes); err != nil {
		return resultMalformed, "malformed AP-REQ", nil, types.EncryptionKey{}, 0
	}

	target := krbkeys.NameFromPrincipalName(apReq.Ticket.SName, apReq.Ticket.Realm)
	if !target.IsChangePW() {
		return resultAuthError, "the ticket was not issued for kadmin/changepw", nil, types.EncryptionKey{}, 0
	}

	changepw, err := s.st.GetPrincipalKVNO(ctx, target, apReq.Ticket.EncPart.KVNO)
	if err != nil {
		return resultHardError, "the password service principal is unavailable", nil, types.EncryptionKey{}, 0
	}

	svcKey, ok := changepw.KeyFor(apReq.Ticket.EncPart.EType)
	if !ok {
		return resultHardError, "no key of the ticket's enctype", nil, types.EncryptionKey{}, 0
	}

	if err := apReq.Ticket.Decrypt(svcKey.EncryptionKey()); err != nil {
		return resultAuthError, "the ticket did not decrypt", nil, types.EncryptionKey{}, 0
	}

	tkt := apReq.Ticket.DecryptedEncPart

	// RFC 3244 requires the ticket to come straight from an AS exchange. That is what proves
	// the requester typed the current password just now, rather than reusing a TGT obtained
	// hours ago on a machine that has since changed hands.
	if !types.IsFlagSet(&tkt.Flags, flags.Initial) {
		return resultInitialFlagNeeded, "the ticket must be obtained with the current password", nil, types.EncryptionKey{}, 0
	}

	now := time.Now().UTC()
	if !tkt.EndTime.IsZero() && now.After(tkt.EndTime) {
		return resultAuthError, "the ticket has expired", nil, types.EncryptionKey{}, 0
	}

	if err := apReq.DecryptAuthenticator(tkt.Key); err != nil {
		return resultAuthError, "the authenticator did not decrypt", nil, types.EncryptionKey{}, 0
	}

	authn := apReq.Authenticator

	if skew := now.Sub(authn.CTime); skew > s.cfg.ClockSkew || skew < -s.cfg.ClockSkew {
		return resultAuthError, "clock skew too great", nil, types.EncryptionKey{}, 0
	}

	requester := krbkeys.NameFromPrincipalName(tkt.CName, tkt.CRealm)

	// The KRB-PRIV in each direction is sealed with the authenticator's subkey when the client
	// offered one; the AP-REP is not. RFC 4120 Section 5.5.2 has the AP-REP encrypted under the
	// ticket's session key, and a client that follows it cannot open one sealed with the subkey.
	privKey = tkt.Key
	if authn.SubKey.KeyType != 0 && len(authn.SubKey.KeyValue) > 0 {
		privKey = authn.SubKey
	}

	// The sequence number the server announces in the AP-REP is the one its first message
	// carries, and a client checking sequence numbers rejects the reply if the two disagree.
	seq, err = newSequenceNumber()
	if err != nil {
		return resultHardError, "could not generate a sequence number", nil, privKey, 0
	}

	apRep, err = buildAPRep(authn, tkt.Key, seq)
	if err != nil {
		return resultHardError, "could not build AP-REP", nil, privKey, 0
	}

	var priv messages.KRBPriv
	if err := priv.Unmarshal(privBytes); err != nil {
		return resultMalformed, "malformed KRB-PRIV", apRep, privKey, seq
	}
	if err := priv.DecryptEncPart(privKey); err != nil {
		return resultAuthError, "the request body did not decrypt", apRep, privKey, seq
	}

	newPassword, subject, err := parsePayload(version, priv.DecryptedEncPart.UserData, requester, s.cfg.Realm)
	if err != nil {
		return resultMalformed, err.Error(), apRep, privKey, seq
	}

	// Changing someone else's password is a privileged act. Only a request that names the
	// requester's own principal is accepted here; anything else goes through the REST API,
	// where an administrator is authenticated and the change is auditable.
	if !subject.Equal(requester) {
		return resultAccessDenied,
			"this service only changes the requester's own password; use the management API for others",
			apRep, privKey, seq
	}

	if code, msg := s.checkPolicy(newPassword); code != resultSuccess {
		return code, msg, apRep, privKey, seq
	}

	if code, msg := s.applyPassword(ctx, subject, newPassword); code != resultSuccess {
		return code, msg, apRep, privKey, seq
	}

	s.log.Info().Str("principal", subject.String()).Str("from", from.String()).Msg("password changed")

	return resultSuccess, "password changed", apRep, privKey, seq
}

// checkPolicy applies the realm's password rules.
func (s *Server) checkPolicy(password string) (uint16, string) {
	if len(password) < s.cfg.MinPasswordLength {
		return resultSoftError, fmt.Sprintf("password must be at least %d characters", s.cfg.MinPasswordLength)
	}
	if len(password) > 72 {
		// The LDAP side stores a bcrypt digest, which ignores anything past 72 bytes.
		return resultSoftError, "password must not exceed 72 bytes"
	}

	return resultSuccess, ""
}

// applyPassword writes the new password to both credential forms.
func (s *Server) applyPassword(ctx context.Context, subject krbkeys.Name, password string) (uint16, string) {
	principal, err := s.st.GetPrincipal(ctx, subject)
	if err != nil {
		return resultHardError, "principal not found"
	}

	// An account with a directory user behind it must have its LDAP digest changed at the same
	// time, or the two credentials would drift apart and only Kerberos would see the new
	// password.
	if principal.UserID != nil {
		user, err := s.st.GetUserByID(ctx, *principal.UserID)
		if err != nil {
			return resultHardError, "could not load the account"
		}

		if err := s.st.SetUserPassword(ctx, user.Name, password, s.cfg.EncTypes, nil); err != nil {
			return resultHardError, "could not store the new password"
		}

		return resultSuccess, ""
	}

	if _, err := s.st.SetPrincipalPassword(ctx, subject, password, s.cfg.EncTypes); err != nil {
		return resultHardError, "could not store the new password"
	}

	return resultSuccess, ""
}

// changePasswdData is the RFC 3244 set-password payload, which can name a principal other than the
// sender.
type changePasswdData struct {
	NewPasswd []byte              `asn1:"explicit,tag:0"`
	TargName  types.PrincipalName `asn1:"optional,explicit,tag:1"`
	TargRealm string              `asn1:"generalstring,optional,explicit,tag:2"`
}

// parsePayload reads the new password, and the principal it applies to, out of the request body.
func parsePayload(version uint16, data []byte, requester krbkeys.Name, realm string) (string, krbkeys.Name, error) {
	if version == versionChangePassword {
		// The plain change-password version carries the new password and nothing else, so it
		// can only ever apply to the sender.
		return string(data), requester, nil
	}

	var cpd changePasswdData
	if _, err := asn1.Unmarshal(data, &cpd, asn1.WithUnmarshalAllowTypeGeneralString(true)); err != nil {
		return "", krbkeys.Name{}, fmt.Errorf("malformed ChangePasswdData")
	}

	subject := requester
	if len(cpd.TargName.NameString) > 0 {
		r := cpd.TargRealm
		if len(r) == 0 {
			r = realm
		}
		subject = krbkeys.NameFromPrincipalName(cpd.TargName, r)
	}

	return string(cpd.NewPasswd), subject, nil
}

// buildAPRep answers the AP-REQ, proving to the client that the service holds the session key.
// key must be the ticket's session key: RFC 4120 Section 5.5.2 encrypts the AP-REP under it, even
// when the client offered a subkey for the messages that follow.
func buildAPRep(authn types.Authenticator, key types.EncryptionKey, seq int64) ([]byte, error) {
	part := messages.EncAPRepPart{
		CTime:          authn.CTime,
		Cusec:          authn.Cusec,
		SequenceNumber: seq,
	}

	b, err := part.Marshal()
	if err != nil {
		return nil, err
	}

	ed, err := crypto.GetEncryptedData(b, key, keyusage.AP_REP_ENCPART, 0)
	if err != nil {
		return nil, err
	}

	rep := messages.APRep{PVNO: iana.PVNO, MsgType: msgtype.KRB_AP_REP, EncPart: ed}

	return rep.Marshal()
}

// parseRequest splits an RFC 3244 message into its version, AP-REQ and KRB-PRIV parts.
func parseRequest(b []byte) (version uint16, apReq, priv []byte, err error) {
	if len(b) < 6 {
		return 0, nil, nil, errors.New("message is too short")
	}

	length := binary.BigEndian.Uint16(b[0:2])
	if int(length) != len(b) {
		return 0, nil, nil, fmt.Errorf("message declares %d bytes but carries %d", length, len(b))
	}

	version = binary.BigEndian.Uint16(b[2:4])
	apReqLen := int(binary.BigEndian.Uint16(b[4:6]))

	if apReqLen > len(b)-6 {
		return 0, nil, nil, errors.New("AP-REQ length runs past the end of the message")
	}

	return version, b[6 : 6+apReqLen], b[6+apReqLen:], nil
}

// successMessage builds the reply carrying the result code inside a KRB-PRIV.
func (s *Server) successMessage(code uint16, msg string, apRep []byte, key types.EncryptionKey, seq int64, to net.Addr) ([]byte, error) {
	body := make([]byte, 2, 2+len(msg))
	binary.BigEndian.PutUint16(body[0:2], code)
	body = append(body, msg...)

	addr, err := hostAddress(to)
	if err != nil {
		return nil, err
	}

	now := time.Now().UTC()

	priv := messages.NewKRBPriv(messages.EncKrbPrivPart{
		UserData:       body,
		Timestamp:      now,
		Usec:           int(now.Nanosecond() / 1000),
		SequenceNumber: seq,
		SAddress:       addr,
	})

	if err := priv.EncryptEncPart(key); err != nil {
		return nil, err
	}

	privBytes, err := priv.Marshal()
	if err != nil {
		return nil, err
	}

	return assemble(versionChangePassword, apRep, privBytes), nil
}

// errorMessage builds a reply for a request that could not be authenticated, where the result must
// travel as a KRB-ERROR because there is no key to seal a KRB-PRIV with.
func (s *Server) errorMessage(code uint16, msg string) []byte {
	body := make([]byte, 2, 2+len(msg))
	binary.BigEndian.PutUint16(body[0:2], code)
	body = append(body, msg...)

	kerr := messages.NewKRBError(
		types.PrincipalName{NameType: 1, NameString: []string{"kadmin", "changepw"}},
		s.cfg.Realm, errorcode.KRB_AP_ERR_MODIFIED, msg)
	kerr.EData = body

	b, err := kerr.Marshal()
	if err != nil {
		s.log.Error().Err(err).Msg("could not marshal KRB-ERROR")

		return nil
	}

	// An AP-REP length of zero tells the client the remainder is a KRB-ERROR rather than a
	// KRB-PRIV (RFC 3244 section 2).
	return assemble(versionChangePassword, nil, b)
}

// assemble builds the RFC 3244 framing around an AP-REP and a following message.
func assemble(version uint16, apRep, rest []byte) []byte {
	total := 6 + len(apRep) + len(rest)

	out := make([]byte, 6, total)
	binary.BigEndian.PutUint16(out[0:2], uint16(total))
	binary.BigEndian.PutUint16(out[2:4], version)
	binary.BigEndian.PutUint16(out[4:6], uint16(len(apRep)))
	out = append(out, apRep...)
	out = append(out, rest...)

	return out
}

// hostAddress converts a net.Addr into the Kerberos form the KRB-PRIV sender field needs.
func hostAddress(a net.Addr) (types.HostAddress, error) {
	if a == nil {
		return types.HostAddress{}, errors.New("no local address")
	}

	host := a.String()
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}

	// A wildcard listener reports an unspecified address, which is not something a peer can
	// meaningfully check; loopback is the honest stand-in and is what MIT sends in that case.
	if ip := net.ParseIP(host); ip == nil || ip.IsUnspecified() {
		host = "127.0.0.1"
	}

	return types.GetHostAddress(host + ":0")
}

// newSequenceNumber picks the server's initial sequence number, bounded well below the 32 bit
// wrap so a long-lived exchange cannot roll over into a value a peer has already accepted.
func newSequenceNumber() (int64, error) {
	n, err := rand.Int(rand.Reader, big.NewInt(1<<30))
	if err != nil {
		return 0, err
	}

	return n.Int64(), nil
}

// resultName labels a result code for logs and metrics.
func resultName(code uint16) string {
	switch code {
	case resultSuccess:
		return "ok"
	case resultMalformed:
		return "malformed"
	case resultHardError:
		return "hard-error"
	case resultAuthError:
		return "auth-error"
	case resultSoftError:
		return "policy"
	case resultAccessDenied:
		return "access-denied"
	case resultBadVersion:
		return "bad-version"
	case resultInitialFlagNeeded:
		return "initial-flag-needed"
	default:
		return "unknown"
	}
}
