package kdc

import (
	"fmt"
	"slices"
	"time"

	"github.com/go-krb5/krb5/asn1tools"
	"github.com/go-krb5/krb5/crypto"
	"github.com/go-krb5/krb5/iana"
	"github.com/go-krb5/krb5/iana/asn1apptag"
	"github.com/go-krb5/krb5/iana/errorcode"
	"github.com/go-krb5/krb5/iana/flags"
	"github.com/go-krb5/krb5/iana/keyusage"
	"github.com/go-krb5/krb5/messages"
	"github.com/go-krb5/krb5/types"
	"github.com/go-krb5/x/encoding/asn1"

	"github.com/shulutkov/ldap-kdc/internal/krbkeys"
	"github.com/shulutkov/ldap-kdc/internal/store"
)

// ticketSpec is everything needed to mint one ticket.
type ticketSpec struct {
	Client krbkeys.Name
	Server krbkeys.Name

	// ServerKey encrypts the ticket; only the named service can open it.
	ServerKey  krbkeys.Key
	ServerKVNO int

	// SessionEType is the enctype of the session key handed to both sides.
	SessionEType int32

	Flags     asn1.BitString
	AuthTime  time.Time
	StartTime time.Time
	EndTime   time.Time
	RenewTill time.Time

	Addresses         types.HostAddresses
	AuthorizationData types.AuthorizationData
	Transited         messages.TransitedEncoding
}

// mintTicket builds and seals a ticket, returning it with the session key inside it.
//
// The library's NewTicket cannot be used: it derives the service key from a keytab and offers no
// way to place authorization data in the encrypted part, which is exactly where the PAC has to go.
func mintTicket(spec ticketSpec) (messages.Ticket, types.EncryptionKey, error) {
	et, err := crypto.GetEType(spec.SessionEType)
	if err != nil {
		return messages.Ticket{}, types.EncryptionKey{}, fmt.Errorf("session enctype: %w", err)
	}

	sessionKey, err := types.GenerateEncryptionKey(et)
	if err != nil {
		return messages.Ticket{}, types.EncryptionKey{}, fmt.Errorf("generating session key: %w", err)
	}

	etp := messages.EncTicketPart{
		Flags:             spec.Flags,
		Key:               sessionKey,
		CRealm:            spec.Client.Realm,
		CName:             spec.Client.PrincipalName(),
		Transited:         spec.Transited,
		AuthTime:          spec.AuthTime,
		StartTime:         spec.StartTime,
		EndTime:           spec.EndTime,
		RenewTill:         spec.RenewTill,
		CAddr:             spec.Addresses,
		AuthorizationData: spec.AuthorizationData,
	}

	b, err := asn1.Marshal(etp,
		asn1.WithMarshalSlicePreserveTypes(true),
		asn1.WithMarshalSliceAllowStrings(true))
	if err != nil {
		return messages.Ticket{}, types.EncryptionKey{}, fmt.Errorf("marshalling ticket: %w", err)
	}

	b = asn1tools.AddASNAppTag(b, asn1apptag.EncTicketPart)

	ed, err := crypto.GetEncryptedData(b, spec.ServerKey.EncryptionKey(), keyusage.KDC_REP_TICKET, spec.ServerKVNO)
	if err != nil {
		return messages.Ticket{}, types.EncryptionKey{}, fmt.Errorf("encrypting ticket: %w", err)
	}

	return messages.Ticket{
		TktVNO:  iana.PVNO,
		Realm:   spec.Server.Realm,
		SName:   spec.Server.PrincipalName(),
		EncPart: ed,
	}, sessionKey, nil
}

// ticketTimes is the validity window and renewal limit worked out for a request.
type ticketTimes struct {
	AuthTime  time.Time
	StartTime time.Time
	EndTime   time.Time
	RenewTill time.Time
	Renewable bool
	Postdated bool
}

// computeTimes turns the client's requested times into the ones policy allows.
//
// The client asks for an end time and, if it wants renewal, a renew-until time; both are clamped to
// the shorter of what the client principal, the service principal and the realm permit. A request
// whose window closes before it opens is refused rather than quietly adjusted, because a client
// that asked for a ticket valid in the past is confused about the time and should be told so.
func (s *Server) computeTimes(
	body *messages.KDCReqBody,
	client, server *store.Principal,
	now time.Time,
) (ticketTimes, *protocolError) {
	var t ticketTimes

	t.AuthTime = now
	t.StartTime = now

	postdate := types.IsFlagSet(&body.KDCOptions, flags.PostDated)
	if postdate && !body.From.IsZero() {
		if !client.AllowPostdate {
			return t, krbErr(errorcode.KDC_ERR_BADOPTION, "postdated tickets are not allowed for this principal")
		}
		t.StartTime = body.From
		t.Postdated = true
	} else if !body.From.IsZero() && body.From.After(now.Add(s.cfg.ClockSkew)) {
		// A start time in the future without the POSTDATED option is a request the KDC
		// cannot honour: the ticket would be unusable until then and the client did not ask
		// for that.
		return t, krbErr(errorcode.KDC_ERR_CANNOT_POSTDATE, "start time is in the future but POSTDATED was not requested")
	}

	maxLife := s.effectiveLife(client.MaxTicketLife, server.MaxTicketLife, s.cfg.MaxTicketLife)

	t.EndTime = t.StartTime.Add(maxLife)
	if isRequestedTime(body.Till) && body.Till.Before(t.EndTime) {
		t.EndTime = body.Till
	}

	if !t.EndTime.After(t.StartTime) {
		return t, krbErr(errorcode.KDC_ERR_NEVER_VALID, "requested ticket would expire before it starts")
	}

	maxRenew := s.effectiveLife(client.MaxRenewableLife, server.MaxRenewableLife, s.cfg.MaxRenewableLife)

	wantRenew := types.IsFlagSet(&body.KDCOptions, flags.Renewable)
	renewableOK := types.IsFlagSet(&body.KDCOptions, flags.RenewableOK)

	switch {
	case wantRenew && client.AllowRenewable && server.AllowRenewable:
		t.Renewable = true
		t.RenewTill = t.StartTime.Add(maxRenew)
		if isRequestedTime(body.RTime) && body.RTime.Before(t.RenewTill) {
			t.RenewTill = body.RTime
		}
	case renewableOK && client.AllowRenewable && server.AllowRenewable &&
		isRequestedTime(body.Till) && body.Till.After(t.EndTime):
		// RENEWABLE-OK means: if you cannot give me a ticket that lives as long as I asked,
		// give me a shorter renewable one instead (RFC 4120 section 3.1.3).
		t.Renewable = true
		t.RenewTill = body.Till
		if limit := t.StartTime.Add(maxRenew); t.RenewTill.After(limit) {
			t.RenewTill = limit
		}
	}

	if t.Renewable && !t.RenewTill.After(t.EndTime) {
		// A renew-until no later than the end time makes the ticket renewable in name only.
		t.Renewable = false
		t.RenewTill = time.Time{}
	}

	return t, nil
}

// isRequestedTime reports whether a time in a request names a real instant the KDC should honour.
//
// RFC 4120 Section 5.4.1 gives 19700101000000Z a special meaning in till: it asks for the latest
// end time KDC policy allows, rather than for an expiry in 1970. Heimdal sends exactly that in a
// TGS request, so reading it literally makes every service ticket collapse into an empty window
// and the KDC answer KDC_ERR_NEVER_VALID.
func isRequestedTime(t time.Time) bool {
	return !t.IsZero() && t.Unix() > 0
}

// effectiveLife picks the shortest of the client limit, the service limit and the realm limit,
// treating zero as "no opinion, use the realm default".
func (s *Server) effectiveLife(client, server, realm time.Duration) time.Duration {
	out := realm

	for _, d := range []time.Duration{client, server} {
		if d > 0 && d < out {
			out = d
		}
	}

	if out <= 0 {
		out = realm
	}

	return out
}

// ticketFlags builds the flag set for a new ticket from what the client asked for and what policy
// permits. A flag the client requested but policy denies is simply not set: RFC 4120 has the KDC
// issue the ticket it can rather than fail, and the client can see what it got in the reply.
func ticketFlags(body *messages.KDCReqBody, client, server *store.Principal, t ticketTimes, initial, preAuth bool) asn1.BitString {
	f := types.NewKrbFlags()

	if initial {
		types.SetFlag(&f, flags.Initial)
	}
	if preAuth {
		types.SetFlag(&f, flags.PreAuthent)
	}
	if types.IsFlagSet(&body.KDCOptions, flags.Forwardable) && client.AllowForwardable && server.AllowForwardable {
		types.SetFlag(&f, flags.Forwardable)
	}
	if types.IsFlagSet(&body.KDCOptions, flags.Proxiable) && client.AllowProxiable && server.AllowProxiable {
		types.SetFlag(&f, flags.Proxiable)
	}
	if types.IsFlagSet(&body.KDCOptions, flags.AllowPostDate) && client.AllowPostdate {
		types.SetFlag(&f, flags.MayPostDate)
	}
	if t.Renewable {
		types.SetFlag(&f, flags.Renewable)
	}
	if t.Postdated {
		types.SetFlag(&f, flags.PostDated)
		// A postdated ticket is not valid until a client brings it back to be validated.
		types.SetFlag(&f, flags.Invalid)
	}
	if server.OKAsDelegate {
		types.SetFlag(&f, flags.OKAsDelegate)
	}

	return f
}

// selectSessionEType picks the strongest enctype both the client and this KDC support, preferring
// the KDC's order so realm policy decides rather than the client.
func (s *Server) selectSessionEType(offered []int32) (int32, bool) {
	for _, mine := range s.cfg.EncTypes {
		if slices.Contains(offered, mine) {
			return mine, true
		}
	}

	return 0, false
}

// selectKey picks the principal's key whose enctype the client offered, preferring this KDC's
// enctype order. It is used for the long-term keys that encrypt tickets and pre-authentication.
func selectKey(p *store.Principal, preference, offered []int32) (krbkeys.Key, bool) {
	for _, want := range preference {
		var offeredOK bool

		if offered == nil {
			offeredOK = true
		} else if slices.Contains(offered, want) {
			offeredOK = true
		}

		if !offeredOK {
			continue
		}

		if k, ok := p.KeyFor(want); ok {
			return k, true
		}
	}

	return krbkeys.Key{}, false
}

// marshalEncKDCRepPart serialises the encrypted part of a KDC reply under the given application
// tag. The library's own Marshal always writes tag 25 (EncASRepPart), which is wrong for a
// TGS-REP; RFC 4120 section 5.4.2 wants tag 26 there, and some clients check.
func marshalEncKDCRepPart(part *messages.EncKDCRepPart, appTag int) ([]byte, error) {
	b, err := asn1.Marshal(*part,
		asn1.WithMarshalSlicePreserveTypes(true),
		asn1.WithMarshalSliceAllowStrings(true))
	if err != nil {
		return nil, fmt.Errorf("marshalling KDC-REP encrypted part: %w", err)
	}

	return asn1tools.AddASNAppTag(b, appTag), nil
}
