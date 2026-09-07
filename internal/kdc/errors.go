package kdc

import (
	"fmt"
	"time"

	"github.com/go-krb5/krb5/iana/errorcode"
	"github.com/go-krb5/krb5/messages"
	"github.com/go-krb5/krb5/types"

	"github.com/shulutkov/ldap-kdc/internal/krbkeys"
	"github.com/shulutkov/ldap-kdc/internal/store"
)

// protocolError is a failure that must be reported to the client as a KRB-ERROR. Everything the
// client is allowed to learn is in Code; ETextl carries a human readable hint, and Internal keeps
// the detail that belongs in the log but not on the wire.
type protocolError struct {
	Code     int32
	EText    string
	EData    []byte
	Internal error

	// Client identifies the requester when known, so the error can echo it back.
	Client *krbkeys.Name
}

func (e *protocolError) Error() string {
	name := errorcode.Lookup(e.Code)
	if len(e.EText) > 0 {
		name += ": " + e.EText
	}
	if e.Internal != nil {
		name += " (" + e.Internal.Error() + ")"
	}

	return name
}

func (e *protocolError) Unwrap() error { return e.Internal }

// clientStatusError maps an unusable client principal onto the error code MIT returns for it. An
// expired account and a revoked one are different answers, and a client that cannot tell them
// apart cannot tell the user what to do about it.
func clientStatusError(status store.PrincipalStatus) *protocolError {
	code := errorcode.KDC_ERR_CLIENT_REVOKED
	if status == store.PrincipalExpired {
		code = errorcode.KDC_ERR_NAME_EXP
	}

	return krbErr(code, "%s", status)
}

// serverStatusError does the same for the service a ticket was asked for.
func serverStatusError(status store.PrincipalStatus) *protocolError {
	code := errorcode.KDC_ERR_S_PRINCIPAL_UNKNOWN
	if status == store.PrincipalExpired {
		code = errorcode.KDC_ERR_SERVICE_EXP
	}

	return krbErr(code, "%s", status)
}

// krbErr builds a protocol error with a message meant for the client.
func krbErr(code int32, format string, args ...any) *protocolError {
	return &protocolError{Code: code, EText: fmt.Sprintf(format, args...)}
}

// krbErrf builds a protocol error whose detail stays server side. The client is told only the
// error code and a short text, because the detail of why a key failed to decrypt or which
// principal was missing is exactly what an attacker probing the KDC wants.
func krbErrf(code int32, public string, cause error) *protocolError {
	return &protocolError{Code: code, EText: public, Internal: cause}
}

// errorReply renders a protocol error as the KRB-ERROR bytes to send back.
func (s *Server) errorReply(perr *protocolError, sname types.PrincipalName, srealm string) []byte {
	if len(srealm) == 0 {
		srealm = s.cfg.Realm
	}
	if len(sname.NameString) == 0 {
		sname = s.tgsName().PrincipalName()
	}

	m := messages.NewKRBError(sname, srealm, perr.Code, perr.EText)
	m.EData = perr.EData

	if perr.Client != nil {
		m.CName = perr.Client.PrincipalName()
		m.CRealm = perr.Client.Realm
	}

	// A KRB-ERROR whose ctime is set claims to answer a specific request; leaving it zero is
	// correct for errors raised before the request was understood.
	m.CTime = time.Time{}

	b, err := m.Marshal()
	if err != nil {
		s.log.Error().Err(err).Msg("could not marshal KRB-ERROR")

		return nil
	}

	return b
}
