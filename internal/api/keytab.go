package api

import (
	"net/http"

	"github.com/shulutkov/ldap-kdc/internal/krbkeys"
	"github.com/shulutkov/ldap-kdc/internal/store"
)

// maxKeytabPrincipals bounds one request: a keytab for a whole host is a few principals, and the
// bound keeps a single call from re-keying or reading an unbounded set.
const maxKeytabPrincipals = 500

// keytabRequest names the principals a keytab should hold.
type keytabRequest struct {
	Principals []string `json:"principals" required:"true" example:"[\"HTTP/nn.adh.local\",\"nn/nn.adh.local\"]" description:"Principals to put in the keytab, with or without @REALM. An alias resolves to the principal it belongs to, and a principal named twice is written once."`
	RandKey    bool     `json:"randkey,omitempty" description:"Give every principal new random keys before the keytab is written, as MIT's ktadd does. Keytabs issued before stop working once their kvno is gone."`
}

// handleKeytab answers with one keytab holding the current keys of every principal asked for, in
// the order asked. It reads the store and writes nothing unless randkey is set.
func (s *Server) handleKeytab(w http.ResponseWriter, r *http.Request) {
	var req keytabRequest
	if !decode(w, r, &req) {
		return
	}

	if len(req.Principals) == 0 {
		writeError(w, http.StatusBadRequest, "name at least one principal")

		return
	}
	if len(req.Principals) > maxKeytabPrincipals {
		writeError(w, http.StatusBadRequest, "at most %d principals per keytab", maxKeytabPrincipals)

		return
	}

	ctx := r.Context()

	// Every name is resolved before any principal is re-keyed, so one unknown name fails the whole
	// request without rotating the others first.
	principals := make([]*store.Principal, 0, len(req.Principals))
	seen := make(map[string]bool, len(req.Principals))
	for _, raw := range req.Principals {
		name, ok := s.principalName(w, raw)
		if !ok {
			return
		}

		p, err := s.st.GetPrincipal(ctx, name)
		if err != nil {
			writeStoreError(w, err)

			return
		}

		if seen[p.FullName()] {
			continue
		}
		seen[p.FullName()] = true

		principals = append(principals, p)
	}

	if req.RandKey {
		for i, p := range principals {
			rekeyed, err := s.st.RandomizePrincipalKeys(ctx, p.KrbName(), s.cfg.EncTypes)
			if err != nil {
				writeStoreError(w, err)

				return
			}

			principals[i] = rekeyed
		}
	}

	var entries []krbkeys.KeytabEntry
	now := timeNow()
	for _, p := range principals {
		if len(p.Keys) == 0 {
			writeError(w, http.StatusConflict, "%s has no keys", p.FullName())

			return
		}

		// The keys are salted with the canonical name, so the entries carry it even when the
		// principal was asked for under an alias.
		canonical := p.KrbName()
		for _, k := range p.Keys {
			entries = append(entries, krbkeys.KeytabEntry{
				Name: canonical, KVNO: p.KVNO, Key: k, Timestamp: now,
			})
		}
	}

	blob, err := krbkeys.MarshalKeytab(entries)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "%s", err)

		return
	}

	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", `attachment; filename="ldap-kdc.keytab"`)
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(blob)

	s.log.Info().
		Int("principals", len(principals)).
		Int("entries", len(entries)).
		Bool("randkey", req.RandKey).
		Msg("keytab issued")
}
