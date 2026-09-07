package api

import (
	"errors"
	"net/http"
	"strings"

	"github.com/shulutkov/ldap-kdc/internal/krbkeys"
	"github.com/shulutkov/ldap-kdc/internal/store"
)

type createTrustRequest struct {
	RemoteRealm string               `json:"remoteRealm"`
	Direction   store.TrustDirection `json:"direction"`
	Transitive  *bool                `json:"transitive,omitempty"`
	Enabled     *bool                `json:"enabled,omitempty"`
	// Password is the secret shared with the remote realm. Both realms must derive the
	// cross-realm keys from the same string, so it is supplied rather than generated.
	Password string `json:"password"`
}

type patchTrustRequest struct {
	Direction  *store.TrustDirection `json:"direction,omitempty"`
	Transitive *bool                 `json:"transitive,omitempty"`
	Enabled    *bool                 `json:"enabled,omitempty"`
}

func (s *Server) handleListTrusts(w http.ResponseWriter, r *http.Request) {
	trusts, err := s.st.ListTrusts(r.Context())
	if err != nil {
		writeStoreError(w, err)

		return
	}

	writeJSON(w, http.StatusOK, map[string]any{"trusts": trusts})
}

func (s *Server) handleGetTrust(w http.ResponseWriter, r *http.Request) {
	t, err := s.st.GetTrust(r.Context(), r.PathValue("realm"))
	if err != nil {
		writeStoreError(w, err)

		return
	}

	writeJSON(w, http.StatusOK, map[string]any{"trust": t})
}

// handleCreateTrust records a cross-realm relationship and creates the krbtgt principals that
// carry its keys.
//
// A trust is two principals, not one: krbtgt/REMOTE@LOCAL lets our clients be referred outwards,
// and krbtgt/LOCAL@REMOTE lets the remote realm's clients be accepted here. Both are keyed from
// the same shared password, which is exactly what the administrator of the other realm enters on
// their side.
func (s *Server) handleCreateTrust(w http.ResponseWriter, r *http.Request) {
	var req createTrustRequest
	if !decode(w, r, &req) {
		return
	}

	remote := strings.ToUpper(strings.TrimSpace(req.RemoteRealm))
	if len(remote) == 0 {
		writeError(w, http.StatusBadRequest, "remoteRealm is required")

		return
	}
	if strings.EqualFold(remote, s.cfg.Realm) {
		writeError(w, http.StatusBadRequest, "a realm cannot trust itself")

		return
	}
	if !s.checkPassword(w, req.Password) {
		return
	}

	direction := req.Direction
	if len(direction) == 0 {
		direction = store.TrustBidirectional
	}

	switch direction {
	case store.TrustInbound, store.TrustOutbound, store.TrustBidirectional:
	default:
		writeError(w, http.StatusBadRequest,
			"direction must be one of inbound, outbound or bidirectional")

		return
	}

	ctx := r.Context()

	t := &store.Trust{
		RemoteRealm: remote,
		Direction:   direction,
		Transitive:  req.Transitive == nil || *req.Transitive,
		Enabled:     req.Enabled == nil || *req.Enabled,
	}

	if err := s.st.CreateTrust(ctx, t); err != nil {
		writeStoreError(w, err)

		return
	}

	// Outbound needs krbtgt/REMOTE in our realm; inbound needs krbtgt/LOCAL keyed under theirs.
	var wanted []krbkeys.Name

	if t.Allows(store.TrustOutbound) {
		wanted = append(wanted, krbkeys.Name{Components: []string{"krbtgt", remote}, Realm: s.cfg.Realm})
	}
	if t.Allows(store.TrustInbound) {
		wanted = append(wanted, krbkeys.Name{Components: []string{"krbtgt", s.cfg.Realm}, Realm: remote})
	}

	for _, name := range wanted {
		keys, err := krbkeys.DeriveKeys(req.Password, name, s.cfg.EncTypes)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "%s", err)

			return
		}

		p := &store.Principal{
			Name: name.Principal(), Realm: name.Realm,
			Enabled: true, RequiresPreAuth: true,
			AllowForwardable: true, AllowProxiable: true, AllowRenewable: true,
		}

		err = s.st.CreatePrincipal(ctx, p, keys)
		if errors.Is(err, store.ErrConflict) {
			// The principal already exists, so re-key it rather than refusing: rotating a
			// trust password is a normal operation.
			_, err = s.st.SetKeys(ctx, name, keys, timeNow())
		}
		if err != nil {
			writeStoreError(w, err)

			return
		}
	}

	s.log.Info().Str("realm", remote).Str("direction", string(direction)).Msg("trust created")
	writeJSON(w, http.StatusCreated, map[string]any{"trust": t})
}

func (s *Server) handlePatchTrust(w http.ResponseWriter, r *http.Request) {
	var req patchTrustRequest
	if !decode(w, r, &req) {
		return
	}

	updated, err := s.st.UpdateTrust(r.Context(), r.PathValue("realm"), func(t *store.Trust) error {
		applyIf(req.Direction, &t.Direction)
		applyIf(req.Transitive, &t.Transitive)
		applyIf(req.Enabled, &t.Enabled)

		return nil
	})
	if err != nil {
		writeStoreError(w, err)

		return
	}

	writeJSON(w, http.StatusOK, map[string]any{"trust": updated})
}

func (s *Server) handleDeleteTrust(w http.ResponseWriter, r *http.Request) {
	realm := strings.ToUpper(r.PathValue("realm"))

	if err := s.st.DeleteTrust(r.Context(), realm); err != nil {
		writeStoreError(w, err)

		return
	}

	// The shared keys go with the relationship; leaving them behind would let a revoked trust
	// keep working until someone noticed.
	for _, name := range []krbkeys.Name{
		{Components: []string{"krbtgt", realm}, Realm: s.cfg.Realm},
		{Components: []string{"krbtgt", s.cfg.Realm}, Realm: realm},
	} {
		if err := s.st.DeletePrincipal(r.Context(), name); err != nil && !errors.Is(err, store.ErrNotFound) {
			writeStoreError(w, err)

			return
		}
	}

	s.log.Info().Str("realm", realm).Msg("trust deleted")
	w.WriteHeader(http.StatusNoContent)
}
