package api

import (
	"net/http"
	"strings"
	"time"

	"github.com/shulutkov/ldap-kdc/internal/krbkeys"
	"github.com/shulutkov/ldap-kdc/internal/store"
)

// timeNow exists so the trust handler and the principal handler agree on "now".
func timeNow() time.Time { return time.Now().UTC() }

type createPrincipalRequest struct {
	Name string `json:"name"`
	// UserName links the principal to a directory account, so setting the account's password
	// re-keys this principal too.
	UserName string `json:"userName,omitempty"`

	Enabled         *bool `json:"enabled,omitempty"`
	RequiresPreAuth *bool `json:"requiresPreAuth,omitempty"`

	AllowForwardable   *bool `json:"allowForwardable,omitempty"`
	AllowProxiable     *bool `json:"allowProxiable,omitempty"`
	AllowRenewable     *bool `json:"allowRenewable,omitempty"`
	AllowPostdate      *bool `json:"allowPostdate,omitempty"`
	OKAsDelegate       *bool `json:"okAsDelegate,omitempty"`
	OKToAuthAsDelegate *bool `json:"okToAuthAsDelegate,omitempty"`

	AllowedToDelegateTo  []string `json:"allowedToDelegateTo,omitempty"`
	AllowedToImpersonate []string `json:"allowedToImpersonate,omitempty"`

	// Aliases are further names this principal answers to.
	Aliases []string `json:"aliases,omitempty"`

	MaxTicketLife    string `json:"maxTicketLife,omitempty"`
	MaxRenewableLife string `json:"maxRenewableLife,omitempty"`

	ExpiresAt *time.Time `json:"expiresAt,omitempty"`

	// Password keys the principal from a password. Leave it out for a service principal and
	// take a keytab instead: a random key cannot be guessed.
	Password string `json:"password,omitempty"`
}

type patchPrincipalRequest struct {
	Enabled         *bool `json:"enabled,omitempty"`
	RequiresPreAuth *bool `json:"requiresPreAuth,omitempty"`

	AllowForwardable   *bool `json:"allowForwardable,omitempty"`
	AllowProxiable     *bool `json:"allowProxiable,omitempty"`
	AllowRenewable     *bool `json:"allowRenewable,omitempty"`
	AllowPostdate      *bool `json:"allowPostdate,omitempty"`
	OKAsDelegate       *bool `json:"okAsDelegate,omitempty"`
	OKToAuthAsDelegate *bool `json:"okToAuthAsDelegate,omitempty"`

	AllowedToDelegateTo  *[]string `json:"allowedToDelegateTo,omitempty"`
	AllowedToImpersonate *[]string `json:"allowedToImpersonate,omitempty"`

	// Aliases replaces the principal's alternative names outright, so sending the list without
	// one removes it. The canonical name is not part of the list and cannot be changed here.
	Aliases *[]string `json:"aliases,omitempty"`

	MaxTicketLife    *string `json:"maxTicketLife,omitempty"`
	MaxRenewableLife *string `json:"maxRenewableLife,omitempty"`

	ExpiresAt         *time.Time `json:"expiresAt,omitempty"`
	PasswordExpiresAt *time.Time `json:"passwordExpiresAt,omitempty"`
	// Unlock clears a lockout imposed by repeated failed pre-authentications.
	Unlock *bool `json:"unlock,omitempty"`
}

type principalPasswordRequest struct {
	// Password keys the principal from a password; leave it empty and set randomize to replace
	// the keys with random ones.
	Password  string `json:"password,omitempty"`
	Randomize bool   `json:"randomize,omitempty"`
}

func (s *Server) handleListPrincipals(w http.ResponseWriter, r *http.Request) {
	principals, err := s.st.ListPrincipals(r.Context(), r.URL.Query().Get("realm"))
	if err != nil {
		writeStoreError(w, err)

		return
	}

	writeJSON(w, http.StatusOK, map[string]any{"principals": principals})
}

// handlePrincipalGet answers both the principal itself and, on the .keytab suffix, a keytab file
// for it. Routing them together keeps service principal names, which contain slashes, in one
// wildcard pattern.
func (s *Server) handlePrincipalGet(w http.ResponseWriter, r *http.Request) {
	raw := r.PathValue("name")

	if trimmed, ok := strings.CutSuffix(raw, "/keytab"); ok {
		s.writeKeytab(w, r, trimmed)

		return
	}

	name, ok := s.principalName(w, raw)
	if !ok {
		return
	}

	p, err := s.st.GetPrincipal(r.Context(), name)
	if err != nil {
		writeStoreError(w, err)

		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"principal":        p,
		"encTypes":         encTypeNames(p.EncTypes()),
		"maxTicketLife":    durationString(p.MaxTicketLife),
		"maxRenewableLife": durationString(p.MaxRenewableLife),
		// The same policy as MIT and FreeIPA record it in krbTicketFlags, so a value read
		// here can be compared with one read from either.
		"krbTicketFlags": p.TicketFlags(),
	})
}

func (s *Server) handleCreatePrincipal(w http.ResponseWriter, r *http.Request) {
	var req createPrincipalRequest
	if !decode(w, r, &req) {
		return
	}

	name, ok := s.principalName(w, req.Name)
	if !ok {
		return
	}
	if len(req.Password) > 0 && !s.checkPassword(w, req.Password) {
		return
	}

	ctx := r.Context()

	p := &store.Principal{
		Name: name.Principal(), Realm: name.Realm,
		Enabled:              boolOr(req.Enabled, true),
		RequiresPreAuth:      boolOr(req.RequiresPreAuth, true),
		AllowForwardable:     boolOr(req.AllowForwardable, true),
		AllowProxiable:       boolOr(req.AllowProxiable, true),
		AllowRenewable:       boolOr(req.AllowRenewable, true),
		AllowPostdate:        boolOr(req.AllowPostdate, false),
		OKAsDelegate:         boolOr(req.OKAsDelegate, false),
		OKToAuthAsDelegate:   boolOr(req.OKToAuthAsDelegate, false),
		AllowedToDelegateTo:  req.AllowedToDelegateTo,
		AllowedToImpersonate: req.AllowedToImpersonate,
		Aliases:              req.Aliases,
		ExpiresAt:            req.ExpiresAt,
	}

	var err error
	if p.MaxTicketLife, err = parseDuration(req.MaxTicketLife); err != nil {
		writeError(w, http.StatusBadRequest, "maxTicketLife: %s", err)

		return
	}
	if p.MaxRenewableLife, err = parseDuration(req.MaxRenewableLife); err != nil {
		writeError(w, http.StatusBadRequest, "maxRenewableLife: %s", err)

		return
	}

	if len(req.UserName) > 0 {
		u, err := s.st.GetUser(ctx, req.UserName)
		if err != nil {
			writeStoreError(w, err)

			return
		}
		p.UserID = &u.ID
	}

	var keys []krbkeys.Key
	if len(req.Password) > 0 {
		keys, err = krbkeys.DeriveKeys(req.Password, name, s.cfg.EncTypes)
	} else {
		keys, err = krbkeys.RandomKeys(s.cfg.EncTypes)
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "%s", err)

		return
	}

	if err := s.st.CreatePrincipal(ctx, p, keys); err != nil {
		writeStoreError(w, err)

		return
	}

	s.log.Info().Str("principal", p.FullName()).Msg("principal created")
	writeJSON(w, http.StatusCreated, map[string]any{"principal": p})
}

// handlePrincipalPost carries the actions on an existing principal. Only the password action is
// defined today; the sub-path is matched here rather than in the router because a service principal
// name contains slashes and would otherwise be split across pattern segments.
func (s *Server) handlePrincipalPost(w http.ResponseWriter, r *http.Request) {
	raw := r.PathValue("name")

	trimmed, ok := strings.CutSuffix(raw, "/password")
	if !ok {
		writeError(w, http.StatusNotFound, "no such action on a principal")

		return
	}

	s.setPrincipalPassword(w, r, trimmed)
}

// handlePatchPrincipal edits a principal's attributes and policy.
func (s *Server) handlePatchPrincipal(w http.ResponseWriter, r *http.Request) {
	name, ok := s.principalName(w, r.PathValue("name"))
	if !ok {
		return
	}

	var req patchPrincipalRequest
	if !decode(w, r, &req) {
		return
	}

	var badField, badValue string

	updated, err := s.st.UpdatePrincipal(r.Context(), name, func(p *store.Principal) error {
		applyIf(req.Enabled, &p.Enabled)
		applyIf(req.RequiresPreAuth, &p.RequiresPreAuth)
		applyIf(req.AllowForwardable, &p.AllowForwardable)
		applyIf(req.AllowProxiable, &p.AllowProxiable)
		applyIf(req.AllowRenewable, &p.AllowRenewable)
		applyIf(req.AllowPostdate, &p.AllowPostdate)
		applyIf(req.OKAsDelegate, &p.OKAsDelegate)
		applyIf(req.OKToAuthAsDelegate, &p.OKToAuthAsDelegate)
		applyIf(req.AllowedToDelegateTo, &p.AllowedToDelegateTo)
		applyIf(req.AllowedToImpersonate, &p.AllowedToImpersonate)
		applyIf(req.Aliases, &p.Aliases)

		if req.ExpiresAt != nil {
			p.ExpiresAt = req.ExpiresAt
		}
		if req.PasswordExpiresAt != nil {
			p.PasswordExpiresAt = req.PasswordExpiresAt
		}
		if req.Unlock != nil && *req.Unlock {
			p.LockedUntil = nil
			p.FailCount = 0
		}

		for _, f := range []struct {
			name string
			src  *string
			dst  *time.Duration
		}{
			{"maxTicketLife", req.MaxTicketLife, &p.MaxTicketLife},
			{"maxRenewableLife", req.MaxRenewableLife, &p.MaxRenewableLife},
		} {
			if f.src == nil {
				continue
			}

			d, err := parseDuration(*f.src)
			if err != nil {
				badField, badValue = f.name, *f.src

				return err
			}
			*f.dst = d
		}

		return nil
	})
	if err != nil {
		if len(badField) > 0 {
			writeError(w, http.StatusBadRequest, "%s: %q is not a duration", badField, badValue)

			return
		}

		writeStoreError(w, err)

		return
	}

	s.log.Info().Str("principal", updated.FullName()).Msg("principal updated")
	writeJSON(w, http.StatusOK, map[string]any{"principal": updated})
}

func (s *Server) handleDeletePrincipal(w http.ResponseWriter, r *http.Request) {
	name, ok := s.principalName(w, r.PathValue("name"))
	if !ok {
		return
	}

	if name.IsTGS() && strings.EqualFold(name.Components[1], s.cfg.Realm) {
		// Deleting the realm's own ticket-granting principal would invalidate every ticket
		// in circulation and leave the KDC unable to answer at all.
		writeError(w, http.StatusConflict, "the realm's own ticket-granting principal cannot be deleted")

		return
	}

	if err := s.st.DeletePrincipal(r.Context(), name); err != nil {
		writeStoreError(w, err)

		return
	}

	s.log.Info().Str("principal", name.String()).Msg("principal deleted")
	w.WriteHeader(http.StatusNoContent)
}

// setPrincipalPassword re-keys a principal, either from a password or randomly.
func (s *Server) setPrincipalPassword(w http.ResponseWriter, r *http.Request, raw string) {
	name, ok := s.principalName(w, raw)
	if !ok {
		return
	}

	var req principalPasswordRequest
	if !decode(w, r, &req) {
		return
	}

	if len(req.Password) == 0 && !req.Randomize {
		writeError(w, http.StatusBadRequest, "either password or randomize is required")

		return
	}
	if len(req.Password) > 0 && !s.checkPassword(w, req.Password) {
		return
	}

	var (
		p   *store.Principal
		err error
	)

	if req.Randomize {
		p, err = s.st.RandomizePrincipalKeys(r.Context(), name, s.cfg.EncTypes)
	} else {
		p, err = s.st.SetPrincipalPassword(r.Context(), name, req.Password, s.cfg.EncTypes)
	}
	if err != nil {
		writeStoreError(w, err)

		return
	}

	s.log.Info().Str("principal", p.FullName()).Bool("random", req.Randomize).Int("kvno", p.KVNO).
		Msg("principal re-keyed")
	writeJSON(w, http.StatusOK, map[string]any{"principal": p})
}

// writeKeytab returns a keytab file holding the principal's current keys.
func (s *Server) writeKeytab(w http.ResponseWriter, r *http.Request, raw string) {
	name, ok := s.principalName(w, raw)
	if !ok {
		return
	}

	p, err := s.st.GetPrincipal(r.Context(), name)
	if err != nil {
		writeStoreError(w, err)

		return
	}

	if len(p.Keys) == 0 {
		writeError(w, http.StatusConflict, "principal has no keys")

		return
	}

	entries := make([]krbkeys.KeytabEntry, 0, len(p.Keys))
	for _, k := range p.Keys {
		entries = append(entries, krbkeys.KeytabEntry{
			Name: name, KVNO: p.KVNO, Key: k, Timestamp: timeNow(),
		})
	}

	blob, err := krbkeys.MarshalKeytab(entries)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "%s", err)

		return
	}

	filename := strings.ReplaceAll(name.Principal(), "/", "_") + ".keytab"

	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", `attachment; filename="`+filename+`"`)
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(blob)

	s.log.Info().Str("principal", p.FullName()).Int("kvno", p.KVNO).Msg("keytab issued")
}

// parseDuration reads an optional duration, treating an empty string as "use the realm default".
func parseDuration(s string) (time.Duration, error) {
	if len(strings.TrimSpace(s)) == 0 {
		return 0, nil
	}

	return time.ParseDuration(s)
}

// durationString renders a duration, or an empty string when the realm default applies.
func durationString(d time.Duration) string {
	if d == 0 {
		return ""
	}

	return d.String()
}

// encTypeNames renders enctype numbers as their canonical names.
func encTypeNames(ids []int32) []string {
	out := make([]string, 0, len(ids))
	for _, id := range ids {
		out = append(out, krbkeys.EncTypeName(id))
	}

	return out
}

func boolOr(v *bool, fallback bool) bool {
	if v == nil {
		return fallback
	}

	return *v
}
