package api

import (
	"net/http"
	"strconv"
	"time"

	"github.com/shulutkov/ldap-kdc/internal/krbkeys"
	"github.com/shulutkov/ldap-kdc/internal/store"
)

// createUserRequest is the body of a user creation.
type createUserRequest struct {
	Name         string              `json:"name"`
	UIDNumber    int                 `json:"uidNumber"`
	PrimaryGroup int                 `json:"primaryGroup"`
	OtherGroups  []int               `json:"otherGroups,omitempty"`
	GivenName    string              `json:"givenName,omitempty"`
	SN           string              `json:"sn,omitempty"`
	Mail         string              `json:"mail,omitempty"`
	LoginShell   string              `json:"loginShell,omitempty"`
	Homedir      string              `json:"homeDirectory,omitempty"`
	Disabled     bool                `json:"disabled,omitempty"`
	SSHKeys      []string            `json:"sshKeys,omitempty"`
	CustomAttrs  map[string][]string `json:"customAttributes,omitempty"`
	Capabilities []store.Capability  `json:"capabilities,omitempty"`
	OTPSecret    string              `json:"otpSecret,omitempty"`

	// Password sets the account's credentials on both sides at creation time.
	Password string `json:"password,omitempty"`
	// ForceChange marks the password expired so the account has to choose its own at first
	// login. It defaults to true, because a password an administrator typed is one the
	// administrator knows.
	ForceChange *bool `json:"forceChange,omitempty"`
	// Aliases are further Kerberos names the account answers to.
	Aliases []string `json:"aliases,omitempty"`
}

// patchUserRequest carries only the fields being changed; anything absent is left alone.
type patchUserRequest struct {
	UIDNumber    *int                 `json:"uidNumber,omitempty"`
	PrimaryGroup *int                 `json:"primaryGroup,omitempty"`
	OtherGroups  *[]int               `json:"otherGroups,omitempty"`
	GivenName    *string              `json:"givenName,omitempty"`
	SN           *string              `json:"sn,omitempty"`
	Mail         *string              `json:"mail,omitempty"`
	LoginShell   *string              `json:"loginShell,omitempty"`
	Homedir      *string              `json:"homeDirectory,omitempty"`
	Disabled     *bool                `json:"disabled,omitempty"`
	SSHKeys      *[]string            `json:"sshKeys,omitempty"`
	CustomAttrs  *map[string][]string `json:"customAttributes,omitempty"`
	Capabilities *[]store.Capability  `json:"capabilities,omitempty"`
	OTPSecret    *string              `json:"otpSecret,omitempty"`
}

// setPasswordRequest sets an account's password.
type setPasswordRequest struct {
	Password string `json:"password"`
	// ExpiresAt, when set, is when the password must next be changed. It overrides ForceChange.
	ExpiresAt *time.Time `json:"expiresAt,omitempty"`
	// ForceChange marks the password expired immediately, so the account must replace it at the
	// next login. It defaults to true: a password set through this interface is one an
	// administrator chose and therefore knows, and FreeIPA expires an administrative reset for
	// the same reason.
	ForceChange *bool `json:"forceChange,omitempty"`
}

// passwordExpiry works out when a password set through this interface should expire.
func passwordExpiry(explicit *time.Time, forceChange *bool) *time.Time {
	if explicit != nil {
		return explicit
	}

	if forceChange != nil && !*forceChange {
		return nil
	}

	now := timeNow()

	return &now
}

func (s *Server) handleListUsers(w http.ResponseWriter, r *http.Request) {
	users, err := s.st.ListUsers(r.Context())
	if err != nil {
		writeStoreError(w, err)

		return
	}

	writeJSON(w, http.StatusOK, map[string]any{"users": users})
}

func (s *Server) handleGetUser(w http.ResponseWriter, r *http.Request) {
	u, err := s.st.GetUser(r.Context(), r.PathValue("name"))
	if err != nil {
		writeStoreError(w, err)

		return
	}

	principals, err := s.st.PrincipalsForUser(r.Context(), u.ID)
	if err != nil {
		writeStoreError(w, err)

		return
	}

	writeJSON(w, http.StatusOK, map[string]any{"user": u, "principals": principals})
}

func (s *Server) handleCreateUser(w http.ResponseWriter, r *http.Request) {
	var req createUserRequest
	if !decode(w, r, &req) {
		return
	}

	if len(req.Name) == 0 {
		writeError(w, http.StatusBadRequest, "name is required")

		return
	}
	if len(req.Password) > 0 && !s.checkPassword(w, req.Password) {
		return
	}

	ctx := r.Context()

	u := &store.User{
		Name: req.Name, UIDNumber: req.UIDNumber, PrimaryGroup: req.PrimaryGroup,
		OtherGroups: req.OtherGroups, GivenName: req.GivenName, SN: req.SN, Mail: req.Mail,
		LoginShell: req.LoginShell, Homedir: req.Homedir, Disabled: req.Disabled,
		SSHKeys: req.SSHKeys, CustomAttrs: req.CustomAttrs, Capabilities: req.Capabilities,
		OTPSecret: req.OTPSecret,
	}

	if err := s.st.CreateAccount(ctx, store.NewAccount{
		User:              u,
		Realm:             s.cfg.Realm,
		EncTypes:          s.cfg.EncTypes,
		Password:          req.Password,
		PasswordExpiresAt: passwordExpiry(nil, req.ForceChange),
		Aliases:           req.Aliases,
	}); err != nil {
		writeStoreError(w, err)

		return
	}

	created, err := s.st.GetUser(ctx, u.Name)
	if err != nil {
		writeStoreError(w, err)

		return
	}

	s.log.Info().Str("user", u.Name).Msg("user created")
	writeJSON(w, http.StatusCreated, map[string]any{"user": created})
}

func (s *Server) handlePatchUser(w http.ResponseWriter, r *http.Request) {
	var req patchUserRequest
	if !decode(w, r, &req) {
		return
	}

	updated, err := s.st.UpdateUser(r.Context(), r.PathValue("name"), func(u *store.User) error {
		applyIf(req.UIDNumber, &u.UIDNumber)
		applyIf(req.PrimaryGroup, &u.PrimaryGroup)
		applyIf(req.OtherGroups, &u.OtherGroups)
		applyIf(req.GivenName, &u.GivenName)
		applyIf(req.SN, &u.SN)
		applyIf(req.Mail, &u.Mail)
		applyIf(req.LoginShell, &u.LoginShell)
		applyIf(req.Homedir, &u.Homedir)
		applyIf(req.Disabled, &u.Disabled)
		applyIf(req.SSHKeys, &u.SSHKeys)
		applyIf(req.CustomAttrs, &u.CustomAttrs)
		applyIf(req.Capabilities, &u.Capabilities)
		applyIf(req.OTPSecret, &u.OTPSecret)

		return nil
	})
	if err != nil {
		writeStoreError(w, err)

		return
	}

	// Disabling the account has to reach the Kerberos side too, or the user would keep getting
	// tickets after being locked out of LDAP.
	if req.Disabled != nil {
		if err := s.syncPrincipalEnabled(r, updated); err != nil {
			writeStoreError(w, err)

			return
		}
	}

	s.log.Info().Str("user", updated.Name).Msg("user updated")
	writeJSON(w, http.StatusOK, map[string]any{"user": updated})
}

// syncPrincipalEnabled mirrors an account's disabled flag onto its principals.
func (s *Server) syncPrincipalEnabled(r *http.Request, u *store.User) error {
	principals, err := s.st.PrincipalsForUser(r.Context(), u.ID)
	if err != nil {
		return err
	}

	for i := range principals {
		name := principals[i].KrbName()

		if _, err := s.st.UpdatePrincipal(r.Context(), name, func(p *store.Principal) error {
			p.Enabled = !u.Disabled

			return nil
		}); err != nil {
			return err
		}
	}

	return nil
}

func (s *Server) handleDeleteUser(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")

	if err := s.st.DeleteUser(r.Context(), name); err != nil {
		writeStoreError(w, err)

		return
	}

	s.log.Info().Str("user", name).Msg("user deleted")
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleSetUserPassword(w http.ResponseWriter, r *http.Request) {
	var req setPasswordRequest
	if !decode(w, r, &req) {
		return
	}

	if !s.checkPassword(w, req.Password) {
		return
	}

	name := r.PathValue("name")
	expiry := passwordExpiry(req.ExpiresAt, req.ForceChange)

	if err := s.st.SetUserPassword(r.Context(), name, req.Password, s.cfg.EncTypes, expiry); err != nil {
		writeStoreError(w, err)

		return
	}

	mustChange := expiry != nil && !expiry.After(timeNow())

	s.log.Info().Str("user", name).Bool("mustChange", mustChange).Msg("password set")
	writeJSON(w, http.StatusOK, map[string]any{
		"status":     "password set",
		"mustChange": mustChange,
	})
}

// appPasswordRequest names a new application password.
type appPasswordRequest struct {
	Name string `json:"name"`
	// Password is optional; one is generated when it is omitted, which is the usual case.
	Password string `json:"password,omitempty"`
}

func (s *Server) handleListAppPasswords(w http.ResponseWriter, r *http.Request) {
	u, err := s.st.GetUser(r.Context(), r.PathValue("name"))
	if err != nil {
		writeStoreError(w, err)

		return
	}

	writeJSON(w, http.StatusOK, map[string]any{"appPasswords": u.AppPasswords})
}

func (s *Server) handleCreateAppPassword(w http.ResponseWriter, r *http.Request) {
	var req appPasswordRequest
	if !decode(w, r, &req) {
		return
	}

	if len(req.Name) == 0 {
		writeError(w, http.StatusBadRequest, "name is required")

		return
	}

	password := req.Password
	generated := len(password) == 0

	if generated {
		var err error
		if password, err = krbkeys.RandomPassword(24); err != nil {
			writeError(w, http.StatusInternalServerError, "%s", err)

			return
		}
	} else if !s.checkPassword(w, password) {
		return
	}

	hash, err := s.st.HashPassword(password)
	if err != nil {
		writeError(w, http.StatusBadRequest, "%s", err)

		return
	}

	name := r.PathValue("name")

	ap, err := s.st.AddAppPassword(r.Context(), name, req.Name, hash)
	if err != nil {
		writeStoreError(w, err)

		return
	}

	body := map[string]any{"appPassword": ap}
	if generated {
		// The generated secret is shown once, here, because nothing stores it in the clear.
		body["password"] = password
	}

	s.log.Info().Str("user", name).Str("appPassword", req.Name).Msg("application password created")
	writeJSON(w, http.StatusCreated, body)
}

func (s *Server) handleDeleteAppPassword(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeError(w, http.StatusBadRequest, "application password id must be a number")

		return
	}

	if err := s.st.DeleteAppPassword(r.Context(), r.PathValue("name"), id); err != nil {
		writeStoreError(w, err)

		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// applyIf writes a patch field onto its target when the field was present in the request.
func applyIf[T any](src *T, dst *T) {
	if src != nil {
		*dst = *src
	}
}
