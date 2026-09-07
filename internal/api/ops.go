package api

import (
	"net/http"

	"github.com/shulutkov/ldap-kdc/internal/store"
)

// handleHealth reports that the process is running. It never touches the database, so a stuck
// query cannot make an otherwise healthy process look dead to an orchestrator.
func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// handleReady reports whether the service can actually serve: the database has to answer and the
// realm's ticket-granting principal has to be there with keys.
func (s *Server) handleReady(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	if err := s.st.DB().PingContext(ctx); err != nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{
			"status": "unavailable",
			"reason": "database: " + err.Error(),
		})

		return
	}

	realm, err := s.st.GetMeta(ctx, store.MetaRealm)
	if err != nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{
			"status": "unavailable",
			"reason": "realm is not initialized",
		})

		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"status": "ok", "realm": realm})
}

// handleStats summarises what the directory holds.
func (s *Server) handleStats(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	users, err := s.st.ListUsers(ctx)
	if err != nil {
		writeStoreError(w, err)

		return
	}

	groups, err := s.st.ListGroups(ctx)
	if err != nil {
		writeStoreError(w, err)

		return
	}

	principals, err := s.st.ListPrincipals(ctx, "")
	if err != nil {
		writeStoreError(w, err)

		return
	}

	trusts, err := s.st.ListTrusts(ctx)
	if err != nil {
		writeStoreError(w, err)

		return
	}

	var disabled, withoutPassword int
	for i := range users {
		if users[i].Disabled {
			disabled++
		}
		if !users[i].HasPassword {
			withoutPassword++
		}
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"realm": s.cfg.Realm,
		"users": map[string]int{
			"total":    len(users),
			"disabled": disabled,
			// An account with no password can bind to nothing and get no ticket, so it is
			// worth surfacing rather than leaving to be discovered by a failed login.
			"withoutPassword": withoutPassword,
		},
		"groups":     len(groups),
		"principals": len(principals),
		"trusts":     len(trusts),
		"encTypes":   encTypeNames(s.cfg.EncTypes),
	})
}
