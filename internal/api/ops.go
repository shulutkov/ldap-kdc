package api

import (
	"net/http"

	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/shulutkov/ldap-kdc/internal/store"
)

// handleMetrics exposes the collectors. It is a method so that it sits in the route table with
// every other endpoint, which is what the OpenAPI document is generated from.
func (s *Server) handleMetrics(w http.ResponseWriter, r *http.Request) {
	promhttp.HandlerFor(s.metrics.Registry, promhttp.HandlerOpts{}).ServeHTTP(w, r)
}

// handleHealth reports that the process is running. It never touches the database, so a stuck
// query cannot make an otherwise healthy process look dead to an orchestrator.
func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, statusBody{Status: "ok"})
}

// handleReady reports whether the service can actually serve: the database has to answer and the
// realm's ticket-granting principal has to be there with keys.
func (s *Server) handleReady(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	if err := s.st.DB().PingContext(ctx); err != nil {
		writeJSON(w, http.StatusServiceUnavailable, statusBody{
			Status: "unavailable", Reason: "database: " + err.Error(),
		})

		return
	}

	realm, err := s.st.GetMeta(ctx, store.MetaRealm)
	if err != nil {
		writeJSON(w, http.StatusServiceUnavailable, statusBody{
			Status: "unavailable", Reason: "realm is not initialized",
		})

		return
	}

	writeJSON(w, http.StatusOK, statusBody{Status: "ok", Realm: realm})
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

	writeJSON(w, http.StatusOK, statsBody{
		Realm: s.cfg.Realm,
		Users: userCounts{
			Total: len(users), Disabled: disabled, WithoutPassword: withoutPassword,
		},
		Groups:     len(groups),
		Principals: len(principals),
		Trusts:     len(trusts),
		EncTypes:   encTypeNames(s.cfg.EncTypes),
	})
}
