package api

import (
	"net/http"

	"github.com/shulutkov/ldap-kdc/internal/store"
)

type createGroupRequest struct {
	Name          string             `json:"name"`
	GIDNumber     int                `json:"gidNumber"`
	Description   string             `json:"description,omitempty"`
	IncludeGroups []int              `json:"includeGroups,omitempty"`
	Capabilities  []store.Capability `json:"capabilities,omitempty"`
}

type patchGroupRequest struct {
	GIDNumber     *int                `json:"gidNumber,omitempty"`
	Description   *string             `json:"description,omitempty"`
	IncludeGroups *[]int              `json:"includeGroups,omitempty"`
	Capabilities  *[]store.Capability `json:"capabilities,omitempty"`
}

func (s *Server) handleListGroups(w http.ResponseWriter, r *http.Request) {
	groups, err := s.st.ListGroups(r.Context())
	if err != nil {
		writeStoreError(w, err)

		return
	}

	writeJSON(w, http.StatusOK, map[string]any{"groups": groups})
}

func (s *Server) handleGetGroup(w http.ResponseWriter, r *http.Request) {
	g, err := s.st.GetGroup(r.Context(), r.PathValue("name"))
	if err != nil {
		writeStoreError(w, err)

		return
	}

	writeJSON(w, http.StatusOK, map[string]any{"group": g})
}

func (s *Server) handleCreateGroup(w http.ResponseWriter, r *http.Request) {
	var req createGroupRequest
	if !decode(w, r, &req) {
		return
	}

	if len(req.Name) == 0 {
		writeError(w, http.StatusBadRequest, "name is required")

		return
	}

	g := &store.Group{
		Name: req.Name, GIDNumber: req.GIDNumber, Description: req.Description,
		IncludeGroups: req.IncludeGroups, Capabilities: req.Capabilities,
	}

	if g.GIDNumber == 0 {
		next, err := s.st.NextGIDNumber(r.Context())
		if err != nil {
			writeStoreError(w, err)

			return
		}
		g.GIDNumber = next
	}

	if err := s.st.CreateGroup(r.Context(), g); err != nil {
		writeStoreError(w, err)

		return
	}

	s.log.Info().Str("group", g.Name).Int("gid", g.GIDNumber).Msg("group created")
	writeJSON(w, http.StatusCreated, map[string]any{"group": g})
}

func (s *Server) handlePatchGroup(w http.ResponseWriter, r *http.Request) {
	var req patchGroupRequest
	if !decode(w, r, &req) {
		return
	}

	updated, err := s.st.UpdateGroup(r.Context(), r.PathValue("name"), func(g *store.Group) error {
		applyIf(req.GIDNumber, &g.GIDNumber)
		applyIf(req.Description, &g.Description)
		applyIf(req.IncludeGroups, &g.IncludeGroups)
		applyIf(req.Capabilities, &g.Capabilities)

		return nil
	})
	if err != nil {
		writeStoreError(w, err)

		return
	}

	writeJSON(w, http.StatusOK, map[string]any{"group": updated})
}

func (s *Server) handleDeleteGroup(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")

	if err := s.st.DeleteGroup(r.Context(), name); err != nil {
		writeStoreError(w, err)

		return
	}

	s.log.Info().Str("group", name).Msg("group deleted")
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleGroupMembers(w http.ResponseWriter, r *http.Request) {
	g, err := s.st.GetGroup(r.Context(), r.PathValue("name"))
	if err != nil {
		writeStoreError(w, err)

		return
	}

	// Membership follows included groups, so this is the same set the LDAP entry publishes.
	members, err := s.st.GroupMembers(r.Context(), g.GIDNumber)
	if err != nil {
		writeStoreError(w, err)

		return
	}

	writeJSON(w, http.StatusOK, map[string]any{"members": members})
}
