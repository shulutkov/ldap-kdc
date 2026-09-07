package store

import (
	"context"
	"errors"
	"testing"
)

func TestCustomAttributesRoundTripOnBothKindsOfObject(t *testing.T) {
	ctx := context.Background()
	s := testStore(t)

	g := &Group{
		Name: "engineering", GIDNumber: 5000,
		CustomAttrs: map[string][]string{"costCentre": {"CC-42"}},
	}
	if err := s.CreateGroup(ctx, g); err != nil {
		t.Fatalf("CreateGroup: %v", err)
	}

	u := &User{
		Name: "alice", UIDNumber: 10000, PrimaryGroup: 5000,
		// Several values under one name, because an account can hold more than one role and
		// a policy elsewhere has to see all of them.
		CustomAttrs: map[string][]string{"departmentHead": {"engineering", "platform"}},
	}
	if err := s.CreateUser(ctx, u); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}

	got, err := s.GetGroup(ctx, "engineering")
	if err != nil {
		t.Fatalf("GetGroup: %v", err)
	}
	if v := got.CustomAttrs["costCentre"]; len(v) != 1 || v[0] != "CC-42" {
		t.Errorf("group attributes = %v", got.CustomAttrs)
	}

	user, err := s.GetUser(ctx, "alice")
	if err != nil {
		t.Fatalf("GetUser: %v", err)
	}
	if v := user.CustomAttrs["departmentHead"]; len(v) != 2 || v[0] != "engineering" || v[1] != "platform" {
		t.Errorf("user attributes = %v, want both values in the order they were given", user.CustomAttrs)
	}

	// Updating replaces the set outright, so a name left out is gone rather than merged.
	if _, err := s.UpdateGroup(ctx, "engineering", func(g *Group) error {
		g.CustomAttrs = map[string][]string{"owner": {"alice"}}

		return nil
	}); err != nil {
		t.Fatalf("UpdateGroup: %v", err)
	}

	if got, err = s.GetGroup(ctx, "engineering"); err != nil {
		t.Fatalf("GetGroup: %v", err)
	}
	if _, ok := got.CustomAttrs["costCentre"]; ok {
		t.Errorf("a replaced attribute survived: %v", got.CustomAttrs)
	}

	// Nothing is left behind for the next object to inherit through a reused id.
	if err := s.DeleteUser(ctx, "alice"); err != nil {
		t.Fatalf("DeleteUser: %v", err)
	}
	if err := s.DeleteGroup(ctx, "engineering"); err != nil {
		t.Fatalf("DeleteGroup: %v", err)
	}

	var n int
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM object_attrs`).Scan(&n); err != nil {
		t.Fatalf("counting attributes: %v", err)
	}
	if n != 0 {
		t.Errorf("%d attribute rows outlived the objects that carried them", n)
	}
}

func TestAttributesTheDirectoryBuildsCannotBeOverridden(t *testing.T) {
	ctx := context.Background()
	s := testStore(t)

	if err := s.CreateGroup(ctx, &Group{Name: "staff", GIDNumber: 5000}); err != nil {
		t.Fatalf("CreateGroup: %v", err)
	}

	for _, name := range []string{"memberOf", "objectclass", "krbPrincipalName", "uidNumber", " spaced"} {
		// An account that could write its own memberOf would be granting itself whatever an
		// authorization rule reads out of the directory.
		err := s.CreateUser(ctx, &User{
			Name: "forger", UIDNumber: 10001, PrimaryGroup: 5000,
			CustomAttrs: map[string][]string{name: {"cn=admins,ou=groups,dc=example,dc=com"}},
		})
		if !errors.Is(err, ErrInvalidAttribute) {
			t.Errorf("custom attribute %q: %v, want it refused", name, err)
			_ = s.DeleteUser(ctx, "forger")
		}
	}

	if err := s.CreateGroup(ctx, &Group{
		Name: "other", GIDNumber: 5001,
		CustomAttrs: map[string][]string{"gidNumber": {"0"}},
	}); !errors.Is(err, ErrInvalidAttribute) {
		t.Errorf("a group overriding gidNumber: %v, want it refused", err)
	}
}
