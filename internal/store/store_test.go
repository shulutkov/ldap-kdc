package store

import (
	"context"
	"errors"
	"io"
	"path/filepath"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"golang.org/x/crypto/bcrypt"

	"github.com/shulutkov/ldap-kdc/internal/krbkeys"
	"github.com/shulutkov/ldap-kdc/internal/secret"
)

func testStore(t *testing.T) *Store {
	t.Helper()

	dir := t.TempDir()

	key, _, err := secret.LoadOrCreateMasterKey(filepath.Join(dir, "master.key"))
	if err != nil {
		t.Fatalf("master key: %v", err)
	}

	sealer, err := secret.NewSealer(key)
	if err != nil {
		t.Fatalf("sealer: %v", err)
	}

	// Hashing at the production cost would have this suite spend minutes proving nothing about
	// the cost. What it is is measured by BenchmarkHashPassword instead.
	s, err := Open(context.Background(), filepath.Join(dir, "test.db"), sealer,
		zerolog.New(io.Discard), WithPasswordHashCost(bcrypt.MinCost))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })

	return s
}

func testEncTypes(t *testing.T) []int32 {
	t.Helper()

	ids, err := krbkeys.ResolveEncTypes([]string{"aes256-cts-hmac-sha1-96", "aes128-cts-hmac-sha1-96"})
	if err != nil {
		t.Fatalf("enctypes: %v", err)
	}

	return ids
}

func TestEnsureRealmIsIdempotent(t *testing.T) {
	ctx := context.Background()
	s := testStore(t)
	etypes := testEncTypes(t)

	first, err := s.EnsureRealm(ctx, "EXAMPLE.COM", etypes)
	if err != nil {
		t.Fatalf("first EnsureRealm: %v", err)
	}
	if !first {
		t.Fatal("first EnsureRealm should report initialization")
	}

	second, err := s.EnsureRealm(ctx, "EXAMPLE.COM", etypes)
	if err != nil {
		t.Fatalf("second EnsureRealm: %v", err)
	}
	if second {
		t.Fatal("second EnsureRealm should be a no-op")
	}

	if _, err := s.EnsureRealm(ctx, "OTHER.COM", etypes); err == nil {
		t.Fatal("switching realms should be refused")
	}

	tgt, err := s.GetPrincipal(ctx, krbkeys.MustParseName("krbtgt/EXAMPLE.COM", "EXAMPLE.COM"))
	if err != nil {
		t.Fatalf("krbtgt: %v", err)
	}
	if len(tgt.Keys) != len(etypes) {
		t.Fatalf("krbtgt has %d keys, want %d", len(tgt.Keys), len(etypes))
	}
	for _, k := range tgt.Keys {
		if len(k.Value) == 0 {
			t.Fatalf("krbtgt key for etype %d is empty", k.EType)
		}
		if len(k.Salt) > 0 {
			t.Errorf("krbtgt key should be random, not password derived (salt %q)", k.Salt)
		}
	}
}

func TestSetUserPasswordWritesBothCredentialForms(t *testing.T) {
	ctx := context.Background()
	s := testStore(t)
	etypes := testEncTypes(t)

	if _, err := s.EnsureRealm(ctx, "EXAMPLE.COM", etypes); err != nil {
		t.Fatalf("EnsureRealm: %v", err)
	}

	g := &Group{Name: "staff", GIDNumber: 5000}
	if err := s.CreateGroup(ctx, g); err != nil {
		t.Fatalf("CreateGroup: %v", err)
	}

	u := &User{Name: "alice", UIDNumber: 10000, PrimaryGroup: 5000, Mail: "alice@example.com"}
	if err := s.CreateUser(ctx, u); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}

	name := krbkeys.MustParseName("alice", "EXAMPLE.COM")
	p := &Principal{
		Name: name.Principal(), Realm: name.Realm, UserID: &u.ID,
		Enabled: true, RequiresPreAuth: true, AllowForwardable: true, AllowRenewable: true,
	}

	keys, err := krbkeys.RandomKeys(etypes)
	if err != nil {
		t.Fatalf("RandomKeys: %v", err)
	}
	if err := s.CreatePrincipal(ctx, p, keys); err != nil {
		t.Fatalf("CreatePrincipal: %v", err)
	}

	if err := s.SetUserPassword(ctx, "alice", "correct horse battery staple", etypes, nil); err != nil {
		t.Fatalf("SetUserPassword: %v", err)
	}

	got, err := s.GetUser(ctx, "alice")
	if err != nil {
		t.Fatalf("GetUser: %v", err)
	}
	if !CheckPassword(got.PassBcrypt, "correct horse battery staple") {
		t.Error("LDAP side: password does not verify")
	}
	if CheckPassword(got.PassBcrypt, "wrong") {
		t.Error("LDAP side: wrong password verified")
	}

	kp, err := s.GetPrincipal(ctx, name)
	if err != nil {
		t.Fatalf("GetPrincipal: %v", err)
	}
	if kp.KVNO != 2 {
		t.Errorf("kvno is %d, want 2 after one password change", kp.KVNO)
	}

	// The Kerberos side must hold exactly the key a client derives from the same password and
	// the principal's default salt; anything else and pre-authentication fails at login.
	want, err := krbkeys.DeriveKeys("correct horse battery staple", name, etypes)
	if err != nil {
		t.Fatalf("DeriveKeys: %v", err)
	}
	for _, w := range want {
		k, ok := kp.KeyFor(w.EType)
		if !ok {
			t.Fatalf("principal has no key for etype %d", w.EType)
		}
		if string(k.Value) != string(w.Value) {
			t.Errorf("etype %d: stored key does not match the client derivation", w.EType)
		}
		if k.Salt != name.DefaultSalt() {
			t.Errorf("etype %d: salt is %q, want %q", w.EType, k.Salt, name.DefaultSalt())
		}
	}

	// The previous key version must survive so tickets issued under it still decrypt.
	if prev, err := s.GetPrincipalKVNO(ctx, name, 1); err != nil {
		t.Errorf("previous kvno: %v", err)
	} else if len(prev.Keys) == 0 {
		t.Error("previous kvno has no keys")
	}
}

func TestKeysAreSealedAgainstTheirPrincipal(t *testing.T) {
	ctx := context.Background()
	s := testStore(t)
	etypes := testEncTypes(t)

	if _, err := s.EnsureRealm(ctx, "EXAMPLE.COM", etypes); err != nil {
		t.Fatalf("EnsureRealm: %v", err)
	}

	name := krbkeys.MustParseName("krbtgt/EXAMPLE.COM", "EXAMPLE.COM")

	p, err := s.GetPrincipal(ctx, name)
	if err != nil {
		t.Fatalf("GetPrincipal: %v", err)
	}

	var sealed []byte
	if err := s.db.QueryRowContext(ctx,
		`SELECT key FROM principal_keys WHERE principal_id = ? AND kvno = ? AND etype = ?`,
		p.ID, p.KVNO, p.Keys[0].EType,
	).Scan(&sealed); err != nil {
		t.Fatalf("reading sealed key: %v", err)
	}

	// A key lifted out of one principal's row must not decrypt under another's context, or a
	// stolen database row could be replayed onto a different identity.
	if _, err := s.openKey(p.ID+1, p.KVNO, p.Keys[0].EType, sealed); err == nil {
		t.Error("a key sealed for one principal opened under another")
	}

	plain, err := s.openKey(p.ID, p.KVNO, p.Keys[0].EType, sealed)
	if err != nil {
		t.Fatalf("opening key under its own context: %v", err)
	}
	if string(plain) != string(p.Keys[0].Value) {
		t.Error("decrypted key does not match the loaded one")
	}
}

func TestGroupExpansion(t *testing.T) {
	ctx := context.Background()
	s := testStore(t)

	// "umbrella" includes "danger": whoever is in danger is also seen in umbrella.
	if err := s.CreateGroup(ctx, &Group{Name: "danger", GIDNumber: 5504}); err != nil {
		t.Fatalf("CreateGroup danger: %v", err)
	}
	if err := s.CreateGroup(ctx, &Group{Name: "umbrella", GIDNumber: 5503, IncludeGroups: []int{5504}}); err != nil {
		t.Fatalf("CreateGroup umbrella: %v", err)
	}

	u := &User{Name: "bob", UIDNumber: 10001, PrimaryGroup: 5504}
	if err := s.CreateUser(ctx, u); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}

	members, err := s.GroupMembers(ctx, 5503)
	if err != nil {
		t.Fatalf("GroupMembers: %v", err)
	}
	if len(members) != 1 || members[0] != "bob" {
		t.Errorf("umbrella members = %v, want [bob]", members)
	}

	gids, err := s.UserGIDs(ctx, u)
	if err != nil {
		t.Fatalf("UserGIDs: %v", err)
	}
	if len(gids) != 2 || gids[0] != 5503 || gids[1] != 5504 {
		t.Errorf("bob's gids = %v, want [5503 5504]", gids)
	}
}

func TestGroupIncludeCycleTerminates(t *testing.T) {
	ctx := context.Background()
	s := testStore(t)

	if err := s.CreateGroup(ctx, &Group{Name: "a", GIDNumber: 1}); err != nil {
		t.Fatalf("CreateGroup a: %v", err)
	}
	if err := s.CreateGroup(ctx, &Group{Name: "b", GIDNumber: 2, IncludeGroups: []int{1}}); err != nil {
		t.Fatalf("CreateGroup b: %v", err)
	}
	if _, err := s.UpdateGroup(ctx, "a", func(g *Group) error {
		g.IncludeGroups = []int{2}

		return nil
	}); err != nil {
		t.Fatalf("UpdateGroup a: %v", err)
	}

	done := make(chan []int, 1)
	go func() {
		gids, err := s.ExpandGroup(ctx, 1)
		if err != nil {
			t.Errorf("ExpandGroup: %v", err)
		}
		done <- gids
	}()

	select {
	case gids := <-done:
		if len(gids) != 2 {
			t.Errorf("cyclic expansion = %v, want both groups once", gids)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("ExpandGroup did not terminate on a cyclic include graph")
	}
}

func TestDuplicateUserIsAConflict(t *testing.T) {
	ctx := context.Background()
	s := testStore(t)

	if err := s.CreateUser(ctx, &User{Name: "carol", UIDNumber: 1, PrimaryGroup: 1}); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}

	err := s.CreateUser(ctx, &User{Name: "carol", UIDNumber: 2, PrimaryGroup: 1})
	if !errors.Is(err, ErrConflict) {
		t.Errorf("duplicate user error = %v, want ErrConflict", err)
	}
}

func TestLockoutAfterRepeatedFailures(t *testing.T) {
	ctx := context.Background()
	s := testStore(t)
	etypes := testEncTypes(t)

	if _, err := s.EnsureRealm(ctx, "EXAMPLE.COM", etypes); err != nil {
		t.Fatalf("EnsureRealm: %v", err)
	}

	name := krbkeys.MustParseName("krbtgt/EXAMPLE.COM", "EXAMPLE.COM")

	p, err := s.GetPrincipal(ctx, name)
	if err != nil {
		t.Fatalf("GetPrincipal: %v", err)
	}

	policy := LockoutPolicy{MaxFailures: 3, FailureCountInterval: time.Minute, LockoutDuration: time.Minute}

	for range 3 {
		if err := s.RecordAuthResult(ctx, p.ID, false, policy); err != nil {
			t.Fatalf("RecordAuthResult: %v", err)
		}
	}

	locked, err := s.GetPrincipal(ctx, name)
	if err != nil {
		t.Fatalf("GetPrincipal: %v", err)
	}
	if status := locked.Status(time.Now()); status != PrincipalLockedOut {
		t.Errorf("status = %v, want the principal locked out after 3 failures", status)
	}

	if err := s.RecordAuthResult(ctx, p.ID, true, policy); err != nil {
		t.Fatalf("RecordAuthResult success: %v", err)
	}

	unlocked, err := s.GetPrincipal(ctx, name)
	if err != nil {
		t.Fatalf("GetPrincipal: %v", err)
	}
	if status := unlocked.Status(time.Now()); status != PrincipalOK {
		t.Errorf("principal should be usable after a success: %v", status)
	}
}

func TestSecurityIdentifiersDoNotCollideBetweenUsersAndGroups(t *testing.T) {
	ctx := context.Background()
	s := testStore(t)

	if _, err := s.EnsureIDRange(ctx, DefaultIDRange()); err != nil {
		t.Fatalf("EnsureIDRange: %v", err)
	}

	// The POSIX uid and gid spaces are independent, so a directory may hold a user and a group
	// that share a number. Deriving a RID from the number alone would give them the same SID,
	// and a member server would then read one as the other.
	const shared = 7000

	g := &Group{Name: "shared", GIDNumber: shared}
	if err := s.CreateGroup(ctx, g); err != nil {
		t.Fatalf("CreateGroup: %v", err)
	}

	u := &User{Name: "shared", UIDNumber: shared, PrimaryGroup: shared}
	if err := s.CreateUser(ctx, u); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}

	groupRID, ok, err := s.RID(ctx, "group", g.ID)
	if err != nil || !ok {
		t.Fatalf("group RID: %v (found %v)", err, ok)
	}

	userRID, ok, err := s.RID(ctx, "user", u.ID)
	if err != nil || !ok {
		t.Fatalf("user RID: %v (found %v)", err, ok)
	}

	if userRID == groupRID {
		t.Fatalf("the user and the group share RID %d", userRID)
	}

	// The group took the primary interval because it was created first; the user fell back to
	// the secondary one, which is exactly the mechanism FreeIPA uses.
	r := s.IDRange()
	if groupRID != r.BaseRID+shared-r.BaseID {
		t.Errorf("group RID = %d, want the primary %d", groupRID, r.BaseRID+shared-r.BaseID)
	}
	if userRID != r.SecondaryBaseRID+shared-r.BaseID {
		t.Errorf("user RID = %d, want the secondary %d", userRID, r.SecondaryBaseRID+shared-r.BaseID)
	}
}

func TestSecurityIdentifierIsReleasedAndReallocated(t *testing.T) {
	ctx := context.Background()
	s := testStore(t)

	if _, err := s.EnsureIDRange(ctx, DefaultIDRange()); err != nil {
		t.Fatalf("EnsureIDRange: %v", err)
	}

	u := &User{Name: "mover", UIDNumber: 8000, PrimaryGroup: 1}
	if err := s.CreateUser(ctx, u); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}

	before, _, err := s.RID(ctx, "user", u.ID)
	if err != nil {
		t.Fatalf("RID: %v", err)
	}

	// A changed uid means a changed identity to a member server, so the allocation has to move.
	if _, err := s.UpdateUser(ctx, "mover", func(u *User) error {
		u.UIDNumber = 8001

		return nil
	}); err != nil {
		t.Fatalf("UpdateUser: %v", err)
	}

	after, _, err := s.RID(ctx, "user", u.ID)
	if err != nil {
		t.Fatalf("RID: %v", err)
	}
	if after != before+1 {
		t.Errorf("RID = %d, want %d after the uid moved up by one", after, before+1)
	}

	// Deleting the account frees its identifier for whoever takes the uid next.
	if err := s.DeleteUser(ctx, "mover"); err != nil {
		t.Fatalf("DeleteUser: %v", err)
	}

	next := &User{Name: "successor", UIDNumber: 8001, PrimaryGroup: 1}
	if err := s.CreateUser(ctx, next); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}

	reused, _, err := s.RID(ctx, "user", next.ID)
	if err != nil {
		t.Fatalf("RID: %v", err)
	}
	if reused != after {
		t.Errorf("RID = %d, want the released %d", reused, after)
	}
}

func TestFailureCountDecaysWithTheInterval(t *testing.T) {
	ctx := context.Background()
	s := testStore(t)
	etypes := testEncTypes(t)

	if _, err := s.EnsureRealm(ctx, "EXAMPLE.COM", etypes); err != nil {
		t.Fatalf("EnsureRealm: %v", err)
	}

	name := krbkeys.MustParseName("krbtgt/EXAMPLE.COM", "EXAMPLE.COM")

	p, err := s.GetPrincipal(ctx, name)
	if err != nil {
		t.Fatalf("GetPrincipal: %v", err)
	}

	// A failure older than the interval no longer counts, so occasional typos spread over
	// months cannot accumulate into a lockout of an account nobody is attacking.
	policy := LockoutPolicy{MaxFailures: 3, FailureCountInterval: time.Hour, LockoutDuration: time.Minute}

	for range 2 {
		if err := s.RecordAuthResult(ctx, p.ID, false, policy); err != nil {
			t.Fatalf("RecordAuthResult: %v", err)
		}
	}

	// Backdate the last failure past the interval.
	stale := time.Now().Add(-2 * time.Hour).Unix()
	if _, err := s.db.ExecContext(ctx,
		`UPDATE principals SET last_failure = ? WHERE id = ?`, stale, p.ID); err != nil {
		t.Fatalf("backdating: %v", err)
	}

	if err := s.RecordAuthResult(ctx, p.ID, false, policy); err != nil {
		t.Fatalf("RecordAuthResult: %v", err)
	}

	after, err := s.GetPrincipal(ctx, name)
	if err != nil {
		t.Fatalf("GetPrincipal: %v", err)
	}

	if after.FailCount != 1 {
		t.Errorf("fail count = %d, want the tally restarted at 1", after.FailCount)
	}
	if status := after.Status(time.Now()); status != PrincipalOK {
		t.Errorf("status = %v, want the principal still usable", status)
	}
}

func TestProductionHashCostIsNotWeakenedByTheTestOption(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()

	key, _, err := secret.LoadOrCreateMasterKey(filepath.Join(dir, "master.key"))
	if err != nil {
		t.Fatalf("master key: %v", err)
	}

	sealer, err := secret.NewSealer(key)
	if err != nil {
		t.Fatalf("sealer: %v", err)
	}

	// Opened the way the service opens it, with no options at all.
	s, err := Open(ctx, filepath.Join(dir, "cost.db"), sealer, zerolog.New(io.Discard))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })

	hash, err := s.HashPassword("a reasonably long password")
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}

	cost, err := bcrypt.Cost([]byte(hash))
	if err != nil {
		t.Fatalf("reading the cost back: %v", err)
	}

	// The suites lower this so they do not spend minutes on it. A refactor that let that
	// setting escape into the default would weaken every password the service ever stores,
	// silently and everywhere.
	if cost != DefaultPasswordHashCost {
		t.Errorf("a store opened without options hashes at cost %d, want %d",
			cost, DefaultPasswordHashCost)
	}
}
