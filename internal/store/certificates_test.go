package store

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestSerialNormalization(t *testing.T) {
	for in, want := range map[string]string{
		"2a":   "2a",   // already canonical
		"2A":   "2a",   // case is not part of the value
		"abc":  "0abc", // padded to whole bytes
		"AbC":  "0abc",
		"00ab": "00ab", // leading bytes beyond the pad are the caller's
	} {
		if got := normalizeSerial(in); got != want {
			t.Errorf("normalizeSerial(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestCertificates(t *testing.T) {
	ctx := context.Background()
	s := testStore(t)

	u := &User{Name: "alice", UIDNumber: 10000, PrimaryGroup: 5000}
	if err := s.CreateUser(ctx, u); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	other := &User{Name: "bob", UIDNumber: 10001, PrimaryGroup: 5000}
	if err := s.CreateUser(ctx, other); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}

	now := time.Now().UTC().Truncate(time.Second)
	cert := &Certificate{
		Serial:    "2a",
		Subject:   "CN=alice,O=Example",
		DER:       []byte("a first certificate"),
		NotBefore: now.Add(-time.Hour),
		NotAfter:  now.Add(time.Hour),
	}
	if err := s.AddCertificate(ctx, "alice", cert); err != nil {
		t.Fatalf("AddCertificate: %v", err)
	}
	if cert.ID == 0 || cert.CreatedAt.IsZero() {
		t.Errorf("AddCertificate filled in id %d and createdAt %v", cert.ID, cert.CreatedAt)
	}

	// The same serial twice is a conflict, whoever it is imported for and however it is
	// spelled: the database enforces what an issuer's serial uniqueness promises.
	dup := &Certificate{Serial: "2A", Subject: "CN=other", DER: []byte("another"), NotBefore: now, NotAfter: now}
	if err := s.AddCertificate(ctx, "bob", dup); !errors.Is(err, ErrConflict) {
		t.Errorf("duplicate serial error = %v, want ErrConflict", err)
	}

	// An account that does not exist is not found, not an empty success.
	if err := s.AddCertificate(ctx, "nobody", dup); !errors.Is(err, ErrNotFound) {
		t.Errorf("AddCertificate for a missing account = %v, want ErrNotFound", err)
	}

	// Serial numbers are unique per issuer: two authorities may both issue serial 2a, but one
	// issuer may not issue it twice.
	carol := &User{Name: "carol", UIDNumber: 10002, PrimaryGroup: 5000}
	if err := s.CreateUser(ctx, carol); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	for _, issuer := range []string{"aa", "bb"} {
		c := &Certificate{Issuer: issuer, Serial: "2a", Subject: "CN=carol", DER: []byte(issuer),
			NotBefore: now, NotAfter: now.Add(time.Hour)}
		if err := s.AddCertificate(ctx, "carol", c); err != nil {
			t.Fatalf("AddCertificate from issuer %s: %v", issuer, err)
		}
	}
	again := &Certificate{Issuer: "AA", Serial: "2a", Subject: "CN=carol", DER: []byte("again"),
		NotBefore: now, NotAfter: now.Add(time.Hour)}
	if err := s.AddCertificate(ctx, "carol", again); !errors.Is(err, ErrConflict) {
		t.Errorf("same serial from the same issuer = %v, want ErrConflict", err)
	}
	if got, err := s.GetCertificate(ctx, "carol", "BB", "2a"); err != nil || string(got.DER) != "bb" {
		t.Errorf("GetCertificate by issuer = %v (%v), want issuer bb's certificate", got, err)
	}

	second := &Certificate{
		Serial:    "2b",
		Subject:   "CN=alice,O=Example",
		DER:       []byte("a second certificate"),
		NotBefore: now.Add(-time.Hour),
		NotAfter:  now.Add(2 * time.Hour),
	}
	if err := s.AddCertificate(ctx, "alice", second); err != nil {
		t.Fatalf("AddCertificate second: %v", err)
	}

	// A 160-bit serial, the size Vault issues: text is exactly why it fits.
	bigSerial := "01" + strings.Repeat("ef", 19)
	wide := &Certificate{
		Serial:    bigSerial,
		Subject:   "CN=alice,O=Example",
		DER:       []byte("a wide-serial certificate"),
		NotBefore: now.Add(-time.Hour),
		NotAfter:  now.Add(time.Hour),
	}
	if err := s.AddCertificate(ctx, "alice", wide); err != nil {
		t.Fatalf("AddCertificate with a 160-bit serial: %v", err)
	}

	bobs := &Certificate{
		Serial:    "2c",
		Subject:   "CN=bob,O=Example",
		DER:       []byte("bob's certificate"),
		NotBefore: now.Add(-time.Hour),
		NotAfter:  now.Add(time.Hour),
	}
	if err := s.AddCertificate(ctx, "bob", bobs); err != nil {
		t.Fatalf("AddCertificate bob: %v", err)
	}

	list, err := s.ListUserCertificates(ctx, "alice")
	if err != nil {
		t.Fatalf("ListUserCertificates: %v", err)
	}
	if len(list) != 3 || list[0].Serial != "2a" || list[1].Serial != "2b" || list[2].Serial != bigSerial {
		t.Errorf("alice's certificates = %v, want serials 2a, 2b, then the wide one", list)
	}
	if got := string(list[0].DER); got != "a first certificate" {
		t.Errorf("DER = %q", got)
	}
	if !list[0].NotBefore.Equal(now.Add(-time.Hour)) || !list[0].NotAfter.Equal(now.Add(time.Hour)) {
		t.Errorf("validity window = %v..%v", list[0].NotBefore, list[0].NotAfter)
	}
	if _, err := s.ListUserCertificates(ctx, "nobody"); !errors.Is(err, ErrNotFound) {
		t.Errorf("ListUserCertificates for a missing account = %v, want ErrNotFound", err)
	}

	// The batch read the LDAP front end does: one query, grouped by the ids it was asked about.
	byID, err := s.UserCertificates(ctx, []int64{u.ID, other.ID})
	if err != nil {
		t.Fatalf("UserCertificates: %v", err)
	}
	if len(byID[u.ID]) != 3 || len(byID[other.ID]) != 1 {
		t.Errorf("UserCertificates = %v, want three for alice and one for bob", byID)
	}
	if byID[other.ID][0].UserName != "bob" {
		t.Errorf("bob's certificate reads back as %q", byID[other.ID][0].UserName)
	}

	// More accounts than one batch names, with the account at the end and listed twice: its
	// certificates still come back once each.
	many := make([]int64, 0, 1201)
	for i := int64(0); i < 1200; i++ {
		many = append(many, 100000+i)
	}
	many = append(many, u.ID, u.ID)
	wideBatch, err := s.UserCertificates(ctx, many)
	if err != nil {
		t.Fatalf("UserCertificates across batches: %v", err)
	}
	if len(wideBatch[u.ID]) != 3 {
		t.Errorf("alice across batches has %d certificates, want 3", len(wideBatch[u.ID]))
	}

	// A lookup normalizes its serial too, so the spelling the caller has need not be the
	// spelling that was stored.
	got, err := s.GetCertificate(ctx, "alice", "", "2B")
	if err != nil {
		t.Fatalf("GetCertificate: %v", err)
	}
	if string(got.DER) != "a second certificate" {
		t.Errorf("GetCertificate DER = %q", got.DER)
	}
	if _, err := s.GetCertificate(ctx, "alice", "", "99"); !errors.Is(err, ErrNotFound) {
		t.Errorf("GetCertificate of a missing serial = %v, want ErrNotFound", err)
	}

	if err := s.DeleteCertificate(ctx, "alice", "", "2a"); err != nil {
		t.Fatalf("DeleteCertificate: %v", err)
	}
	if err := s.DeleteCertificate(ctx, "alice", "", "2a"); !errors.Is(err, ErrNotFound) {
		t.Errorf("deleting again = %v, want ErrNotFound", err)
	}
	if list, err := s.ListUserCertificates(ctx, "alice"); err != nil || len(list) != 2 {
		t.Errorf("after the delete alice has %v (%v), want two certificates", list, err)
	}

	// The account going away takes its certificates with it.
	if err := s.DeleteUser(ctx, "bob"); err != nil {
		t.Fatalf("DeleteUser: %v", err)
	}
	if byID, err := s.UserCertificates(ctx, []int64{other.ID}); err != nil || len(byID[other.ID]) != 0 {
		t.Errorf("bob's certificates survived the account: %v (%v)", byID, err)
	}
}
