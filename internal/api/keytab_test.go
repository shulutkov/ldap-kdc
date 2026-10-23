package api

import (
	"context"
	"net/http"
	"testing"

	"github.com/go-krb5/krb5/keytab"

	"github.com/shulutkov/ldap-kdc/internal/krbkeys"
)

// keytabFor posts a principal list and returns the parsed keytab.
func keytabFor(t *testing.T, h *harness, body map[string]any) (*keytab.Keytab, int, []byte) {
	t.Helper()

	status, raw := h.raw(t, "POST", "/api/v1/keytab", body, testToken)
	if status != http.StatusOK {
		return nil, status, raw
	}

	kt := keytab.New()
	if err := kt.Unmarshal(raw); err != nil {
		t.Fatalf("the keytab does not parse: %v", err)
	}

	return kt, status, raw
}

func TestKeytabForSeveralPrincipalsInOneFile(t *testing.T) {
	h := newHarness(t)

	for _, name := range []string{"HTTP/nn.adh.local", "nn/nn.adh.local", "hdfs"} {
		if status, body := h.do(t, "POST", "/api/v1/principals", map[string]any{"name": name}); status != http.StatusCreated {
			t.Fatalf("creating %s: status = %d, body = %v", name, status, body)
		}
	}

	kt, status, raw := keytabFor(t, h, map[string]any{
		"principals": []string{"HTTP/nn.adh.local", "nn/nn.adh.local", "hdfs"},
	})
	if status != http.StatusOK {
		t.Fatalf("status = %d, body = %s", status, raw)
	}

	// One key per enctype for each of the three principals.
	if want := 3 * len(h.etypes); len(kt.Entries) != want {
		t.Fatalf("keytab has %d entries, want %d", len(kt.Entries), want)
	}

	for _, p := range []string{"HTTP/nn.adh.local", "nn/nn.adh.local", "hdfs"} {
		name := krbkeys.MustParseName(p, testRealm)
		if _, _, err := kt.GetEncryptionKey(name.PrincipalName(), testRealm, 0, h.etypes[0]); err != nil {
			t.Errorf("%s: no usable key in the keytab: %v", p, err)
		}
	}
}

func TestKeytabDeduplicatesAndFollowsAliases(t *testing.T) {
	h := newHarness(t)

	h.do(t, "POST", "/api/v1/principals", map[string]any{
		"name": "HTTP/web.example.com", "aliases": []string{"HTTP/www.example.com"},
	})

	kt, status, raw := keytabFor(t, h, map[string]any{
		"principals": []string{"HTTP/web.example.com", "HTTP/www.example.com", "HTTP/web.example.com@" + testRealm},
	})
	if status != http.StatusOK {
		t.Fatalf("status = %d, body = %s", status, raw)
	}

	if len(kt.Entries) != len(h.etypes) {
		t.Errorf("keytab has %d entries, want %d (one principal named three ways)", len(kt.Entries), len(h.etypes))
	}
}

func TestKeytabUnknownPrincipalWritesNothing(t *testing.T) {
	ctx := context.Background()
	h := newHarness(t)

	h.do(t, "POST", "/api/v1/principals", map[string]any{"name": "hdfs"})

	before, err := h.store.GetPrincipal(ctx, krbkeys.MustParseName("hdfs", testRealm))
	if err != nil {
		t.Fatal(err)
	}

	_, status, _ := keytabFor(t, h, map[string]any{
		"principals": []string{"hdfs", "nosuch/host.example.com"},
		"randkey":    true,
	})
	if status != http.StatusNotFound {
		t.Fatalf("status = %d, want %d", status, http.StatusNotFound)
	}

	// The known principal must not have been re-keyed by a request that failed on the other one.
	after, err := h.store.GetPrincipal(ctx, krbkeys.MustParseName("hdfs", testRealm))
	if err != nil {
		t.Fatal(err)
	}
	if after.KVNO != before.KVNO {
		t.Errorf("hdfs was re-keyed by a failed request: kvno %d -> %d", before.KVNO, after.KVNO)
	}
}

func TestKeytabWithoutRandKeyKeepsTheKeys(t *testing.T) {
	ctx := context.Background()
	h := newHarness(t)

	h.do(t, "POST", "/api/v1/principals", map[string]any{"name": "hdfs"})
	name := krbkeys.MustParseName("hdfs", testRealm)

	before, err := h.store.GetPrincipal(ctx, name)
	if err != nil {
		t.Fatal(err)
	}

	if _, status, raw := keytabFor(t, h, map[string]any{"principals": []string{"hdfs"}}); status != http.StatusOK {
		t.Fatalf("status = %d, body = %s", status, raw)
	}

	after, err := h.store.GetPrincipal(ctx, name)
	if err != nil {
		t.Fatal(err)
	}
	if after.KVNO != before.KVNO {
		t.Errorf("kvno changed without randkey: %d -> %d", before.KVNO, after.KVNO)
	}
}

func TestKeytabRandKeyBumpsTheKVNO(t *testing.T) {
	ctx := context.Background()
	h := newHarness(t)

	h.do(t, "POST", "/api/v1/principals", map[string]any{"name": "hdfs"})
	name := krbkeys.MustParseName("hdfs", testRealm)

	before, err := h.store.GetPrincipal(ctx, name)
	if err != nil {
		t.Fatal(err)
	}

	kt, status, raw := keytabFor(t, h, map[string]any{"principals": []string{"hdfs"}, "randkey": true})
	if status != http.StatusOK {
		t.Fatalf("status = %d, body = %s", status, raw)
	}

	after, err := h.store.GetPrincipal(ctx, name)
	if err != nil {
		t.Fatal(err)
	}
	if after.KVNO != before.KVNO+1 {
		t.Errorf("kvno = %d, want %d", after.KVNO, before.KVNO+1)
	}

	// The keytab carries the new kvno, the one the KDC now expects.
	if _, _, err := kt.GetEncryptionKey(name.PrincipalName(), testRealm, after.KVNO, h.etypes[0]); err != nil {
		t.Errorf("the keytab does not hold the new kvno: %v", err)
	}
}

func TestKeytabRejectsEmptyAndOversizedRequests(t *testing.T) {
	h := newHarness(t)

	if _, status, _ := keytabFor(t, h, map[string]any{"principals": []string{}}); status != http.StatusBadRequest {
		t.Errorf("empty list: status = %d, want %d", status, http.StatusBadRequest)
	}

	big := make([]string, maxKeytabPrincipals+1)
	for i := range big {
		big[i] = "hdfs"
	}
	if _, status, _ := keytabFor(t, h, map[string]any{"principals": big}); status != http.StatusBadRequest {
		t.Errorf("oversized list: status = %d, want %d", status, http.StatusBadRequest)
	}
}
