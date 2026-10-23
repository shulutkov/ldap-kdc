package dockerdns

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"golang.org/x/crypto/bcrypt"

	"github.com/shulutkov/ldap-kdc/internal/secret"
	"github.com/shulutkov/ldap-kdc/internal/store"
)

// fakeDaemon answers the two calls the registration makes: the container list and the event
// stream, which it holds open and never sends on.
type fakeDaemon struct {
	mu         sync.Mutex
	containers []map[string]any
	fail       bool
	srv        *httptest.Server
}

func newFakeDaemon(t *testing.T) *fakeDaemon {
	t.Helper()

	f := &fakeDaemon{}
	mux := http.NewServeMux()

	mux.HandleFunc("GET /containers/json", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()

		if f.fail {
			http.Error(w, "daemon is down", http.StatusInternalServerError)

			return
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(f.containers)
	})

	mux.HandleFunc("GET /events", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.(http.Flusher).Flush()
		<-r.Context().Done()
	})

	f.srv = httptest.NewServer(mux)
	t.Cleanup(f.srv.Close)

	return f
}

func (f *fakeDaemon) endpoint() string {
	return "tcp://" + strings.TrimPrefix(f.srv.URL, "http://")
}

func (f *fakeDaemon) set(containers ...map[string]any) {
	f.mu.Lock()
	defer f.mu.Unlock()

	f.containers = containers
}

func (f *fakeDaemon) setFailing(fail bool) {
	f.mu.Lock()
	defer f.mu.Unlock()

	f.fail = fail
}

// ctr is a running container with an address on each of the given networks.
func ctr(id, name string, addresses map[string]string) map[string]any {
	networks := map[string]any{}
	for network, ip := range addresses {
		networks[network] = map[string]any{"IPAddress": ip}
	}

	return map[string]any{
		"Id":              id,
		"Names":           []string{"/" + name},
		"NetworkSettings": map[string]any{"Networks": networks},
	}
}

func testStore(t *testing.T) *store.Store {
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

	st, err := store.Open(context.Background(), filepath.Join(dir, "dns.db"), sealer,
		zerolog.New(io.Discard), store.WithPasswordHashCost(bcrypt.MinCost))
	if err != nil {
		t.Fatalf("store: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })

	return st
}

// newDiscovery points a registration at the fake daemon. The tests drive reconcile directly, so
// the background loop never runs and every assertion sees a settled state.
func newDiscovery(t *testing.T, f *fakeDaemon, st *store.Store, networks ...string) *Discovery {
	t.Helper()

	d, err := New(Config{
		Endpoint:    f.endpoint(),
		Networks:    networks,
		Zone:        "Example.COM.",
		TTL:         300,
		ResyncEvery: time.Minute,
	}, st, zerolog.New(io.Discard))
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	return d
}

// discovered lists the registrations as name -> address, the form the assertions compare.
func discovered(t *testing.T, st *store.Store) map[string]string {
	t.Helper()

	records, err := st.ListDiscoveredDNSRecords(context.Background(), source)
	if err != nil {
		t.Fatalf("ListDiscoveredDNSRecords: %v", err)
	}

	out := map[string]string{}
	for _, r := range records {
		out[r.Name] = r.Value
	}

	return out
}

func TestRegistersOnlyTheSelectedNetworks(t *testing.T) {
	ctx := context.Background()
	f := newFakeDaemon(t)
	st := testStore(t)

	f.set(
		ctr("web-id", "web", map[string]string{"app": "10.0.0.5", "other": "10.1.0.5"}),
		ctr("db-id", "db", map[string]string{"other": "10.1.0.6"}),
	)

	newDiscovery(t, f, st, "app").reconcile(ctx)

	got := discovered(t, st)
	if len(got) != 1 || got["web.example.com"] != "10.0.0.5" {
		t.Errorf("registrations = %v, want only web on the app network", got)
	}

	records, _ := st.ListDiscoveredDNSRecords(ctx, source)
	if len(records) != 1 || records[0].Origin != "docker:web-id" || records[0].TTL != 300 {
		t.Errorf("record = %+v, want origin docker:web-id and the zone's ttl", records)
	}
}

func TestCIDRSelectsByAddress(t *testing.T) {
	ctx := context.Background()
	f := newFakeDaemon(t)
	st := testStore(t)

	f.set(
		ctr("web-id", "web", map[string]string{"app": "10.0.0.5", "other": "10.1.0.5"}),
		ctr("db-id", "db", map[string]string{"other": "10.1.0.6"}),
	)

	newDiscovery(t, f, st, "10.1.0.0/16").reconcile(ctx)

	got := discovered(t, st)
	if len(got) != 2 || got["web.example.com"] != "10.1.0.5" || got["db.example.com"] != "10.1.0.6" {
		t.Errorf("registrations = %v, want web and db on their addresses inside the prefix", got)
	}
}

func TestStoppedContainerIsUnregistered(t *testing.T) {
	ctx := context.Background()
	f := newFakeDaemon(t)
	st := testStore(t)
	d := newDiscovery(t, f, st, "app")

	f.set(ctr("web-id", "web", map[string]string{"app": "10.0.0.5"}))
	d.reconcile(ctx)

	before, _ := st.ZoneSerial(ctx)

	f.set()
	d.reconcile(ctx)

	if got := discovered(t, st); len(got) != 0 {
		t.Errorf("registrations after the container stopped = %v, want none", got)
	}

	// The removal is a change to the zone, so a secondary comparing serials sees it.
	if after, _ := st.ZoneSerial(ctx); after <= before {
		t.Errorf("zone serial %d after the removal, want past %d", after, before)
	}
}

func TestRenameMovesTheRegistration(t *testing.T) {
	ctx := context.Background()
	f := newFakeDaemon(t)
	st := testStore(t)
	d := newDiscovery(t, f, st, "app")

	f.set(ctr("web-id", "web", map[string]string{"app": "10.0.0.5"}))
	d.reconcile(ctx)

	f.set(ctr("web-id", "api", map[string]string{"app": "10.0.0.5"}))
	d.reconcile(ctx)

	if got := discovered(t, st); len(got) != 1 || got["api.example.com"] != "10.0.0.5" {
		t.Errorf("registrations after the rename = %v, want only api", got)
	}
}

func TestDaemonOutageKeepsRegistrations(t *testing.T) {
	ctx := context.Background()
	f := newFakeDaemon(t)
	st := testStore(t)
	d := newDiscovery(t, f, st, "app")

	f.set(ctr("web-id", "web", map[string]string{"app": "10.0.0.5"}))
	d.reconcile(ctx)

	// An unanswered daemon says nothing about what runs, so the names of running containers stay.
	f.setFailing(true)
	d.reconcile(ctx)

	if got := discovered(t, st); got["web.example.com"] != "10.0.0.5" {
		t.Errorf("registrations during an outage = %v, want web kept", got)
	}
}

func TestAdministratorsNameIsNotTaken(t *testing.T) {
	ctx := context.Background()
	f := newFakeDaemon(t)
	st := testStore(t)

	manual := &store.DNSRecord{Name: "web.example.com", Type: "A", Value: "192.0.2.1", TTL: 300}
	if err := st.CreateDNSRecord(ctx, manual); err != nil {
		t.Fatalf("CreateDNSRecord: %v", err)
	}

	f.set(ctr("web-id", "web", map[string]string{"app": "10.0.0.5"}))
	newDiscovery(t, f, st, "app").reconcile(ctx)

	if got := discovered(t, st); len(got) != 0 {
		t.Errorf("registrations = %v, want none under a name an administrator holds", got)
	}

	records, _ := st.LookupDNSRecords(ctx, "web.example.com")
	if len(records) != 1 || records[0].Value != "192.0.2.1" || records[0].Origin != "" {
		t.Errorf("administrator's record = %+v, want it untouched", records)
	}
}

func TestEachSelectedAddressIsRegistered(t *testing.T) {
	ctx := context.Background()
	f := newFakeDaemon(t)
	st := testStore(t)

	f.set(ctr("web-id", "web", map[string]string{"app": "10.0.0.5", "front": "10.2.0.5"}))
	newDiscovery(t, f, st, "app", "front").reconcile(ctx)

	records, _ := st.ListDiscoveredDNSRecords(ctx, source)
	if len(records) != 2 {
		t.Fatalf("records = %+v, want one address per selected network", records)
	}
}

func TestSelectsIgnoresIPv6AndAddresslessContainers(t *testing.T) {
	ctx := context.Background()
	f := newFakeDaemon(t)
	st := testStore(t)

	f.set(
		ctr("v6-id", "v6", map[string]string{"app": "fd00::5"}),
		ctr("host-id", "host", map[string]string{"app": ""}),
	)
	newDiscovery(t, f, st, "app").reconcile(ctx)

	if got := discovered(t, st); len(got) != 0 {
		t.Errorf("registrations = %v, want none: the zone carries A records only", got)
	}
}

func TestNewRejectsAnUnknownEndpoint(t *testing.T) {
	_, err := New(Config{Endpoint: "ftp://nope", Networks: []string{"app"}, Zone: "example.com", TTL: 60, ResyncEvery: time.Minute},
		nil, zerolog.New(io.Discard))
	if err == nil {
		t.Error("New accepted an ftp endpoint")
	}
}
