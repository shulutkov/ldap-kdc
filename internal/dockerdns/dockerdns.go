// Package dockerdns registers the containers of a Docker host in the realm's zone.
//
// A container on a configured network gets an address record under its name in the zone, and the
// record goes when the container stops. The daemon is the source of truth: the registrations are
// reconciled against its full list of running containers, and the daemon's event stream only
// brings that reconciliation forward. A missed event therefore costs at most one resync interval.
//
// Registrations are tagged with their origin in the store, so they never touch a record an
// administrator made, and a name an administrator already holds is left to them.
package dockerdns

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"time"

	"github.com/rs/zerolog"

	"github.com/shulutkov/ldap-kdc/internal/dnssrv"
	"github.com/shulutkov/ldap-kdc/internal/store"
)

// source is the origin prefix every registration of this package carries.
const source = "docker"

// Config is what the registration needs, in the terms the configuration file gives it.
type Config struct {
	// Endpoint is unix:///path/to/socket or tcp://host:port.
	Endpoint string
	// Networks selects containers: a network name, or an IPv4 CIDR an address must fall in.
	Networks []string
	// Zone is the forward zone the container names are registered under.
	Zone string
	// TTL is the lifetime of each registered record, in seconds.
	TTL         int
	ResyncEvery time.Duration
}

// Discovery keeps the zone's container registrations in step with the Docker daemon.
type Discovery struct {
	cfg      Config
	st       *store.Store
	log      zerolog.Logger
	client   *http.Client
	base     string
	names    map[string]bool
	prefixes []netip.Prefix

	// wake brings a reconciliation forward when the daemon reports a change. It holds at most one
	// pending request, so a burst of events costs one reconciliation, not one each.
	wake chan struct{}

	// blocked holds the names an administrator's record has refused on the last reconciliation,
	// so each refusal is logged when it begins rather than on every resync.
	blocked map[string]bool

	cancel context.CancelFunc
	done   chan struct{}
}

// New prepares a registration. It does not contact the daemon; Start does.
func New(cfg Config, st *store.Store, log zerolog.Logger) (*Discovery, error) {
	client, base, err := dialer(cfg.Endpoint)
	if err != nil {
		return nil, err
	}

	d := &Discovery{
		cfg:    cfg,
		st:     st,
		log:    log.With().Str("component", "dockerdns").Logger(),
		client: client,
		base:   base,
		names:  map[string]bool{},
		wake:   make(chan struct{}, 1),
	}
	d.cfg.Zone = store.NormalizeDNSName(cfg.Zone)

	for _, n := range cfg.Networks {
		if strings.Contains(n, "/") {
			p, err := netip.ParsePrefix(n)
			if err != nil {
				return nil, fmt.Errorf("dockerdns: network %q: %w", n, err)
			}
			d.prefixes = append(d.prefixes, p)
			continue
		}
		d.names[n] = true
	}

	return d, nil
}

// dialer builds the HTTP client for a daemon endpoint, and the base URL its API paths hang from.
func dialer(endpoint string) (*http.Client, string, error) {
	u, err := url.Parse(endpoint)
	if err != nil {
		return nil, "", fmt.Errorf("dockerdns: endpoint %q: %w", endpoint, err)
	}

	switch u.Scheme {
	case "unix":
		socket := u.Path
		transport := &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				var d net.Dialer

				return d.DialContext(ctx, "unix", socket)
			},
		}

		// The daemon's API has no host of its own over a socket; the name only fills the request.
		return &http.Client{Transport: transport}, "http://docker", nil
	case "tcp", "http":
		return &http.Client{}, "http://" + u.Host, nil
	default:
		return nil, "", fmt.Errorf("dockerdns: endpoint %q must be unix:// or tcp://", endpoint)
	}
}

// Start begins the registration. It returns at once; the work runs until Shutdown.
func (d *Discovery) Start(ctx context.Context) {
	ctx, cancel := context.WithCancel(ctx)
	d.cancel = cancel
	d.done = make(chan struct{})

	d.log.Info().Str("endpoint", d.cfg.Endpoint).Str("zone", d.cfg.Zone).
		Strs("networks", d.cfg.Networks).Msg("container registration started")

	go d.run(ctx)
}

// Shutdown stops the registration and waits for it to leave. The records already registered stay:
// the containers they describe are still running, and the next start reconciles them.
func (d *Discovery) Shutdown(ctx context.Context) error {
	if d.cancel == nil {
		return nil
	}

	d.cancel()

	select {
	case <-d.done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (d *Discovery) run(ctx context.Context) {
	defer close(d.done)

	go d.watch(ctx)

	ticker := time.NewTicker(d.cfg.ResyncEvery)
	defer ticker.Stop()

	d.reconcile(ctx)

	for {
		select {
		case <-ctx.Done():
			return
		case <-d.wake:
		case <-ticker.C:
		}

		d.reconcile(ctx)
	}
}

// signal asks for a reconciliation without waiting for one.
func (d *Discovery) signal() {
	select {
	case d.wake <- struct{}{}:
	default:
	}
}

// watch follows the daemon's event stream, reconnecting with a backoff that resets once events
// flow again.
func (d *Discovery) watch(ctx context.Context) {
	const (
		minBackoff = time.Second
		maxBackoff = 30 * time.Second
	)

	backoff := minBackoff

	for {
		n, err := d.streamEvents(ctx)
		if ctx.Err() != nil {
			return
		}

		if n > 0 {
			backoff = minBackoff
		}

		d.log.Warn().Err(err).Dur("retryIn", backoff).Msg("docker event stream ended")

		select {
		case <-ctx.Done():
			return
		case <-time.After(backoff):
		}

		backoff = min(backoff*2, maxBackoff)
	}
}

// streamEvents reads the container and network events that can change a registration. It reports
// how many it read before the stream ended.
func (d *Discovery) streamEvents(ctx context.Context) (int, error) {
	filters := `{"type":["container","network"],"event":["start","die","stop","destroy","rename","connect","disconnect"]}`

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, d.base+"/events?filters="+url.QueryEscape(filters), nil)
	if err != nil {
		return 0, err
	}

	resp, err := d.client.Do(req)
	if err != nil {
		return 0, err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("docker answered %s to the event stream", resp.Status)
	}

	var n int

	dec := json.NewDecoder(resp.Body)
	for {
		var ev struct {
			Type   string `json:"Type"`
			Action string `json:"Action"`
		}

		if err := dec.Decode(&ev); err != nil {
			return n, err
		}

		n++
		d.signal()
	}
}

// container is the part of the daemon's container listing a registration reads.
type container struct {
	ID    string   `json:"Id"`
	Names []string `json:"Names"`

	NetworkSettings struct {
		Networks map[string]struct {
			IPAddress string `json:"IPAddress"`
		} `json:"Networks"`
	} `json:"NetworkSettings"`
}

// containers lists the running containers.
func (d *Discovery) containers(ctx context.Context) ([]container, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, d.base+"/containers/json", nil)
	if err != nil {
		return nil, err
	}

	resp, err := d.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("docker answered %s to the container list", resp.Status)
	}

	var out []container
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, err
	}

	return out, nil
}

// desired works out the registrations the running containers call for, keyed by identity.
func (d *Discovery) desired(containers []container) map[string]store.DNSRecord {
	out := map[string]store.DNSRecord{}

	for _, c := range containers {
		if len(c.Names) == 0 {
			continue
		}

		name := store.NormalizeDNSName(strings.TrimPrefix(c.Names[0], "/"))
		fqdn := name + "." + d.cfg.Zone

		for network, ep := range c.NetworkSettings.Networks {
			addr, err := netip.ParseAddr(ep.IPAddress)
			if err != nil || !addr.Is4() || !d.selects(network, addr) {
				continue
			}

			rec := store.DNSRecord{
				Name:   fqdn,
				Type:   "A",
				Value:  addr.String(),
				TTL:    d.cfg.TTL,
				Origin: source + ":" + c.ID,
			}

			if err := dnssrv.ValidateRecord(rec); err != nil {
				d.log.Warn().Err(err).Str("container", name).Msg("container name cannot be registered")

				continue
			}

			out[identity(rec)] = rec
		}
	}

	return out
}

// selects reports whether a container address on a network is one to register.
func (d *Discovery) selects(network string, addr netip.Addr) bool {
	if d.names[network] {
		return true
	}

	for _, p := range d.prefixes {
		if p.Contains(addr) {
			return true
		}
	}

	return false
}

// identity is what makes two registrations the same one: the container, the name and the address.
func identity(r store.DNSRecord) string {
	return r.Origin + "|" + r.Name + "|" + r.Value
}

// reconcile brings the registered records into line with the running containers. If the daemon
// cannot be asked, nothing changes: an outage must not take the names of running containers away.
func (d *Discovery) reconcile(ctx context.Context) {
	containers, err := d.containers(ctx)
	if err != nil {
		if ctx.Err() == nil {
			d.log.Warn().Err(err).Msg("listing containers failed; registrations left as they are")
		}

		return
	}

	want := d.desired(containers)

	have, err := d.st.ListDiscoveredDNSRecords(ctx, source)
	if err != nil {
		d.log.Warn().Err(err).Msg("reading registrations failed")

		return
	}

	held := make(map[string]store.DNSRecord, len(have))
	for _, r := range have {
		held[identity(r)] = r
	}

	stillBlocked := map[string]bool{}
	defer func() { d.blocked = stillBlocked }()

	for key, rec := range want {
		if _, ok := held[key]; ok {
			continue
		}

		taken, err := d.administered(ctx, rec.Name)
		if err != nil {
			d.log.Warn().Err(err).Str("name", rec.Name).Msg("reading the name failed")

			continue
		}
		if taken {
			// Said once, not on every resync: the name stays refused until it is free.
			if !d.blocked[rec.Name] {
				d.log.Warn().Str("name", rec.Name).Msg("an administrator's record holds the name; not registered")
			}
			stillBlocked[rec.Name] = true

			continue
		}

		if err := d.st.CreateDiscoveredDNSRecord(ctx, rec.Origin, &rec); err != nil {
			if !errors.Is(err, store.ErrConflict) {
				d.log.Warn().Err(err).Str("name", rec.Name).Msg("registering a container failed")
			}

			continue
		}

		d.log.Info().Str("name", rec.Name).Str("address", rec.Value).Str("origin", rec.Origin).
			Msg("container registered")
	}

	for key, r := range held {
		if _, ok := want[key]; ok {
			continue
		}

		if err := d.st.DeleteDiscoveredDNSRecord(ctx, r.ID); err != nil && !errors.Is(err, store.ErrNotFound) {
			d.log.Warn().Err(err).Str("name", r.Name).Msg("removing a registration failed")

			continue
		}

		d.log.Info().Str("name", r.Name).Str("address", r.Value).Str("origin", r.Origin).
			Msg("container registration removed")
	}
}

// administered reports whether an administrator has a record at a name. A registration never
// shares a name with one, so that name is left to the administrator.
func (d *Discovery) administered(ctx context.Context, name string) (bool, error) {
	records, err := d.st.LookupDNSRecords(ctx, name)
	if err != nil {
		return false, err
	}

	for _, r := range records {
		if len(r.Origin) == 0 {
			return true, nil
		}
	}

	return false, nil
}
