package ldapsrv

import (
	"net"
	"sync"
	"time"
)

// bindLimiter throttles password guessing over LDAP by source address. A directory exposed to a
// network is otherwise an unlimited oracle: bind is cheap for the attacker and each attempt costs
// the server a bcrypt verification.
type bindLimiter struct {
	mu      sync.Mutex
	sources map[string]*sourceState

	enabled    bool
	threshold  int
	window     time.Duration
	blockFor   time.Duration
	pruneEvery time.Duration
	pruneOlder time.Duration

	nextPrune time.Time
}

type sourceState struct {
	failures  []time.Time
	lastSeen  time.Time
	blockedTo time.Time
}

func newBindLimiter(cfg Config) *bindLimiter {
	return &bindLimiter{
		sources:    make(map[string]*sourceState),
		enabled:    cfg.LimitFailedBinds,
		threshold:  cfg.NumberOfFailedBinds,
		window:     cfg.PeriodOfFailedBinds,
		blockFor:   cfg.BlockFailedBindsFor,
		pruneEvery: cfg.PruneSourceTableEvery,
		pruneOlder: cfg.PruneSourcesOlderThan,
		nextPrune:  time.Now(),
	}
}

// blocked reports whether the source is currently serving a timeout.
func (l *bindLimiter) blocked(conn net.Conn) bool {
	if !l.enabled {
		return false
	}

	addr := sourceAddr(conn)
	now := time.Now()

	l.mu.Lock()
	defer l.mu.Unlock()

	l.pruneLocked(now)

	s, ok := l.sources[addr]
	if !ok {
		return false
	}

	s.lastSeen = now

	return now.Before(s.blockedTo)
}

// noteFailure records a failed bind and blocks the source once the threshold is reached within the
// window.
func (l *bindLimiter) noteFailure(conn net.Conn) {
	if !l.enabled {
		return
	}

	addr := sourceAddr(conn)
	now := time.Now()

	l.mu.Lock()
	defer l.mu.Unlock()

	s, ok := l.sources[addr]
	if !ok {
		s = &sourceState{}
		l.sources[addr] = s
	}

	s.lastSeen = now

	// Only failures inside the window count, so an address that fails once a day never
	// accumulates its way into a block.
	cutoff := now.Add(-l.window)
	kept := s.failures[:0]
	for _, t := range s.failures {
		if t.After(cutoff) {
			kept = append(kept, t)
		}
	}
	s.failures = append(kept, now)

	if l.threshold > 0 && len(s.failures) >= l.threshold {
		s.blockedTo = now.Add(l.blockFor)
		s.failures = nil
	}
}

// noteSuccess clears the failure history of a source.
func (l *bindLimiter) noteSuccess(conn net.Conn) {
	if !l.enabled {
		return
	}

	addr := sourceAddr(conn)

	l.mu.Lock()
	defer l.mu.Unlock()

	if s, ok := l.sources[addr]; ok {
		s.failures = nil
		s.lastSeen = time.Now()
	}
}

// pruneLocked drops sources that have not been seen for a while, so the table does not grow with
// every address that ever connected.
func (l *bindLimiter) pruneLocked(now time.Time) {
	if now.Before(l.nextPrune) {
		return
	}
	l.nextPrune = now.Add(l.pruneEvery)

	cutoff := now.Add(-l.pruneOlder)
	for addr, s := range l.sources {
		if s.lastSeen.Before(cutoff) && now.After(s.blockedTo) {
			delete(l.sources, addr)
		}
	}
}

// sourceAddr identifies a client by address, dropping the ephemeral port so that repeated
// connections from the same host are counted together.
func sourceAddr(conn net.Conn) string {
	if conn == nil || conn.RemoteAddr() == nil {
		return "unknown"
	}

	host, _, err := net.SplitHostPort(conn.RemoteAddr().String())
	if err != nil {
		return conn.RemoteAddr().String()
	}

	return host
}
