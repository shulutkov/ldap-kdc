// Package failban throttles password guessing by source address, for every door that takes a
// password.
//
// It is one limiter shared between the doors, not one per door, and that is the point of it living
// here: a guesser locked out of LDAP binds must not simply carry on at the management API's sign-in
// with the same list. Each attempt costs the server a bcrypt verification and the attacker nothing.
package failban

import (
	"sync"
	"time"
)

// Config is the policy, in the words the configuration already uses for it.
type Config struct {
	Enabled bool
	// Threshold failures within Window block the source for BlockFor.
	Threshold int
	Window    time.Duration
	BlockFor  time.Duration
	// PruneEvery and PruneOlder bound the table, which would otherwise keep every address that
	// ever failed once.
	PruneEvery time.Duration
	PruneOlder time.Duration
}

// Limiter tracks failures per source.
type Limiter struct {
	mu      sync.Mutex
	cfg     Config
	sources map[string]*source

	nextPrune time.Time
}

type source struct {
	failures  []time.Time
	lastSeen  time.Time
	blockedTo time.Time
}

// New builds a limiter.
func New(cfg Config) *Limiter {
	return &Limiter{cfg: cfg, sources: make(map[string]*source), nextPrune: time.Now()}
}

// Blocked reports whether the source is serving a timeout.
func (l *Limiter) Blocked(addr string) bool {
	if l == nil || !l.cfg.Enabled {
		return false
	}

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

// NoteFailure records a failed attempt and blocks the source once the threshold is reached within
// the window.
func (l *Limiter) NoteFailure(addr string) {
	if l == nil || !l.cfg.Enabled {
		return
	}

	now := time.Now()

	l.mu.Lock()
	defer l.mu.Unlock()

	s, ok := l.sources[addr]
	if !ok {
		s = &source{}
		l.sources[addr] = s
	}
	s.lastSeen = now

	// Only failures inside the window count, so an address that fails once a day never
	// accumulates its way into a block.
	cutoff := now.Add(-l.cfg.Window)
	kept := s.failures[:0]
	for _, t := range s.failures {
		if t.After(cutoff) {
			kept = append(kept, t)
		}
	}
	s.failures = append(kept, now)

	if l.cfg.Threshold > 0 && len(s.failures) >= l.cfg.Threshold {
		s.blockedTo = now.Add(l.cfg.BlockFor)
		s.failures = nil
	}
}

// NoteSuccess clears the failure history of a source.
func (l *Limiter) NoteSuccess(addr string) {
	if l == nil || !l.cfg.Enabled {
		return
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	if s, ok := l.sources[addr]; ok {
		s.failures = nil
		s.lastSeen = time.Now()
	}
}

// pruneLocked drops sources that have not been seen for a while.
func (l *Limiter) pruneLocked(now time.Time) {
	if now.Before(l.nextPrune) {
		return
	}
	l.nextPrune = now.Add(l.cfg.PruneEvery)

	cutoff := now.Add(-l.cfg.PruneOlder)
	for addr, s := range l.sources {
		if s.lastSeen.Before(cutoff) && now.After(s.blockedTo) {
			delete(l.sources, addr)
		}
	}
}
