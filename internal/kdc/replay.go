package kdc

import (
	"crypto/sha256"
	"encoding/binary"
	"sync"
	"time"
)

// replayCache remembers the authenticators seen recently so that a captured TGS-REQ cannot be
// resent to obtain a second service ticket. RFC 4120 section 3.2.3 requires this of any receiver
// that accepts an AP-REQ, and the KDC is one: without it the pre-authentication in a TGS exchange
// proves only that the client once held the session key, not that it holds it now.
type replayCache struct {
	mu      sync.Mutex
	entries map[[32]byte]time.Time
	window  time.Duration

	// lastSweep throttles the expiry scan so a busy KDC does not walk the whole map per request.
	lastSweep time.Time
}

func newReplayCache(window time.Duration) *replayCache {
	return &replayCache{
		entries: make(map[[32]byte]time.Time),
		window:  window,
	}
}

// seen records an authenticator and reports whether it had already been recorded. The key is a
// digest of the identity, the timestamp and the microseconds, which is what RFC 4120 says
// distinguishes two authenticators from the same client.
func (c *replayCache) seen(crealm, cname string, ctime time.Time, cusec int, ticketDigest []byte) bool {
	h := sha256.New()
	h.Write([]byte(crealm))
	h.Write([]byte{0})
	h.Write([]byte(cname))
	h.Write([]byte{0})

	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], uint64(ctime.UnixNano()))
	h.Write(buf[:])
	binary.BigEndian.PutUint64(buf[:], uint64(cusec))
	h.Write(buf[:])
	h.Write(ticketDigest)

	var key [32]byte
	copy(key[:], h.Sum(nil))

	now := time.Now()

	c.mu.Lock()
	defer c.mu.Unlock()

	c.sweepLocked(now)

	if _, dup := c.entries[key]; dup {
		return true
	}

	c.entries[key] = now

	return false
}

// sweepLocked drops entries older than the acceptance window. Anything that old would be rejected
// for clock skew anyway, so remembering it no longer buys anything.
func (c *replayCache) sweepLocked(now time.Time) {
	if now.Sub(c.lastSweep) < c.window/4 {
		return
	}
	c.lastSweep = now

	cutoff := now.Add(-c.window)
	for k, t := range c.entries {
		if t.Before(cutoff) {
			delete(c.entries, k)
		}
	}
}

// size reports the number of remembered authenticators, for tests and diagnostics.
func (c *replayCache) size() int {
	c.mu.Lock()
	defer c.mu.Unlock()

	return len(c.entries)
}
