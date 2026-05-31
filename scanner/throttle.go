package scanner

import (
	"sync"
	"time"
)

// ProxyThrottle spaces out reuse of individual proxies during a scan - "proxy
// burn protection". Free SOCKS proxies often get rate-limited or banned when hit
// with many rapid connections, so a proxy is only "ready" again once the
// configured minimum interval has elapsed since its last use. This protects your
// own proxy pool from being burned mid-scan; it is not a target-evasion feature.
//
// A nil throttle, or one with a non-positive interval, imposes no limit.
type ProxyThrottle struct {
	interval time.Duration
	mu       sync.Mutex
	lastUse  map[string]time.Time
	now      func() time.Time // injectable for tests; defaults to time.Now
}

// NewProxyThrottle returns a throttle enforcing at least interval between
// consecutive uses of the same proxy.
func NewProxyThrottle(interval time.Duration) *ProxyThrottle {
	return &ProxyThrottle{
		interval: interval,
		lastUse:  make(map[string]time.Time),
		now:      time.Now,
	}
}

// Ready reports whether the proxy at addr may be used now. When it returns true
// it records the use, so a subsequent call within the interval returns false.
// A nil throttle or non-positive interval always returns true.
func (t *ProxyThrottle) Ready(addr string) bool {
	if t == nil || t.interval <= 0 {
		return true
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	now := t.now()
	if last, ok := t.lastUse[addr]; ok && now.Sub(last) < t.interval {
		return false
	}
	t.lastUse[addr] = now
	return true
}
