package scanner

import (
	"testing"
	"time"
)

func TestProxyThrottle(t *testing.T) {
	cur := time.Unix(1000, 0)
	tr := NewProxyThrottle(2 * time.Second)
	tr.now = func() time.Time { return cur }

	const a, b = "1.2.3.4:1080", "5.6.7.8:1080"

	if !tr.Ready(a) {
		t.Fatal("first use of a should be ready")
	}
	if tr.Ready(a) {
		t.Error("immediate reuse of a should NOT be ready")
	}
	if !tr.Ready(b) {
		t.Error("different proxy b should be ready independently")
	}

	// advance less than the interval - still resting
	cur = cur.Add(1 * time.Second)
	if tr.Ready(a) {
		t.Error("reuse of a within interval should NOT be ready")
	}

	// advance past the interval - ready again
	cur = cur.Add(2 * time.Second) // 3s since a's last use
	if !tr.Ready(a) {
		t.Error("reuse of a after interval should be ready")
	}
}

func TestProxyThrottleDisabled(t *testing.T) {
	var nilT *ProxyThrottle
	if !nilT.Ready("x:1") {
		t.Error("nil throttle should always be ready (1st call)")
	}
	if !nilT.Ready("x:1") {
		t.Error("nil throttle should always be ready (2nd call)")
	}

	zero := NewProxyThrottle(0)
	if !zero.Ready("x:1") {
		t.Error("zero-interval throttle should always be ready (1st call)")
	}
	if !zero.Ready("x:1") {
		t.Error("zero-interval throttle should always be ready (2nd call)")
	}
}
