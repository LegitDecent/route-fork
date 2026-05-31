package scanner

import (
	"context"
	"errors"
	"net"
	"sync"
	"testing"
	"time"

	"rofk/proxy"
)

// A target-side failure (proxy fine, target down/filtered) must NOT prune the
// proxy. Otherwise scanning a range of dead hosts destroys the whole pool.
func TestRotateScan_TargetFailureDoesNotPrune(t *testing.T) {
	dial := func(ctx context.Context, p *proxy.Proxy, host string, port int, to time.Duration) (net.Conn, error) {
		return nil, errors.New("no CONNECT response") // IsProxyError true, IsProxyDead false
	}
	var mu sync.Mutex
	pruned := 0
	hooks := RotateHooks{OnProxyDead: func(*proxy.Proxy) { mu.Lock(); pruned++; mu.Unlock() }}
	out := RotateScan(context.Background(), dial, mkPool(3),
		RotateConfig{Target: "t", Ports: []int{80}, Quorum: 2, DialConcurrency: 4}, hooks)
	if out[0].Verdict != QuorumUnreachable {
		t.Fatalf("verdict = %v, want Unreachable", out[0].Verdict)
	}
	mu.Lock()
	defer mu.Unlock()
	if pruned != 0 {
		t.Fatalf("a target failure must not prune any proxy; pruned %d", pruned)
	}
}

// A proxy we genuinely cannot reach IS pruned.
func TestRotateScan_UnreachableProxyIsPruned(t *testing.T) {
	dial := func(ctx context.Context, p *proxy.Proxy, host string, port int, to time.Duration) (net.Conn, error) {
		return nil, errors.New("dial tcp " + p.Address() + ": connect: connection refused")
	}
	var mu sync.Mutex
	pruned := map[string]bool{}
	hooks := RotateHooks{OnProxyDead: func(p *proxy.Proxy) { mu.Lock(); pruned[p.Address()] = true; mu.Unlock() }}
	RotateScan(context.Background(), dial, mkPool(3),
		RotateConfig{Target: "t", Ports: []int{80}, Quorum: 2, DialConcurrency: 4}, hooks)
	mu.Lock()
	defer mu.Unlock()
	if len(pruned) == 0 {
		t.Fatal("an unreachable proxy should be pruned")
	}
}

// When burn protection has rested every proxy, the scan must fall back to using
// a resting proxy rather than report a false "unreachable".
func TestRotateScan_BurnProtectionFallsBackWhenStarved(t *testing.T) {
	th := NewProxyThrottle(time.Hour)
	pool := mkPool(3)
	for _, p := range pool {
		th.Ready(p.Address()) // mark each used -> none are "ready"
	}
	dial := func(ctx context.Context, p *proxy.Proxy, host string, port int, to time.Duration) (net.Conn, error) {
		return newFakeConn(""), nil // all open
	}
	out := RotateScan(context.Background(), dial, pool,
		RotateConfig{Target: "t", Ports: []int{80}, Quorum: 2, DialConcurrency: 4, Throttle: th}, RotateHooks{})
	if out[0].Verdict != QuorumOpen {
		t.Fatalf("starved burn protection should fall back to resting proxies; got %v", out[0].Verdict)
	}
}
