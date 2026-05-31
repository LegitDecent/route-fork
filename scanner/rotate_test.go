package scanner

import (
	"context"
	"fmt"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"rofk/proxy"
)

// ── test doubles ────────────────────────────────────────────────────────────

type dummyAddr struct{}

func (dummyAddr) Network() string { return "tcp" }
func (dummyAddr) String() string  { return "fake:0" }

// fakeConn is a net.Conn that returns a fixed banner then EOF.
type fakeConn struct{ r *strings.Reader }

func newFakeConn(banner string) *fakeConn { return &fakeConn{r: strings.NewReader(banner)} }

func (c *fakeConn) Read(b []byte) (int, error)       { return c.r.Read(b) }
func (c *fakeConn) Write(b []byte) (int, error)      { return len(b), nil }
func (c *fakeConn) Close() error                     { return nil }
func (c *fakeConn) LocalAddr() net.Addr              { return dummyAddr{} }
func (c *fakeConn) RemoteAddr() net.Addr             { return dummyAddr{} }
func (c *fakeConn) SetDeadline(time.Time) error      { return nil }
func (c *fakeConn) SetReadDeadline(time.Time) error  { return nil }
func (c *fakeConn) SetWriteDeadline(time.Time) error { return nil }

const (
	voteOpen = iota
	voteRefused
	voteProxyErr
)

type behavior struct {
	kind   int
	banner string
}

// mockDialer returns a DialFunc driven by per-proxy-address behaviour. It also
// records how many times each address was dialled (guarded by mu).
func mockDialer(beh map[string]behavior) (DialFunc, *sync.Map) {
	var calls sync.Map // addr -> *int32 not needed; use mutex map
	var mu sync.Mutex
	counts := map[string]int{}
	dial := func(ctx context.Context, p *proxy.Proxy, host string, port int, to time.Duration) (net.Conn, error) {
		mu.Lock()
		counts[p.Address()]++
		mu.Unlock()
		b, ok := beh[p.Address()]
		if !ok {
			b = behavior{kind: voteOpen}
		}
		switch b.kind {
		case voteProxyErr:
			// "dial tcp <proxyAddr>:..." is classified proxy-side by IsProxyError.
			return nil, fmt.Errorf("dial tcp %s: connect: connection refused", p.Address())
		case voteRefused:
			// Bare "connection refused" is a target-side result (port closed).
			return nil, fmt.Errorf("connection refused")
		default:
			return newFakeConn(b.banner), nil
		}
	}
	// stash counts behind the sync.Map handle so callers can read post-run
	calls.Store("counts", func() map[string]int {
		mu.Lock()
		defer mu.Unlock()
		out := map[string]int{}
		for k, v := range counts {
			out[k] = v
		}
		return out
	})
	return dial, &calls
}

func dialCounts(h *sync.Map) map[string]int {
	v, _ := h.Load("counts")
	return v.(func() map[string]int)()
}

func mkPool(n int) []*proxy.Proxy {
	var pool []*proxy.Proxy
	for i := 0; i < n; i++ {
		pool = append(pool, &proxy.Proxy{Host: fmt.Sprintf("10.0.0.%d", i+1), Port: 1080, Proto: "socks5"})
	}
	return pool
}

func addr(i int) string { return fmt.Sprintf("10.0.0.%d:1080", i+1) }

// ── tests ───────────────────────────────────────────────────────────────────

func TestRotateScan_QuorumReached(t *testing.T) {
	dial, _ := mockDialer(nil) // all open
	pool := mkPool(3)
	out := RotateScan(context.Background(), dial, pool,
		RotateConfig{Target: "t", Ports: []int{80}, Quorum: 2, DialConcurrency: 4}, RotateHooks{})
	if len(out) != 1 {
		t.Fatalf("want 1 outcome, got %d", len(out))
	}
	if out[0].Verdict != QuorumOpen {
		t.Fatalf("want QuorumOpen, got %v", out[0].Verdict)
	}
	if out[0].Confirmations < 2 {
		t.Fatalf("want >=2 confirmations, got %d", out[0].Confirmations)
	}
	if len(out[0].OpenLabels) != out[0].Confirmations {
		t.Fatalf("OpenLabels (%d) should match confirmations (%d)", len(out[0].OpenLabels), out[0].Confirmations)
	}
}

func TestRotateScan_RefutedOverridesOpen(t *testing.T) {
	dial, _ := mockDialer(map[string]behavior{
		addr(1): {kind: voteRefused},
	})
	pool := mkPool(3) // p0 open, p1 refused, p2 open
	out := RotateScan(context.Background(), dial, pool,
		RotateConfig{Target: "t", Ports: []int{80}, Quorum: 2, DialConcurrency: 4}, RotateHooks{})
	if out[0].Verdict != QuorumRefuted {
		t.Fatalf("want QuorumRefuted, got %v", out[0].Verdict)
	}
	if out[0].RefutedBy != addr(1) {
		t.Fatalf("want RefutedBy %s, got %q", addr(1), out[0].RefutedBy)
	}
}

func TestRotateScan_AllProxyErrorsUnreachable(t *testing.T) {
	beh := map[string]behavior{}
	for i := 0; i < 3; i++ {
		beh[addr(i)] = behavior{kind: voteProxyErr}
	}
	dial, _ := mockDialer(beh)

	var deadMu sync.Mutex
	dead := map[string]int{}
	hooks := RotateHooks{OnProxyDead: func(p *proxy.Proxy) {
		deadMu.Lock()
		dead[p.Address()]++
		deadMu.Unlock()
	}}

	out := RotateScan(context.Background(), dial, mkPool(3),
		RotateConfig{Target: "t", Ports: []int{80}, Quorum: 2, DialConcurrency: 4}, hooks)
	if out[0].Verdict != QuorumUnreachable {
		t.Fatalf("want QuorumUnreachable, got %v", out[0].Verdict)
	}
	// Each dead proxy must be reported exactly once (markFailed dedups).
	deadMu.Lock()
	defer deadMu.Unlock()
	if len(dead) != 3 {
		t.Fatalf("want 3 dead proxies reported, got %d (%v)", len(dead), dead)
	}
	for a, c := range dead {
		if c != 1 {
			t.Fatalf("proxy %s reported dead %d times, want exactly 1", a, c)
		}
	}
}

func TestRotateScan_SubQuorumUnconfirmed(t *testing.T) {
	// Only p0 opens; p1 and p2 are proxy-errors. Quorum 3 can never be met.
	beh := map[string]behavior{
		addr(1): {kind: voteProxyErr},
		addr(2): {kind: voteProxyErr},
	}
	dial, _ := mockDialer(beh)
	out := RotateScan(context.Background(), dial, mkPool(3),
		RotateConfig{Target: "t", Ports: []int{80}, Quorum: 3, DialConcurrency: 4}, RotateHooks{})
	if out[0].Verdict != QuorumUnconfirmed {
		t.Fatalf("want QuorumUnconfirmed, got %v (confirmations=%d)", out[0].Verdict, out[0].Confirmations)
	}
	if out[0].Confirmations != 1 {
		t.Fatalf("want 1 confirmation, got %d", out[0].Confirmations)
	}
}

func TestRotateScan_QuorumClampedToPool(t *testing.T) {
	dial, _ := mockDialer(nil) // all open
	out := RotateScan(context.Background(), dial, mkPool(2),
		RotateConfig{Target: "t", Ports: []int{80}, Quorum: 5, DialConcurrency: 4}, RotateHooks{})
	if out[0].Quorum != 2 {
		t.Fatalf("want quorum clamped to 2, got %d", out[0].Quorum)
	}
	if out[0].Verdict != QuorumOpen {
		t.Fatalf("want QuorumOpen, got %v", out[0].Verdict)
	}
}

func TestRotateScan_BannerCaptured(t *testing.T) {
	dial, _ := mockDialer(map[string]behavior{
		addr(0): {kind: voteOpen, banner: "SSH-2.0-OpenSSH_9.6\r\n"},
	})
	out := RotateScan(context.Background(), dial, mkPool(1),
		RotateConfig{Target: "t", Ports: []int{22}, Quorum: 1, DialConcurrency: 1}, RotateHooks{})
	if !strings.Contains(out[0].Banner, "SSH-2.0-OpenSSH_9.6") {
		t.Fatalf("want SSH banner, got %q", out[0].Banner)
	}
}

func TestRotateScan_MultiPortProgress(t *testing.T) {
	dial, _ := mockDialer(nil)
	var maxDone, lastTotal int
	var mu sync.Mutex
	hooks := RotateHooks{OnPortDone: func(done, total int) {
		mu.Lock()
		if done > maxDone {
			maxDone = done
		}
		lastTotal = total
		mu.Unlock()
	}}
	ports := []int{22, 80, 443}
	out := RotateScan(context.Background(), dial, mkPool(3),
		RotateConfig{Target: "t", Ports: ports, Quorum: 1, DialConcurrency: 4}, hooks)
	if len(out) != 3 {
		t.Fatalf("want 3 outcomes, got %d", len(out))
	}
	if maxDone != 3 || lastTotal != 3 {
		t.Fatalf("progress want done=3 total=3, got done=%d total=%d", maxDone, lastTotal)
	}
	for i, p := range ports {
		if out[i].Port != p {
			t.Fatalf("outcome %d: want port %d, got %d", i, p, out[i].Port)
		}
	}
}

func TestRotateScan_CancelledContextDoesNotDial(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	dial, h := mockDialer(nil)
	out := RotateScan(ctx, dial, mkPool(3),
		RotateConfig{Target: "t", Ports: []int{80, 443}, Quorum: 2, DialConcurrency: 4}, RotateHooks{})
	if got := dialCounts(h); len(got) != 0 {
		t.Fatalf("cancelled scan should not dial, got %v", got)
	}
	for _, oc := range out {
		if oc.Verdict != QuorumUnreachable {
			t.Fatalf("cancelled port want Unreachable, got %v", oc.Verdict)
		}
	}
}

func TestRotateScan_EmptyInputs(t *testing.T) {
	dial, _ := mockDialer(nil)
	if out := RotateScan(context.Background(), dial, nil,
		RotateConfig{Target: "t", Ports: []int{80}, Quorum: 1, DialConcurrency: 1}, RotateHooks{}); out != nil {
		t.Fatalf("empty pool should return nil, got %v", out)
	}
	if out := RotateScan(context.Background(), dial, mkPool(2),
		RotateConfig{Target: "t", Ports: nil, Quorum: 1, DialConcurrency: 1}, RotateHooks{}); out != nil {
		t.Fatalf("empty ports should return nil, got %v", out)
	}
}

func TestRotateScan_LabelHook(t *testing.T) {
	dial, _ := mockDialer(nil)
	hooks := RotateHooks{Label: func(p *proxy.Proxy) string { return "LBL:" + p.Address() }}
	out := RotateScan(context.Background(), dial, mkPool(1),
		RotateConfig{Target: "t", Ports: []int{80}, Quorum: 1, DialConcurrency: 1}, hooks)
	if len(out[0].OpenLabels) != 1 || !strings.HasPrefix(out[0].OpenLabels[0], "LBL:") {
		t.Fatalf("want custom label, got %v", out[0].OpenLabels)
	}
}
