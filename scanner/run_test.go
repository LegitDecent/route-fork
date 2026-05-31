package scanner

import (
	"context"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"rofk/proxy"
)

func staticPool(pool []*proxy.Proxy) func() []*proxy.Proxy {
	return func() []*proxy.Proxy { return pool }
}

func countFindings(results []HostResult) int {
	n := 0
	for _, hr := range results {
		n += len(hr.Findings)
	}
	return n
}

func TestRunScan_SingleHostQuorumPath(t *testing.T) {
	dial, _ := mockDialer(nil) // all open
	results := RunScan(context.Background(), dial, staticPool(mkPool(3)),
		ScanRequest{Targets: []string{"host"}, Ports: []int{80, 443}, Quorum: 2, Concurrency: 4}, ScanHooks{})
	if len(results) != 1 {
		t.Fatalf("want 1 host result, got %d", len(results))
	}
	if got := countFindings(results); got != 2 {
		t.Fatalf("want 2 findings, got %d", got)
	}
	for _, f := range results[0].Findings {
		if len(f.Proxies) < 2 {
			t.Fatalf("quorum finding should record >=2 proxies, got %v", f.Proxies)
		}
	}
}

func TestRunScan_CarriesServiceVersion(t *testing.T) {
	dial, _ := mockDialer(map[string]behavior{
		addr(0): {kind: voteOpen, banner: "SSH-2.0-OpenSSH_9.6\r\n"},
		addr(1): {kind: voteOpen, banner: "SSH-2.0-OpenSSH_9.6\r\n"},
	})
	results := RunScan(context.Background(), dial, staticPool(mkPool(2)),
		ScanRequest{Targets: []string{"host"}, Ports: []int{22}, Quorum: 2, Concurrency: 4}, ScanHooks{})
	if countFindings(results) != 1 {
		t.Fatalf("want 1 finding, got %d", countFindings(results))
	}
	f := results[0].Findings[0]
	if f.Service != "ssh" || f.Version == "" {
		t.Fatalf("want ssh + version, got service=%q version=%q", f.Service, f.Version)
	}
}

func TestRunScan_RefusedPortDropped(t *testing.T) {
	dial, _ := mockDialer(map[string]behavior{
		addr(0): {kind: voteRefused}, addr(1): {kind: voteRefused}, addr(2): {kind: voteRefused},
	})
	// One port, all proxies refuse => refuted => no finding.
	results := RunScan(context.Background(), dial, staticPool(mkPool(3)),
		ScanRequest{Targets: []string{"host"}, Ports: []int{80}, Quorum: 2, Concurrency: 4}, ScanHooks{})
	if got := countFindings(results); got != 0 {
		t.Fatalf("refused port should yield no finding, got %d", got)
	}
}

func TestRunScan_ManyPortsUsesFlatPath(t *testing.T) {
	dial, _ := mockDialer(nil) // all open
	var found int
	var mu sync.Mutex
	hooks := ScanHooks{Found: func(ScanFinding) { mu.Lock(); found++; mu.Unlock() }}
	// 3 ports > pool of 2 => flat path; Found hook only fires on the flat path.
	results := RunScan(context.Background(), dial, staticPool(mkPool(2)),
		ScanRequest{Targets: []string{"host"}, Ports: []int{80, 443, 8080}, Quorum: 1, Concurrency: 4}, hooks)
	if got := countFindings(results); got != 3 {
		t.Fatalf("want 3 flat findings, got %d", got)
	}
	mu.Lock()
	defer mu.Unlock()
	if found != 3 {
		t.Fatalf("Found hook should fire 3 times (flat path), got %d", found)
	}
}

func TestRunScan_CIDRExpandsToFlatPath(t *testing.T) {
	dial, _ := mockDialer(nil) // all open
	// /30 => 2 usable hosts (.1, .2); 1 port => 2 findings via flat path.
	results := RunScan(context.Background(), dial, staticPool(mkPool(3)),
		ScanRequest{Targets: []string{"192.168.1.0/30"}, Ports: []int{80}, Quorum: 2, Concurrency: 4}, ScanHooks{})
	if got := countFindings(results); got != 2 {
		t.Fatalf("CIDR /30 + 1 port should yield 2 findings, got %d", got)
	}
	hosts := map[string]bool{}
	for _, f := range results[0].Findings {
		hosts[f.Host] = true
	}
	if !hosts["192.168.1.1"] || !hosts["192.168.1.2"] {
		t.Fatalf("expected findings on .1 and .2, got %v", hosts)
	}
}

func TestRunScan_MultiTarget(t *testing.T) {
	dial, _ := mockDialer(nil)
	results := RunScan(context.Background(), dial, staticPool(mkPool(2)),
		ScanRequest{Targets: []string{"a", "b", "c"}, Ports: []int{80}, Quorum: 1, Concurrency: 4}, ScanHooks{})
	if len(results) != 3 {
		t.Fatalf("want 3 host results, got %d", len(results))
	}
	for i, want := range []string{"a", "b", "c"} {
		if results[i].Target != want {
			t.Fatalf("result %d target = %q, want %q", i, results[i].Target, want)
		}
	}
}

func TestRunScan_PrunesDeadProxyAcrossTargets(t *testing.T) {
	// p0 is a proxy-error; p1/p2 open. After target 1 marks p0 dead, the caller
	// prunes it, so target 2 must not dial p0 again.
	beh := map[string]behavior{addr(0): {kind: voteProxyErr}}
	dial, h := mockDialer(beh)

	var mu sync.Mutex
	pool := mkPool(3)
	getPool := func() []*proxy.Proxy {
		mu.Lock()
		defer mu.Unlock()
		out := make([]*proxy.Proxy, len(pool))
		copy(out, pool)
		return out
	}
	hooks := ScanHooks{ProxyDead: func(p *proxy.Proxy) {
		mu.Lock()
		defer mu.Unlock()
		kept := pool[:0]
		for _, x := range pool {
			if x.Address() != p.Address() {
				kept = append(kept, x)
			}
		}
		pool = kept
	}}

	RunScan(context.Background(), dial, getPool,
		ScanRequest{Targets: []string{"t1", "t2"}, Ports: []int{80}, Quorum: 2, Concurrency: 4}, hooks)

	if c := dialCounts(h)[addr(0)]; c != 1 {
		t.Fatalf("dead proxy should be dialled once (target 1 only), got %d", c)
	}
}

func TestRunScan_CancelledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	dial, hc := mockDialer(nil)
	results := RunScan(ctx, dial, staticPool(mkPool(3)),
		ScanRequest{Targets: []string{"a", "b"}, Ports: []int{80}, Quorum: 1, Concurrency: 4}, ScanHooks{})
	if countFindings(results) != 0 {
		t.Fatalf("cancelled scan should yield no findings")
	}
	if len(dialCounts(hc)) != 0 {
		t.Fatalf("cancelled scan should not dial")
	}
}

func TestRunScan_FlatPathBoundsConcurrency(t *testing.T) {
	// The flat (CIDR / many-port) path must never run more than Concurrency
	// dials at once, regardless of how many host:port pairs there are.
	const conc = 5
	var inFlight, maxSeen atomic.Int32
	dial := func(ctx context.Context, p *proxy.Proxy, host string, port int, to time.Duration) (net.Conn, error) {
		cur := inFlight.Add(1)
		for {
			m := maxSeen.Load()
			if cur <= m || maxSeen.CompareAndSwap(m, cur) {
				break
			}
		}
		time.Sleep(2 * time.Millisecond)
		inFlight.Add(-1)
		return nil, fmt.Errorf("connection refused") // closed; we only measure concurrency
	}
	// /28 => 14 hosts x 4 ports = 56 jobs, far more than conc.
	RunScan(context.Background(), dial, staticPool(mkPool(3)),
		ScanRequest{Targets: []string{"10.0.0.0/28"}, Ports: []int{80, 443, 22, 8080}, Quorum: 2, Concurrency: conc},
		ScanHooks{})
	if m := maxSeen.Load(); m > conc {
		t.Fatalf("max in-flight dials = %d, must not exceed Concurrency %d", m, conc)
	}
	if m := maxSeen.Load(); m < 2 {
		t.Fatalf("expected real parallelism, max in-flight was %d", m)
	}
}

func TestRunScan_EmptyPoolSkips(t *testing.T) {
	dial, _ := mockDialer(nil)
	results := RunScan(context.Background(), dial, staticPool(nil),
		ScanRequest{Targets: []string{"a"}, Ports: []int{80}, Quorum: 1, Concurrency: 1}, ScanHooks{})
	if len(results) != 0 {
		t.Fatalf("empty pool should produce no host results, got %d", len(results))
	}
}
