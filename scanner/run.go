package scanner

import (
	"context"
	"fmt"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"rofk/proxy"
)

// ScanFinding is one discovered open port from a built-in (Go-native) scan.
type ScanFinding struct {
	Host    string   // target host/IP the port was found on
	Port    int      // open port
	Proto   string   // "tcp"
	Service string   // best-effort service name (from PortService)
	Banner  string   // service banner grabbed at connect (may be empty)
	Primary string   // primary proxy label that found it
	Proxies []string // every proxy label that agreed it is open
}

// HostResult groups the open-port findings for one target.
type HostResult struct {
	Target   string
	Findings []ScanFinding
}

// ScanRequest configures a built-in rotate scan over one or more targets. Each
// target is scanned across the whole pool: single hosts with few ports use the
// quorum path (RotateScan); CIDRs and many-port specs use a flat connect sweep.
type ScanRequest struct {
	Targets     []string
	Ports       []int
	Quorum      int
	Concurrency int
	Timeout     time.Duration
	Throttle    *ProxyThrottle            // optional burn protection (quorum path)
	Label       func(*proxy.Proxy) string // proxy display label; nil => p.URI()
	Shuffle     func([]*proxy.Proxy)      // optional pool reordering per target; nil => keep order
}

// ScanHooks observe a running scan without coupling RunScan to any UI. All hooks
// are optional and may be called from multiple goroutines, so implementations
// must be safe for concurrent use. They are for live feedback only - the decided
// results are returned from RunScan.
type ScanHooks struct {
	Log       func(string)                        // orchestration messages
	Progress  func(done, total int)               // per-target port/job progress
	Outcome   func(target string, oc PortOutcome) // per-port verdict (quorum path)
	Found     func(ScanFinding)                   // each open port (flat path)
	ProxyDead func(p *proxy.Proxy)                // proxy classified dead mid-scan
}

func (h ScanHooks) log(s string) {
	if h.Log != nil {
		h.Log(s)
	}
}

func (r ScanRequest) label(p *proxy.Proxy) string {
	if r.Label != nil {
		return r.Label(p)
	}
	return p.URI()
}

// RunScan executes a built-in scan of every target across the pool snapshot
// returned by getPool (re-read per target so mid-scan pruning takes effect on
// later targets). It owns target iteration and per-target routing; the leaf
// dialing is done through dial, making the whole path unit-testable with a mock.
func RunScan(ctx context.Context, dial DialFunc, getPool func() []*proxy.Proxy, req ScanRequest, hooks ScanHooks) []HostResult {
	var results []HostResult
	for _, target := range req.Targets {
		if ctx.Err() != nil {
			hooks.log("[!] Scan stopped\n")
			break
		}
		pool := getPool()
		if len(pool) == 0 {
			hooks.log("[-] No proxies in pool\n")
			continue
		}
		findings := scanTarget(ctx, dial, pool, target, req, hooks)
		results = append(results, HostResult{Target: target, Findings: findings})
	}
	return results
}

// scanTarget routes one target to the quorum path (single host, few ports) or
// the flat connect sweep (CIDR or many ports).
func scanTarget(ctx context.Context, dial DialFunc, pool []*proxy.Proxy, target string, req ScanRequest, hooks ScanHooks) []ScanFinding {
	n := len(pool)
	isCIDR := strings.Contains(target, "/")

	if !isCIDR && len(req.Ports) <= n {
		return quorumTarget(ctx, dial, pool, target, req, hooks)
	}

	hosts, err := ExpandTarget(target)
	if err != nil {
		hooks.log("[-] target error: " + err.Error() + "\n")
		return nil
	}
	if isCIDR {
		hooks.log(fmt.Sprintf("[*] TCP CIDR sweep  %s  %d hosts x %d ports  via %d proxies (rotating per connection)\n",
			target, len(hosts), len(req.Ports), n))
	} else {
		hooks.log(fmt.Sprintf("[*] TCP sweep  %s  %d ports  via %d proxies (rotating per connection)\n",
			target, len(req.Ports), n))
	}
	return flatScan(ctx, dial, pool, hosts, target, req, hooks)
}

// quorumTarget probes each port of a single host across the pool, requiring a
// quorum of proxies to agree before reporting open. Dead proxies are reported
// via hooks.ProxyDead so the caller can prune them.
func quorumTarget(ctx context.Context, dial DialFunc, pool []*proxy.Proxy, target string, req ScanRequest, hooks ScanHooks) []ScanFinding {
	n := len(pool)
	ordered := make([]*proxy.Proxy, len(pool))
	copy(ordered, pool)
	if req.Shuffle != nil {
		req.Shuffle(ordered)
	}

	quorum := req.Quorum
	if quorum < 1 {
		quorum = 1
	}
	if quorum > n {
		quorum = n
	}
	hooks.log(fmt.Sprintf("[*] TCP rotate  %s  %d port(s) / %d proxies  1 port each  (need %d to agree open)  [parallel]\n",
		target, len(req.Ports), n, quorum))
	if req.Throttle != nil {
		hooks.log("[*] Burn protection on\n")
	}

	var mu sync.Mutex
	var findings []ScanFinding
	outcomes := RotateScan(ctx, dial, ordered, RotateConfig{
		Target:          target,
		Ports:           req.Ports,
		Quorum:          quorum,
		DialConcurrency: req.Concurrency,
		Timeout:         req.Timeout,
		Throttle:        req.Throttle,
	}, RotateHooks{
		Label:       req.Label,
		OnProxyDead: hooks.ProxyDead,
		OnPortDone:  hooks.Progress,
		OnOutcome: func(oc PortOutcome) {
			if hooks.Outcome != nil {
				hooks.Outcome(target, oc)
			}
		},
	})

	for _, oc := range outcomes {
		if oc.Verdict != QuorumOpen {
			continue
		}
		svc := PortService(oc.Port)
		if svc == "" {
			svc = "unknown"
		}
		primary := ""
		if len(oc.OpenLabels) > 0 {
			primary = oc.OpenLabels[0]
		}
		mu.Lock()
		findings = append(findings, ScanFinding{
			Host: target, Port: oc.Port, Proto: "tcp", Service: svc,
			Banner: oc.Banner, Primary: primary, Proxies: oc.OpenLabels,
		})
		mu.Unlock()
	}
	return findings
}

// flatScan dials every host:port once through a rotating proxy and reports the
// opens. It mirrors the historical chunk/CIDR behaviour: best-effort, quorum of
// one, no dead-proxy pruning.
func flatScan(ctx context.Context, dial DialFunc, pool []*proxy.Proxy, hosts []string, target string, req ScanRequest, hooks ScanHooks) []ScanFinding {
	total := len(hosts) * len(req.Ports)
	conc := req.Concurrency
	if conc < 1 {
		conc = 1
	}
	sem := make(chan struct{}, conc)
	var doneN atomic.Int64
	var idx atomic.Int64
	var mu sync.Mutex
	var findings []ScanFinding
	var wg sync.WaitGroup

	scanOne := func(host string, port int) {
		defer wg.Done()
		defer func() { <-sem }()
		defer func() {
			if hooks.Progress != nil {
				hooks.Progress(int(doneN.Add(1)), total)
			}
		}()
		if ctx.Err() != nil {
			return
		}
		p := pool[int(idx.Add(1)-1)%len(pool)]
		conn, err := dial(ctx, p, host, port, req.Timeout)
		if ctx.Err() != nil {
			if conn != nil {
				conn.Close()
			}
			return
		}
		if err != nil {
			return // closed/filtered/proxy-error: not an open port
		}
		banner := grabBanner(conn)
		conn.Close()
		svc := PortService(port)
		if svc == "" {
			svc = "unknown"
		}
		label := req.label(p)
		f := ScanFinding{Host: host, Port: port, Proto: "tcp", Service: svc,
			Banner: banner, Primary: label, Proxies: []string{label}}
		mu.Lock()
		findings = append(findings, f)
		mu.Unlock()
		if hooks.Found != nil {
			hooks.Found(f)
		}
	}

	// Acquire the concurrency slot BEFORE spawning, and stream host:port pairs
	// instead of materialising the full job list. A /16 x many ports otherwise
	// builds a multi-million-entry slice and spawns a parked goroutine for each;
	// this keeps at most `conc` goroutines and connections alive at once.
	for _, host := range hosts {
		for _, port := range req.Ports {
			if ctx.Err() != nil {
				wg.Wait()
				return findings
			}
			sem <- struct{}{}
			wg.Add(1)
			go scanOne(host, port)
		}
	}
	wg.Wait()
	return findings
}

// grabBanner reads a short service banner (services that speak first).
func grabBanner(conn net.Conn) string {
	_ = conn.SetReadDeadline(time.Now().Add(800 * time.Millisecond))
	buf := make([]byte, 256)
	n, _ := conn.Read(buf)
	if n > 0 {
		return CleanBanner(buf[:n])
	}
	return ""
}
