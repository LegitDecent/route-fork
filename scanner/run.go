package scanner

import (
	"context"
	"fmt"
	"time"

	"rofk/proxy"
)

// ScanFinding is one discovered open port from a built-in (Go-native) scan.
type ScanFinding struct {
	Host    string   // target host/IP the port was found on
	Port    int      // open port
	Proto   string   // "tcp"
	Service string   // identified service (probe, falling back to port name)
	Version string   // identified version/detail (may be empty)
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
// target is expanded (a CIDR becomes its host list) and every host:port is
// probed across the pool with the same quorum, so the scan mode applies whether
// the target is a single host or a range.
type ScanRequest struct {
	Targets     []string
	Ports       []int
	Quorum      int
	Concurrency int
	Timeout     time.Duration
	Throttle    *ProxyThrottle            // optional burn protection
	Label       func(*proxy.Proxy) string // proxy display label; nil => p.URI()
	Shuffle     func([]*proxy.Proxy)      // optional pool reordering per target; nil => keep order
}

// ScanHooks observe a running scan without coupling RunScan to any UI. All hooks
// are optional and may be called from multiple goroutines, so implementations
// must be safe for concurrent use. They are for live feedback only - the decided
// results are returned from RunScan.
type ScanHooks struct {
	Log       func(string)          // orchestration messages
	Progress  func(done, total int) // host:port progress within a target
	Outcome   func(PortOutcome)     // each host:port verdict (for live logging)
	ProxyDead func(p *proxy.Proxy)  // proxy classified dead mid-scan
}

func (h ScanHooks) log(s string) {
	if h.Log != nil {
		h.Log(s)
	}
}

// RunScan executes a built-in scan of every target across the pool snapshot
// returned by getPool (re-read per target so mid-scan pruning takes effect on
// later targets). It owns target iteration; per-host:port quorum probing is done
// by RotateScan through the injected dialer, making the whole path unit-testable.
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

// scanTarget expands a target (CIDR -> host list) and probes every host:port
// across the pool with the configured quorum. The quorum applies uniformly to
// single hosts and ranges alike.
func scanTarget(ctx context.Context, dial DialFunc, pool []*proxy.Proxy, target string, req ScanRequest, hooks ScanHooks) []ScanFinding {
	hosts, err := ExpandTarget(target)
	if err != nil {
		hooks.log("[-] target error: " + err.Error() + "\n")
		return nil
	}

	ordered := make([]*proxy.Proxy, len(pool))
	copy(ordered, pool)
	if req.Shuffle != nil {
		req.Shuffle(ordered)
	}

	quorum := req.Quorum
	if quorum < 1 {
		quorum = 1
	}
	if quorum > len(pool) {
		quorum = len(pool)
	}

	if len(hosts) > 1 {
		hooks.log(fmt.Sprintf("[*] TCP scan  %s  %d hosts x %d ports / %d proxies  (need %d to agree open)\n",
			target, len(hosts), len(req.Ports), len(pool), quorum))
	} else {
		hooks.log(fmt.Sprintf("[*] TCP scan  %s  %d port(s) / %d proxies  (need %d to agree open)\n",
			target, len(req.Ports), len(pool), quorum))
	}
	if req.Throttle != nil {
		hooks.log("[*] Burn protection on\n")
	}

	outcomes := RotateScan(ctx, dial, ordered, RotateConfig{
		Hosts:           hosts,
		Ports:           req.Ports,
		Quorum:          quorum,
		DialConcurrency: req.Concurrency,
		Timeout:         req.Timeout,
		Throttle:        req.Throttle,
	}, RotateHooks{
		Label:       req.Label,
		OnProxyDead: hooks.ProxyDead,
		OnPortDone:  hooks.Progress,
		OnOutcome:   hooks.Outcome,
	})

	var findings []ScanFinding
	for _, oc := range outcomes {
		if oc.Verdict != QuorumOpen {
			continue
		}
		svc := oc.Service
		if svc == "" {
			svc = PortService(oc.Port)
		}
		if svc == "" {
			svc = "unknown"
		}
		primary := ""
		if len(oc.OpenLabels) > 0 {
			primary = oc.OpenLabels[0]
		}
		findings = append(findings, ScanFinding{
			Host: oc.Host, Port: oc.Port, Proto: "tcp", Service: svc, Version: oc.Version,
			Banner: oc.Banner, Primary: primary, Proxies: oc.OpenLabels,
		})
	}
	return findings
}
