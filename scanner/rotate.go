package scanner

import (
	"context"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"rofk/proxy"
)

// DialFunc opens a TCP tunnel to host:port through proxy p, honouring ctx.
// On success it returns a ready connection the caller must Close; on failure it
// returns an error that proxy.IsProxyError can classify as proxy-side vs
// target-side. Injecting this makes RotateScan deterministic and unit-testable.
type DialFunc func(ctx context.Context, p *proxy.Proxy, host string, port int, timeout time.Duration) (net.Conn, error)

// RotateConfig parameterises a quorum rotate-scan of one target across a pool.
type RotateConfig struct {
	Target          string         // host or IP being scanned
	Ports           []int          // ports to probe (one verdict each)
	Quorum          int            // proxies that must agree "open" (clamped to pool size, min 1)
	DialConcurrency int            // max simultaneous dials across all ports (min 1)
	Timeout         time.Duration  // per-dial timeout
	MaxProxyRetries int            // per-port cap on proxy-side failures before giving up (0 => 10)
	Throttle        *ProxyThrottle // optional burn protection; nil => no pacing
}

// PortOutcome is the decided result for a single port.
type PortOutcome struct {
	Port          int
	Verdict       QuorumVerdict
	Confirmations int      // proxies that voted open
	Quorum        int      // quorum actually required (post-clamp)
	OpenLabels    []string // labels of every proxy that voted open, in probe order
	Banner        string   // first non-empty banner seen on an open vote
	Service       string   // identified service (first open vote that learned one)
	Version       string   // identified version/detail (may be empty)
	RefutedBy     string   // proxy address that voted refused (set when refuted)
}

// RotateHooks lets a caller observe progress without coupling RotateScan to any
// UI. All hooks are optional and may be called from multiple goroutines, so
// implementations must be safe for concurrent use.
type RotateHooks struct {
	// Label renders a proxy's display string for OpenLabels. nil => p.URI().
	Label func(p *proxy.Proxy) string
	// OnProxyDead fires once, the first time a proxy is classified proxy-side
	// dead during this scan. Callers typically prune it from the pool.
	OnProxyDead func(p *proxy.Proxy)
	// OnPortDone fires as each port finishes (done out of total).
	OnPortDone func(done, total int)
	// OnOutcome fires with each port's decided verdict (for live logging).
	OnOutcome func(PortOutcome)
}

func (h RotateHooks) label(p *proxy.Proxy) string {
	if h.Label != nil {
		return h.Label(p)
	}
	return p.URI()
}

// RotateScan probes every port in cfg.Ports across the proxy pool, requiring
// cfg.Quorum independent proxies to agree a port is open before reporting it.
// Each port is probed in parallel batches of (still-needed + 2) proxies so a
// quorum is reached in roughly one round-trip instead of N sequential dials.
//
// A proxy classified as proxy-side dead (see proxy.IsProxyError) is marked
// failed once, skipped by every other port for the rest of the scan, and
// reported via hooks.OnProxyDead. Target-side "refused" votes refute a port.
//
// RotateScan does not shuffle the pool; pass it in the desired probe order. It
// is pure of any UI dependency and deterministic given a deterministic DialFunc.
func RotateScan(ctx context.Context, dial DialFunc, pool []*proxy.Proxy, cfg RotateConfig, hooks RotateHooks) []PortOutcome {
	poolSize := len(pool)
	if poolSize == 0 || len(cfg.Ports) == 0 {
		return nil
	}

	quorum := cfg.Quorum
	if quorum < 1 {
		quorum = 1
	}
	if quorum > poolSize {
		quorum = poolSize
	}
	maxProxyRetries := cfg.MaxProxyRetries
	if maxProxyRetries <= 0 {
		maxProxyRetries = 10
	}
	if maxProxyRetries > poolSize {
		maxProxyRetries = poolSize
	}
	dialConc := cfg.DialConcurrency
	if dialConc < 1 {
		dialConc = 1
	}

	// Shared across ports: a dial-concurrency cap and a dead-proxy set so a
	// proxy that fails once is skipped by every remaining port.
	dialSem := make(chan struct{}, dialConc)
	var failedMu sync.Mutex
	failedSet := make(map[string]bool)
	markFailed := func(p *proxy.Proxy) {
		addr := p.Address()
		failedMu.Lock()
		newlyDead := !failedSet[addr]
		failedSet[addr] = true
		failedMu.Unlock()
		if newlyDead && hooks.OnProxyDead != nil {
			hooks.OnProxyDead(p)
		}
	}
	isFailed := func(p *proxy.Proxy) bool {
		failedMu.Lock()
		defer failedMu.Unlock()
		return failedSet[p.Address()]
	}

	outcomes := make([]PortOutcome, len(cfg.Ports))
	var done atomic.Int64
	total := len(cfg.Ports)

	var wg sync.WaitGroup
	for i, port := range cfg.Ports {
		wg.Add(1)
		go func(i, port int) {
			defer wg.Done()
			defer func() {
				if hooks.OnPortDone != nil {
					hooks.OnPortDone(int(done.Add(1)), total)
				}
			}()

			oc := scanPort(ctx, dial, pool, port, quorum, maxProxyRetries, dialConc,
				i%poolSize, cfg.Target, cfg.Timeout, cfg.Throttle, dialSem, markFailed, isFailed, hooks)
			outcomes[i] = oc
			if hooks.OnOutcome != nil {
				hooks.OnOutcome(oc)
			}
		}(i, port)
	}
	wg.Wait()
	return outcomes
}

// scanPort probes a single port across the pool until the quorum is met,
// refuted, or proxies are exhausted, then returns the decided outcome.
func scanPort(ctx context.Context, dial DialFunc, pool []*proxy.Proxy, port, quorum,
	maxProxyRetries, _ int, startIdx int, target string, timeout time.Duration,
	throttle *ProxyThrottle, dialSem chan struct{},
	markFailed func(*proxy.Proxy), isFailed func(*proxy.Proxy) bool, hooks RotateHooks) PortOutcome {

	poolSize := len(pool)
	confirmations := 0
	proxyErrors := 0
	refuted := false
	refutedBy := ""
	var openLabels []string
	openBanner := ""
	openService := ""
	openVersion := ""
	consumed := 0

	for confirmations < quorum && !refuted && proxyErrors < maxProxyRetries && consumed < poolSize {
		if ctx.Err() != nil {
			break
		}
		need := quorum - confirmations
		batchN := need + 2
		var batch []*proxy.Proxy
		for len(batch) < batchN && consumed < poolSize {
			p := pool[(startIdx+consumed)%poolSize]
			consumed++
			if isFailed(p) {
				continue
			}
			if !throttle.Ready(p.Address()) {
				continue
			}
			batch = append(batch, p)
		}
		if len(batch) == 0 {
			break
		}

		type voteResult struct {
			vote    int // 1 open, -1 refused, 0 proxy-error
			banner  string
			service string
			version string
			label   string
			addr    string
		}
		results := make([]voteResult, len(batch))
		var bwg sync.WaitGroup
		for bi, p := range batch {
			bwg.Add(1)
			go func(bi int, p *proxy.Proxy) {
				defer bwg.Done()
				dialSem <- struct{}{}
				defer func() { <-dialSem }()
				if ctx.Err() != nil {
					return
				}
				conn, err := dial(ctx, p, target, port, timeout)
				if ctx.Err() != nil {
					if conn != nil {
						conn.Close()
					}
					return
				}
				if err != nil {
					if proxy.IsProxyError(p.Address(), err) {
						markFailed(p)
						results[bi] = voteResult{vote: 0, addr: p.Address()}
					} else {
						results[bi] = voteResult{vote: -1, addr: p.Address()}
					}
					return
				}
				svc, ver, banner := IdentifyService(conn, target, port, timeout)
				conn.Close()
				results[bi] = voteResult{vote: 1, banner: banner, service: svc, version: ver, label: hooks.label(p), addr: p.Address()}
			}(bi, p)
		}
		bwg.Wait()
		if ctx.Err() != nil {
			break
		}

		for _, r := range results {
			switch r.vote {
			case 1:
				confirmations++
				openLabels = append(openLabels, r.label)
				if openBanner == "" {
					openBanner = r.banner
				}
				if openService == "" {
					openService = r.service
				}
				if openVersion == "" {
					openVersion = r.version
				}
			case -1:
				refuted = true
				refutedBy = r.addr
			case 0:
				proxyErrors++
			}
		}
	}

	return PortOutcome{
		Port:          port,
		Verdict:       DecideQuorum(confirmations, quorum, refuted),
		Confirmations: confirmations,
		Quorum:        quorum,
		OpenLabels:    openLabels,
		Banner:        openBanner,
		Service:       openService,
		Version:       openVersion,
		RefutedBy:     refutedBy,
	}
}
