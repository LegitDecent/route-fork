package scanner

import (
	"context"
	"sort"
	"sync"
	"time"

	"rofk/proxy"
)

// CountryProbe tallies how proxies from one country saw a target port.
type CountryProbe struct {
	Country string // ISO 3166-1 alpha-2 (or "" / "??" for unknown egress)
	Open    int    // proxies that connected to the port
	Refused int    // proxies that reached the target but were refused/filtered
	Errored int    // proxy-side failures (inconclusive, see proxy.IsProxyError)
}

// Total returns the number of proxies actually probed for this country.
func (c CountryProbe) Total() int { return c.Open + c.Refused + c.Errored }

// RegionStatus is one country's conclusion about a port.
type RegionStatus int

const (
	// RegionStatusInconclusive means no proxy from this country produced a
	// target-side result (only proxy errors, or no proxies tried).
	RegionStatusInconclusive RegionStatus = iota
	// RegionStatusOpen means at least one proxy reached the open port.
	RegionStatusOpen
	// RegionStatusBlocked means proxies reached the target but were all
	// refused/filtered - and none from this country saw it open.
	RegionStatusBlocked
)

// Status classifies a country: an open vote anywhere wins; otherwise a refusal
// means blocked; only proxy errors are inconclusive.
func (c CountryProbe) Status() RegionStatus {
	switch {
	case c.Open > 0:
		return RegionStatusOpen
	case c.Refused > 0:
		return RegionStatusBlocked
	default:
		return RegionStatusInconclusive
	}
}

// RegionVerdict is the overall conclusion of a region-block check.
type RegionVerdict int

const (
	// RegionInconclusive means there isn't enough contrast to conclude anything
	// (port open nowhere, or refused everywhere == just closed, not geo-blocked).
	RegionInconclusive RegionVerdict = iota
	// RegionOpenEverywhere means every country that produced a result saw the
	// port open - no evidence of geo-blocking.
	RegionOpenEverywhere
	// RegionBlockedSomewhere means the port is open from some countries but
	// refused from others - the signature of geo-blocking.
	RegionBlockedSomewhere
)

// RegionReport is the decided outcome of a region-block check.
type RegionReport struct {
	Verdict   RegionVerdict
	Probes    []CountryProbe // per-country tallies, as supplied
	OpenIn    []string       // countries where the port is open (sorted)
	BlockedIn []string       // countries where it appears blocked (sorted)
}

// DecideRegionBlock reduces per-country probes to a single verdict. Geo-blocking
// is inferred only from contrast: open from at least one country AND refused
// from at least one other. Refused-everywhere is treated as a plain closed port
// (inconclusive), since without a country that can reach it there's no evidence
// the refusal is geographic rather than the port simply being closed.
func DecideRegionBlock(probes []CountryProbe) RegionReport {
	var openIn, blockedIn []string
	for _, p := range probes {
		switch p.Status() {
		case RegionStatusOpen:
			openIn = append(openIn, p.Country)
		case RegionStatusBlocked:
			blockedIn = append(blockedIn, p.Country)
		}
	}
	sort.Strings(openIn)
	sort.Strings(blockedIn)

	verdict := RegionInconclusive
	switch {
	case len(openIn) > 0 && len(blockedIn) > 0:
		verdict = RegionBlockedSomewhere
	case len(openIn) > 0:
		verdict = RegionOpenEverywhere
	}
	return RegionReport{Verdict: verdict, Probes: probes, OpenIn: openIn, BlockedIn: blockedIn}
}

// ProbeRegion dials target:port through up to perCountry proxies from each
// country bucket and tallies the votes per country. It shares one dial-
// concurrency cap across all countries and is pure of any UI dependency.
func ProbeRegion(ctx context.Context, dial DialFunc, byCountry map[string][]*proxy.Proxy,
	target string, port int, timeout time.Duration, perCountry, dialConc int) []CountryProbe {

	if dialConc < 1 {
		dialConc = 1
	}
	if perCountry < 1 {
		perCountry = 1
	}

	countries := make([]string, 0, len(byCountry))
	for c := range byCountry {
		countries = append(countries, c)
	}
	sort.Strings(countries)

	type job struct {
		ci int
		p  *proxy.Proxy
	}
	var jobs []job
	for ci, c := range countries {
		ps := byCountry[c]
		if len(ps) > perCountry {
			ps = ps[:perCountry]
		}
		for _, p := range ps {
			jobs = append(jobs, job{ci: ci, p: p})
		}
	}

	votes := make([]int, len(jobs)) // 1 open, -1 refused, 0 proxy-error/cancelled
	sem := make(chan struct{}, dialConc)
	var wg sync.WaitGroup
	for ji := range jobs {
		wg.Add(1)
		go func(ji int) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			if ctx.Err() != nil {
				return
			}
			p := jobs[ji].p
			conn, err := dial(ctx, p, target, port, timeout)
			if ctx.Err() != nil {
				if conn != nil {
					conn.Close()
				}
				return
			}
			if err != nil {
				if !proxy.IsProxyError(p.Address(), err) {
					votes[ji] = -1
				}
				return
			}
			conn.Close()
			votes[ji] = 1
		}(ji)
	}
	wg.Wait()

	probes := make([]CountryProbe, len(countries))
	for ci := range countries {
		probes[ci].Country = countries[ci]
	}
	for ji, j := range jobs {
		switch votes[ji] {
		case 1:
			probes[j.ci].Open++
		case -1:
			probes[j.ci].Refused++
		default:
			probes[j.ci].Errored++
		}
	}
	return probes
}
