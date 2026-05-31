package scanner

import (
	"context"
	"reflect"
	"testing"

	"rofk/proxy"
)

func TestDecideRegionBlock(t *testing.T) {
	tests := []struct {
		name      string
		probes    []CountryProbe
		want      RegionVerdict
		openIn    []string
		blockedIn []string
	}{
		{
			name:      "open here blocked there",
			probes:    []CountryProbe{{Country: "US", Open: 2}, {Country: "CN", Refused: 2}},
			want:      RegionBlockedSomewhere,
			openIn:    []string{"US"},
			blockedIn: []string{"CN"},
		},
		{
			name:   "open everywhere",
			probes: []CountryProbe{{Country: "US", Open: 1}, {Country: "DE", Open: 2}},
			want:   RegionOpenEverywhere,
			openIn: []string{"DE", "US"},
		},
		{
			name:      "refused everywhere is just closed (inconclusive)",
			probes:    []CountryProbe{{Country: "US", Refused: 2}, {Country: "CN", Refused: 1}},
			want:      RegionInconclusive,
			blockedIn: []string{"CN", "US"},
		},
		{
			name:      "inconclusive country excluded from verdict",
			probes:    []CountryProbe{{Country: "US", Open: 1}, {Country: "CN", Refused: 1}, {Country: "RU", Errored: 3}},
			want:      RegionBlockedSomewhere,
			openIn:    []string{"US"},
			blockedIn: []string{"CN"},
		},
		{
			name:   "no signal at all",
			probes: []CountryProbe{{Country: "US", Errored: 2}},
			want:   RegionInconclusive,
		},
		{
			name:   "empty",
			probes: nil,
			want:   RegionInconclusive,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := DecideRegionBlock(tt.probes)
			if r.Verdict != tt.want {
				t.Errorf("verdict = %v, want %v", r.Verdict, tt.want)
			}
			if len(r.OpenIn) != 0 || len(tt.openIn) != 0 {
				if !reflect.DeepEqual(r.OpenIn, tt.openIn) {
					t.Errorf("OpenIn = %v, want %v", r.OpenIn, tt.openIn)
				}
			}
			if len(r.BlockedIn) != 0 || len(tt.blockedIn) != 0 {
				if !reflect.DeepEqual(r.BlockedIn, tt.blockedIn) {
					t.Errorf("BlockedIn = %v, want %v", r.BlockedIn, tt.blockedIn)
				}
			}
		})
	}
}

func TestCountryProbeStatus(t *testing.T) {
	if (CountryProbe{Open: 1, Refused: 5}).Status() != RegionStatusOpen {
		t.Error("any open => Open")
	}
	if (CountryProbe{Refused: 1}).Status() != RegionStatusBlocked {
		t.Error("refused, no open => Blocked")
	}
	if (CountryProbe{Errored: 3}).Status() != RegionStatusInconclusive {
		t.Error("only errors => Inconclusive")
	}
}

func TestProbeRegion(t *testing.T) {
	// US proxies open, CN proxies refused, RU proxies proxy-error.
	beh := map[string]behavior{}
	pool := func(cc string, n, kind int) []*proxy.Proxy {
		var ps []*proxy.Proxy
		for i := 0; i < n; i++ {
			p := &proxy.Proxy{Host: cc + "-" + string(rune('a'+i)), Port: 1080, Proto: "socks5", Country: cc}
			beh[p.Address()] = behavior{kind: kind}
			ps = append(ps, p)
		}
		return ps
	}
	byCountry := map[string][]*proxy.Proxy{
		"US": pool("US", 2, voteOpen),
		"CN": pool("CN", 2, voteRefused),
		"RU": pool("RU", 2, voteProxyErr),
	}
	dial, _ := mockDialer(beh)
	probes := ProbeRegion(context.Background(), dial, byCountry, "t", 443, 0, 3, 8)

	got := map[string]CountryProbe{}
	for _, p := range probes {
		got[p.Country] = p
	}
	if got["US"].Open != 2 || got["US"].Refused != 0 {
		t.Errorf("US probe = %+v, want Open:2", got["US"])
	}
	if got["CN"].Refused != 2 || got["CN"].Open != 0 {
		t.Errorf("CN probe = %+v, want Refused:2", got["CN"])
	}
	if got["RU"].Errored != 2 {
		t.Errorf("RU probe = %+v, want Errored:2", got["RU"])
	}

	r := DecideRegionBlock(probes)
	if r.Verdict != RegionBlockedSomewhere {
		t.Fatalf("verdict = %v, want RegionBlockedSomewhere", r.Verdict)
	}
}

func TestProbeRegionPerCountryCap(t *testing.T) {
	beh := map[string]behavior{}
	var ps []*proxy.Proxy
	for i := 0; i < 5; i++ {
		p := &proxy.Proxy{Host: "x" + string(rune('a'+i)), Port: 1080, Proto: "socks5", Country: "US"}
		beh[p.Address()] = behavior{kind: voteOpen}
		ps = append(ps, p)
	}
	dial, h := mockDialer(beh)
	probes := ProbeRegion(context.Background(), dial, map[string][]*proxy.Proxy{"US": ps}, "t", 80, 0, 2, 8)
	if probes[0].Total() != 2 {
		t.Fatalf("perCountry=2 should probe 2, got %d", probes[0].Total())
	}
	if n := len(dialCounts(h)); n != 2 {
		t.Fatalf("should have dialled 2 distinct proxies, got %d", n)
	}
}

func TestProbeRegionCancelled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	beh := map[string]behavior{}
	var ps []*proxy.Proxy
	for i := 0; i < 3; i++ {
		p := &proxy.Proxy{Host: "y" + string(rune('a'+i)), Port: 1080, Proto: "socks5", Country: "US"}
		beh[p.Address()] = behavior{kind: voteOpen}
		ps = append(ps, p)
	}
	dial, _ := mockDialer(beh)
	probes := ProbeRegion(ctx, dial, map[string][]*proxy.Proxy{"US": ps}, "t", 80, 0, 3, 8)
	if probes[0].Open != 0 {
		t.Fatalf("cancelled probe should see no opens, got %+v", probes[0])
	}
}
