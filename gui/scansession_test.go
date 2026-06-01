package gui

import (
	"reflect"
	"strings"
	"testing"

	"rofk/scanner"
)

func TestBuildTargetList(t *testing.T) {
	const ph = "Optional: one target per line"
	cases := []struct {
		name   string
		single string
		queue  string
		want   []string
	}{
		{"single only", "1.2.3.4", "", []string{"1.2.3.4"}},
		{"queue only", "", "a\nb\nc", []string{"a", "b", "c"}},
		{"single first then queue", "x", "a\nb", []string{"x", "a", "b"}},
		{"dedup single present in queue", "a", "a\nb", []string{"a", "b"}},
		{"blank lines and whitespace trimmed", "  ", " a \n\n b \n", []string{"a", "b"}},
		{"placeholder queue ignored", "x", ph, []string{"x"}},
		{"dedup within queue", "", "a\na\nb\na", []string{"a", "b"}},
		{"empty everything", "", "", nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := buildTargetList(c.single, c.queue, ph)
			if !reflect.DeepEqual(got, c.want) {
				t.Fatalf("buildTargetList(%q,%q) = %v, want %v", c.single, c.queue, got, c.want)
			}
		})
	}
}

func TestQuorumForMode(t *testing.T) {
	cases := map[string]int{
		"Fast (1 proxy)":        1,
		"Confirmed (2 proxies)": 2,
		"Paranoid (3 proxies)":  3,
		"":                      1,
		"nonsense":              1,
	}
	for mode, want := range cases {
		if got := quorumForMode(mode); got != want {
			t.Errorf("quorumForMode(%q) = %d, want %d", mode, got, want)
		}
	}
}

func TestQuietScan(t *testing.T) {
	cases := []struct {
		name    string
		targets []string
		want    bool
	}{
		{"single host", []string{"1.2.3.4"}, false},
		{"single hostname", []string{"example.com"}, false},
		{"multi target", []string{"a", "b"}, true},
		{"single cidr", []string{"10.0.0.0/24"}, true},
		{"cidr among many", []string{"a", "10.0.0.0/24"}, true},
		{"empty", nil, false},
	}
	for _, c := range cases {
		if got := quietScan(c.targets); got != c.want {
			t.Errorf("%s: quietScan(%v) = %v, want %v", c.name, c.targets, got, c.want)
		}
	}
}

func TestRenderSummary_NoOpen(t *testing.T) {
	out := strings.Join(renderSummary([]hostScan{{host: "h", findings: nil}}), "\n")
	if !strings.Contains(out, "(no open ports found)") {
		t.Fatalf("want no-open message, got:\n%s", out)
	}
}

func TestRenderSummary_SingleHost(t *testing.T) {
	results := []hostScan{{
		host: "1.2.3.4",
		findings: []Finding{
			{Host: "1.2.3.4", Port: 22, Proto: "tcp", Service: "ssh", Version: "OpenSSH_9.6", Proxies: []string{"pa", "pb"}},
		},
	}}
	out := strings.Join(renderSummary(results), "\n")
	// Single host: no "HOST:" header.
	if strings.Contains(out, "HOST:") {
		t.Fatalf("single-host summary should not have HOST header:\n%s", out)
	}
	if !strings.Contains(out, "► OPEN") || !strings.Contains(out, "22/tcp   open  ssh  OpenSSH_9.6") {
		t.Fatalf("open line missing/wrong:\n%s", out)
	}
	if !strings.Contains(out, "├─ via pa") || !strings.Contains(out, "└─ via pb") {
		t.Fatalf("proxy tree missing:\n%s", out)
	}
}

func TestRenderSummary_MultiHostWithHeadersAndEmpty(t *testing.T) {
	results := []hostScan{
		{host: "a", findings: []Finding{{Host: "a", Port: 80, Proto: "tcp", Service: "http", ProxyURI: "p1"}}},
		{host: "b", findings: nil},
	}
	out := renderSummary(results)
	joined := strings.Join(out, "\n")
	if !strings.Contains(joined, "HOST: a") || !strings.Contains(joined, "HOST: b") {
		t.Fatalf("multi-host headers missing:\n%s", joined)
	}
	if !strings.Contains(joined, "└─ via p1") {
		t.Fatalf("single-proxy fallback line missing:\n%s", joined)
	}
	if !strings.Contains(joined, "(no open ports)") {
		t.Fatalf("empty host should note no open ports:\n%s", joined)
	}
}

func TestScanFindingToGui(t *testing.T) {
	sf := scanner.ScanFinding{
		Host: "h", Port: 8080, Proto: "tcp", Service: "http-proxy",
		Version: "v1", Banner: "b", Primary: "px", Proxies: []string{"px", "py"},
	}
	g := scanFindingToGui(sf)
	if g.Host != "h" || g.Port != 8080 || g.Service != "http-proxy" || g.Version != "v1" ||
		g.Banner != "b" || g.ProxyURI != "px" || len(g.Proxies) != 2 {
		t.Fatalf("scanFindingToGui mismatch: %+v", g)
	}
}
