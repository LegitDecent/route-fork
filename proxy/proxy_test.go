package proxy

import (
	"testing"
)

// ── ParseLine ─────────────────────────────────────────────────────────────────

func TestParseLineURI(t *testing.T) {
	cases := []struct {
		input string
		proto string
		host  string
		port  int
		user  string
		pass  string
	}{
		{"socks5://1.2.3.4:1080", "socks5", "1.2.3.4", 1080, "", ""},
		{"socks4://10.0.0.1:9050", "socks4", "10.0.0.1", 9050, "", ""},
		{"SOCKS5://host.example.com:8080", "socks5", "host.example.com", 8080, "", ""},
		{"socks5://user:pass@1.2.3.4:1080", "socks5", "1.2.3.4", 1080, "user", "pass"},
		{"socks5://u:p@host.com:443", "socks5", "host.com", 443, "u", "p"},
	}
	for _, tc := range cases {
		p := ParseLine(tc.input)
		if p == nil {
			t.Errorf("ParseLine(%q) = nil, want proxy", tc.input)
			continue
		}
		if p.Proto != tc.proto {
			t.Errorf("%q: proto = %q, want %q", tc.input, p.Proto, tc.proto)
		}
		if p.Host != tc.host {
			t.Errorf("%q: host = %q, want %q", tc.input, p.Host, tc.host)
		}
		if p.Port != tc.port {
			t.Errorf("%q: port = %d, want %d", tc.input, p.Port, tc.port)
		}
		if p.Username != tc.user {
			t.Errorf("%q: username = %q, want %q", tc.input, p.Username, tc.user)
		}
		if p.Password != tc.pass {
			t.Errorf("%q: password = %q, want %q", tc.input, p.Password, tc.pass)
		}
	}
}

func TestParseLineColonFormat(t *testing.T) {
	cases := []struct {
		input string
		host  string
		port  int
		user  string
		pass  string
	}{
		{"1.2.3.4:1080", "1.2.3.4", 1080, "", ""},
		{"host.example.com:9050", "host.example.com", 9050, "", ""},
		{"1.2.3.4:1080:myuser:mypass", "1.2.3.4", 1080, "myuser", "mypass"},
	}
	for _, tc := range cases {
		p := ParseLine(tc.input)
		if p == nil {
			t.Errorf("ParseLine(%q) = nil, want proxy", tc.input)
			continue
		}
		if p.Host != tc.host {
			t.Errorf("%q: host = %q, want %q", tc.input, p.Host, tc.host)
		}
		if p.Port != tc.port {
			t.Errorf("%q: port = %d, want %d", tc.input, p.Port, tc.port)
		}
		if p.Username != tc.user {
			t.Errorf("%q: user = %q, want %q", tc.input, p.Username, tc.user)
		}
	}
}

func TestParseLineInvalid(t *testing.T) {
	cases := []string{
		"",
		"# comment",
		"notaproxy",
		"1.2.3.4:99999", // port out of range
		"1.2.3.4:0",     // port zero
		"1.2.3.4:notaport",
		"socks5://host:99999",
		"socks9://host:1080", // unknown proto
	}
	for _, tc := range cases {
		p := ParseLine(tc)
		if p != nil {
			t.Errorf("ParseLine(%q) = %+v, want nil", tc, p)
		}
	}
}

// ── ParseAll ──────────────────────────────────────────────────────────────────

func TestParseAll(t *testing.T) {
	text := `
# comment
socks5://1.2.3.4:1080
socks4://5.6.7.8:9050
invalid-line
1.2.3.4:1080
`
	// 1.2.3.4:1080 is a duplicate of the socks5 URI (same host:port:proto)
	proxies := ParseAll(text)
	if len(proxies) != 2 {
		t.Errorf("ParseAll: got %d proxies, want 2", len(proxies))
	}
}

func TestParseAllDeduplication(t *testing.T) {
	text := "1.2.3.4:1080\n1.2.3.4:1080\n1.2.3.4:1080\n"
	proxies := ParseAll(text)
	if len(proxies) != 1 {
		t.Errorf("ParseAll dedup: got %d, want 1", len(proxies))
	}
}

func TestParseAllEmpty(t *testing.T) {
	proxies := ParseAll("")
	if len(proxies) != 0 {
		t.Errorf("ParseAll(\"\") = %d, want 0", len(proxies))
	}
}

// ── Address / URI ─────────────────────────────────────────────────────────────

func TestAddress(t *testing.T) {
	p := &Proxy{Host: "1.2.3.4", Port: 1080}
	if got := p.Address(); got != "1.2.3.4:1080" {
		t.Errorf("Address() = %q, want %q", got, "1.2.3.4:1080")
	}
}

func TestURIWithoutCreds(t *testing.T) {
	p := &Proxy{Host: "1.2.3.4", Port: 1080, Proto: "socks5"}
	want := "socks5://1.2.3.4:1080"
	if got := p.URI(); got != want {
		t.Errorf("URI() = %q, want %q", got, want)
	}
}

func TestURIWithCreds(t *testing.T) {
	p := &Proxy{Host: "1.2.3.4", Port: 1080, Proto: "socks5", Username: "user", Password: "pass"}
	want := "socks5://user:pass@1.2.3.4:1080"
	if got := p.URI(); got != want {
		t.Errorf("URI() = %q, want %q", got, want)
	}
}
