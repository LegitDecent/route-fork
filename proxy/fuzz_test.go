package proxy

import (
	"net"
	"strings"
	"testing"
)

// FuzzParseLine feeds arbitrary input to the proxy-line parser. It must never
// panic, and any proxy it returns must be internally consistent.
func FuzzParseLine(f *testing.F) {
	for _, s := range []string{
		"", "#", "1.2.3.4:1080", "socks5://u:p@h:1", "socks4://10.0.0.1:9050",
		"host.example.com:65535", "1.2.3.4:0", "1.2.3.4:99999",
		"socks5://", ":::::", "1.2.3.4:1080:user:pass", " \t\n",
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, line string) {
		p := ParseLine(line)
		if p == nil {
			return
		}
		if p.Port < 1 || p.Port > 65535 {
			t.Fatalf("ParseLine(%q) produced out-of-range port %d", line, p.Port)
		}
		if p.Proto != "socks4" && p.Proto != "socks5" {
			t.Fatalf("ParseLine(%q) produced unexpected proto %q", line, p.Proto)
		}
		if p.Host == "" {
			t.Fatalf("ParseLine(%q) produced empty host", line)
		}
	})
}

// FuzzParseAll ensures the multi-line parser never panics on arbitrary text.
func FuzzParseAll(f *testing.F) {
	f.Add("socks5://1.2.3.4:1080\n# c\n1.2.3.4:1080\ninvalid\n")
	f.Add("")
	f.Fuzz(func(t *testing.T, text string) {
		for _, p := range ParseAll(text) {
			if p.Port < 1 || p.Port > 65535 {
				t.Fatalf("ParseAll produced out-of-range port %d", p.Port)
			}
		}
	})
}

// FuzzExtractPublicIP feeds arbitrary response bodies to the egress-IP
// extractor. It must never panic and must only ever return a public IPv4.
func FuzzExtractPublicIP(f *testing.F) {
	for _, s := range []string{
		"", "1.2.3.4", "10.0.0.1", "no ip", "<p>5.5.5.5</p>",
		"999.999.999.999", "1.2.3.4.5.6.7.8", strings.Repeat("1.", 5000),
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, text string) {
		got := extractPublicIP(text)
		if got == "" {
			return
		}
		ip := net.ParseIP(got)
		if ip == nil || ip.To4() == nil {
			t.Fatalf("extractPublicIP returned non-IPv4 %q", got)
		}
		if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsUnspecified() {
			t.Fatalf("extractPublicIP returned non-public IP %q", got)
		}
	})
}
