package proxy

import (
	"errors"
	"testing"
)

func TestIsProxyDead(t *testing.T) {
	const addr = "1.2.3.4:1080"
	cases := []struct {
		name string
		err  error
		dead bool
	}{
		{"cannot reach proxy", errors.New("dial tcp 1.2.3.4:1080: connect: connection refused"), true},
		{"not a socks server", errors.New("not a SOCKS5 server"), true},
		{"auth failed", errors.New("authentication failed"), true},
		{"no acceptable auth", errors.New("no acceptable auth method"), true},
		// Target-side failures: the proxy is fine, must NOT be condemned.
		{"no connect response (down target)", errors.New("no CONNECT response"), false},
		{"eof mid-connect", errors.New("EOF"), false},
		{"reset", errors.New("connection reset by peer"), false},
		{"broken pipe", errors.New("broken pipe"), false},
		{"target closed", errors.New("connection refused"), false},
		{"nil", nil, false},
	}
	for _, c := range cases {
		if got := IsProxyDead(addr, c.err); got != c.dead {
			t.Errorf("%s: IsProxyDead = %v, want %v", c.name, got, c.dead)
		}
	}
}

// Every "dead" error must also be a (retry-worthy) proxy error, but several
// proxy errors are target-caused and must not be classed dead.
func TestIsProxyDeadIsSubsetOfProxyError(t *testing.T) {
	const addr = "9.9.9.9:1080"
	dead := []error{
		errors.New("dial tcp 9.9.9.9:1080: i/o timeout"),
		errors.New("not a SOCKS5 server"),
	}
	for _, e := range dead {
		if !IsProxyError(addr, e) || !IsProxyDead(addr, e) {
			t.Errorf("expected proxy-error AND dead: %v", e)
		}
	}
	targetCaused := []error{
		errors.New("no CONNECT response"),
		errors.New("EOF"),
	}
	for _, e := range targetCaused {
		if !IsProxyError(addr, e) {
			t.Errorf("expected retry-worthy proxy error: %v", e)
		}
		if IsProxyDead(addr, e) {
			t.Errorf("target-caused error must not be dead: %v", e)
		}
	}
}
