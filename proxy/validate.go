package proxy

import (
	"encoding/binary"
	"fmt"
	"net"
	"strings"
	"time"
)

// DialThroughProxy opens a TCP tunnel to host:port through the SOCKS proxy.
// After a successful return the connection is ready to carry application data.
func DialThroughProxy(p *Proxy, host string, port int, timeout time.Duration) (net.Conn, error) {
	conn, err := net.DialTimeout("tcp", p.Address(), timeout)
	if err != nil {
		return nil, err
	}
	conn.SetDeadline(time.Now().Add(timeout))

	var ok bool
	var errStr string
	if p.Proto == "socks5" {
		ok, errStr = socks5Handshake(conn, host, port, p.Username, p.Password)
	} else {
		ok, errStr = socks4Handshake(conn, host, port)
	}
	if !ok {
		conn.Close()
		return nil, fmt.Errorf("%s", errStr)
	}
	return conn, nil
}

// FetchEgressIP sends HTTP requests through the proxy to IP-echo services and
// returns the outbound IP the target actually sees. On success p.EgressIP is
// populated.
//
// portquiz.net is tried first on port 8080 — this catches proxies that route
// port 80 traffic direct (giving a false egress equal to the entry IP) while
// tunnelling everything else through an upstream. Falling back to port-80
// services covers proxies that block portquiz.net.
func FetchEgressIP(p *Proxy, timeout time.Duration) (string, error) {
	type svc struct {
		host string
		port int
	}
	services := []svc{
		{"portquiz.net", 8080}, // non-80 — same routing path as scan traffic
		{"api.ipify.org", 80},
		{"checkip.amazonaws.com", 80},
	}
	for _, s := range services {
		conn, err := DialThroughProxy(p, s.host, s.port, timeout)
		if err != nil {
			continue
		}
		conn.SetDeadline(time.Now().Add(timeout))

		req := "GET / HTTP/1.0\r\nHost: " + s.host + "\r\nConnection: close\r\n\r\n"
		if _, err = conn.Write([]byte(req)); err != nil {
			conn.Close()
			continue
		}

		buf := make([]byte, 2048)
		total := 0
		for total < len(buf) {
			n, err := conn.Read(buf[total:])
			total += n
			if err != nil {
				break
			}
		}
		conn.Close()

		if total == 0 {
			continue
		}
		// Strip HTTP headers
		parts := strings.SplitN(string(buf[:total]), "\r\n\r\n", 2)
		if len(parts) < 2 {
			continue
		}
		if ip := extractPublicIP(parts[1]); ip != "" {
			p.EgressIP = ip
			return ip, nil
		}
	}
	return "", fmt.Errorf("could not determine egress IP")
}

// extractPublicIP returns the first public IPv4 address found in text.
// Handles bare-IP responses (api.ipify.org) and prose responses (portquiz.net).
func extractPublicIP(text string) string {
	// tokenise on anything that isn't a digit or dot
	fields := strings.FieldsFunc(text, func(r rune) bool {
		return (r < '0' || r > '9') && r != '.'
	})
	for _, f := range fields {
		ip := net.ParseIP(f)
		if ip == nil {
			continue
		}
		ip4 := ip.To4()
		if ip4 == nil {
			continue
		}
		// skip loopback, private, link-local, unspecified
		switch {
		case ip4[0] == 0:
		case ip4[0] == 10:
		case ip4[0] == 127:
		case ip4[0] == 169 && ip4[1] == 254:
		case ip4[0] == 172 && ip4[1] >= 16 && ip4[1] <= 31:
		case ip4[0] == 192 && ip4[1] == 168:
		default:
			return f
		}
	}
	return ""
}

// Validate performs a raw SOCKS4/5 handshake to verify the proxy is alive.
// Returns success, latency in ms, and an error string.
func Validate(p *Proxy, timeout time.Duration, testHost string, testPort int) (bool, float64, string) {
	t0 := time.Now()

	conn, err := net.DialTimeout("tcp", p.Address(), timeout)
	if err != nil {
		return false, 0, err.Error()
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(timeout))

	var ok bool
	var errStr string
	if p.Proto == "socks5" {
		ok, errStr = socks5Handshake(conn, testHost, testPort, p.Username, p.Password)
	} else {
		ok, errStr = socks4Handshake(conn, testHost, testPort)
	}

	if ok {
		return true, float64(time.Since(t0).Milliseconds()), ""
	}
	return false, 0, errStr
}

func socks5Handshake(conn net.Conn, host string, port int, user, pass string) (bool, string) {
	var greeting []byte
	if user != "" {
		greeting = []byte{0x05, 0x02, 0x00, 0x02}
	} else {
		greeting = []byte{0x05, 0x01, 0x00}
	}
	if _, err := conn.Write(greeting); err != nil {
		return false, err.Error()
	}

	resp := make([]byte, 2)
	if _, err := conn.Read(resp); err != nil {
		return false, err.Error()
	}
	if resp[0] != 0x05 {
		return false, "not a SOCKS5 server"
	}

	switch resp[1] {
	case 0xFF:
		return false, "no acceptable auth method"
	case 0x02:
		if user == "" {
			return false, "auth required but no credentials"
		}
		ub, pb := []byte(user), []byte(pass)
		msg := append([]byte{0x01, byte(len(ub))}, ub...)
		msg = append(msg, byte(len(pb)))
		msg = append(msg, pb...)
		if _, err := conn.Write(msg); err != nil {
			return false, err.Error()
		}
		ar := make([]byte, 2)
		if _, err := conn.Read(ar); err != nil {
			return false, err.Error()
		}
		if ar[1] != 0x00 {
			return false, "authentication failed"
		}
	}

	hb := []byte(host)
	req := []byte{0x05, 0x01, 0x00, 0x03, byte(len(hb))}
	req = append(req, hb...)
	req = append(req, byte(port>>8), byte(port))
	if _, err := conn.Write(req); err != nil {
		return false, err.Error()
	}

	buf := make([]byte, 262)
	n, err := conn.Read(buf)
	if err != nil || n < 2 {
		return false, "no CONNECT response"
	}
	if buf[1] != 0x00 {
		codes := map[byte]string{
			0x01: "general failure", 0x02: "not allowed", 0x03: "network unreachable",
			0x04: "host unreachable", 0x05: "connection refused", 0x06: "TTL expired",
		}
		if m, ok := codes[buf[1]]; ok {
			return false, m
		}
		return false, fmt.Sprintf("SOCKS5 error %#02x", buf[1])
	}
	return true, ""
}

func socks4Handshake(conn net.Conn, host string, port int) (bool, string) {
	ip := net.ParseIP(host)
	if ip == nil {
		addrs, err := net.LookupHost(host)
		if err != nil || len(addrs) == 0 {
			return false, "DNS resolution failed"
		}
		ip = net.ParseIP(addrs[0])
	}
	ip4 := ip.To4()
	if ip4 == nil {
		return false, "SOCKS4 requires IPv4"
	}

	req := make([]byte, 9)
	req[0] = 0x04
	req[1] = 0x01
	binary.BigEndian.PutUint16(req[2:4], uint16(port))
	copy(req[4:8], ip4)
	req[8] = 0x00

	if _, err := conn.Write(req); err != nil {
		return false, err.Error()
	}

	resp := make([]byte, 8)
	if _, err := conn.Read(resp); err != nil {
		return false, err.Error()
	}
	if resp[1] == 0x5A {
		return true, ""
	}
	codes := map[byte]string{
		0x5B: "request rejected", 0x5C: "cannot connect to identd", 0x5D: "identd mismatch",
	}
	if m, ok := codes[resp[1]]; ok {
		return false, m
	}
	return false, fmt.Sprintf("SOCKS4 code %#02x", resp[1])
}

// IsProxyError reports whether err indicates the PROXY failed (so a retry through
// a different proxy is warranted) rather than the target port being closed or
// filtered (a real scan result that should be reported as-is).
//
// It is deliberately conservative: only a proxy we can't reach, or one that
// isn't behaving like a SOCKS server, counts as a proxy error. A closed port
// ("connection refused"), an unreachable/filtered target, a SOCKS4 rejection,
// or a missing CONNECT response (target dropping packets) are all treated as
// genuine results — so a closed/filtered target never churns or prunes the pool.
func IsProxyError(proxyAddr string, err error) bool {
	if err == nil {
		return false
	}
	s := err.Error()
	sl := strings.ToLower(s)

	// Couldn't reach the proxy at all (refused or timed out dialing IT).
	if strings.Contains(s, "dial tcp "+proxyAddr) {
		return true
	}
	// Proxy accepted the TCP connection but misbehaved mid-handshake: not a
	// real SOCKS server, auth problem, or it reset/closed the connection /
	// never returned a CONNECT reply. Over SOCKS we never touch the target
	// directly, so a reset/EOF/no-reply on our proxy socket is the PROXY's
	// fault — not evidence the target port is closed. A genuinely closed port
	// comes back as a proper SOCKS "connection refused" (handled below).
	for _, sig := range []string{
		"not a socks5 server",
		"auth",
		"connection reset by peer",
		"no connect response",
		"broken pipe",
		"eof",
	} {
		if strings.Contains(sl, sig) {
			return true
		}
	}
	// Everything else is a real target-side result — the proxy worked:
	// "connection refused" (port closed), "host/network unreachable",
	// SOCKS4 "request rejected". Report as-is, don't retry.
	return false
}
