package proxy

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strconv"
	"testing"
	"time"
)

// ── extractPublicIP ───────────────────────────────────────────────────────────

func TestExtractPublicIP(t *testing.T) {
	cases := []struct {
		input string
		want  string
	}{
		// plain public IPs
		{"1.2.3.4", "1.2.3.4"},
		{"98.97.37.167", "98.97.37.167"},
		{"203.0.113.55", "203.0.113.55"},
		// private / reserved — must be skipped
		{"10.0.0.1", ""},
		{"10.255.255.255", ""},
		{"172.16.0.1", ""},
		{"172.31.0.1", ""},
		{"192.168.1.1", ""},
		{"127.0.0.1", ""},
		{"169.254.1.1", ""},
		{"0.0.0.1", ""},
		// public IP buried in HTML prose (portquiz.net style)
		{"<p>Your public IP is 203.0.113.55 today.</p>", "203.0.113.55"},
		// private IP first, public second — public wins
		{"from 192.168.1.1 and also 5.5.5.5", "5.5.5.5"},
		// empty / no IP at all
		{"no ip here", ""},
		{"", ""},
	}
	for _, tc := range cases {
		got := extractPublicIP(tc.input)
		if got != tc.want {
			t.Errorf("extractPublicIP(%q) = %q, want %q", tc.input, got, tc.want)
		}
	}
}

// ── mock server helpers ───────────────────────────────────────────────────────

// startMockSOCKS5 binds a random localhost port and serves the SOCKS5 protocol.
// Pass user="",pass="" for no-auth; non-empty strings require user/pass auth.
// Accepted CONNECT requests are forwarded to the real target.
func startMockSOCKS5(t *testing.T, user, pass string) (addr string, stop func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go serveMockSOCKS5(c, user, pass)
		}
	}()
	return ln.Addr().String(), func() { ln.Close() }
}

func serveMockSOCKS5(client net.Conn, user, pass string) {
	defer client.Close()
	client.SetDeadline(time.Now().Add(5 * time.Second))

	// 1. Greeting: VER(1) NMETHODS(1) METHODS(NMETHODS)
	hdr := make([]byte, 2)
	if _, err := io.ReadFull(client, hdr); err != nil {
		return
	}
	if hdr[0] != 0x05 {
		return
	}
	methods := make([]byte, hdr[1])
	if _, err := io.ReadFull(client, methods); err != nil {
		return
	}

	// 2. Method selection
	needAuth := user != ""
	if needAuth {
		if _, err := client.Write([]byte{0x05, 0x02}); err != nil {
			return
		}
		// Sub-negotiation: VER(1) ULEN(1) UNAME(ULEN) PLEN(1) PASSWD(PLEN)
		sn := make([]byte, 2)
		if _, err := io.ReadFull(client, sn); err != nil {
			return
		}
		uname := make([]byte, sn[1])
		if _, err := io.ReadFull(client, uname); err != nil {
			return
		}
		plenBuf := make([]byte, 1)
		if _, err := io.ReadFull(client, plenBuf); err != nil {
			return
		}
		pword := make([]byte, plenBuf[0])
		if _, err := io.ReadFull(client, pword); err != nil {
			return
		}
		if string(uname) != user || string(pword) != pass {
			client.Write([]byte{0x01, 0x01}) // auth failure
			return
		}
		client.Write([]byte{0x01, 0x00}) // auth success
	} else {
		if _, err := client.Write([]byte{0x05, 0x00}); err != nil {
			return
		}
	}

	// 3. CONNECT request: VER CMD RSV ATYP [addr] PORT
	reqHdr := make([]byte, 4)
	if _, err := io.ReadFull(client, reqHdr); err != nil {
		return
	}

	var host string
	switch reqHdr[3] {
	case 0x01: // IPv4
		ipBuf := make([]byte, 4)
		if _, err := io.ReadFull(client, ipBuf); err != nil {
			return
		}
		host = net.IP(ipBuf).String()
	case 0x03: // domain name
		lb := make([]byte, 1)
		if _, err := io.ReadFull(client, lb); err != nil {
			return
		}
		db := make([]byte, int(lb[0]))
		if _, err := io.ReadFull(client, db); err != nil {
			return
		}
		host = string(db)
	default:
		client.Write([]byte{0x05, 0x08, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}
	portBuf := make([]byte, 2)
	if _, err := io.ReadFull(client, portBuf); err != nil {
		return
	}
	port := binary.BigEndian.Uint16(portBuf)

	// 4. Connect to real target
	target, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", host, port), 3*time.Second)
	if err != nil {
		client.Write([]byte{0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0}) // connection refused
		return
	}
	defer target.Close()

	// 5. Success reply: VER REP RSV ATYP BND.ADDR BND.PORT
	if _, err := client.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0}); err != nil {
		return
	}
	client.SetDeadline(time.Time{})

	done := make(chan struct{}, 2)
	go func() { io.Copy(target, client); done <- struct{}{} }()
	go func() { io.Copy(client, target); done <- struct{}{} }()
	<-done
}

// startMockSOCKS4 binds a random localhost port and serves SOCKS4 CONNECT.
// IPv4 targets only; forwards to real target.
func startMockSOCKS4(t *testing.T) (addr string, stop func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go serveMockSOCKS4(c)
		}
	}()
	return ln.Addr().String(), func() { ln.Close() }
}

func serveMockSOCKS4(client net.Conn) {
	defer client.Close()
	client.SetDeadline(time.Now().Add(5 * time.Second))

	// Request: VER(1) CMD(1) PORT(2) IP(4)
	hdr := make([]byte, 8)
	if _, err := io.ReadFull(client, hdr); err != nil {
		return
	}
	if hdr[0] != 0x04 || hdr[1] != 0x01 {
		return
	}
	// drain null-terminated userid
	b := make([]byte, 1)
	for {
		if _, err := client.Read(b); err != nil {
			return
		}
		if b[0] == 0x00 {
			break
		}
	}

	dstPort := binary.BigEndian.Uint16(hdr[2:4])
	dstHost := net.IP(hdr[4:8]).String()

	target, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", dstHost, dstPort), 3*time.Second)
	if err != nil {
		client.Write([]byte{0x00, 0x5B, hdr[2], hdr[3], hdr[4], hdr[5], hdr[6], hdr[7]})
		return
	}
	defer target.Close()

	client.Write([]byte{0x00, 0x5A, hdr[2], hdr[3], hdr[4], hdr[5], hdr[6], hdr[7]})
	client.SetDeadline(time.Time{})

	done := make(chan struct{}, 2)
	go func() { io.Copy(target, client); done <- struct{}{} }()
	go func() { io.Copy(client, target); done <- struct{}{} }()
	<-done
}

// startAcceptServer binds a random localhost port, accepts connections, and
// closes them immediately — simulates an open port.
func startAcceptServer(t *testing.T) (host string, port int, stop func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()
	h, ps, _ := net.SplitHostPort(ln.Addr().String())
	p, _ := strconv.Atoi(ps)
	return h, p, func() { ln.Close() }
}

// proxyFromAddr parses "host:port" and creates a *Proxy with the given proto.
func proxyFromAddr(t *testing.T, addr, proto string) *Proxy {
	t.Helper()
	h, ps, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatal(err)
	}
	p, err := strconv.Atoi(ps)
	if err != nil {
		t.Fatal(err)
	}
	return &Proxy{Host: h, Port: p, Proto: proto}
}

// ── socks5Handshake ───────────────────────────────────────────────────────────

func TestSocks5HandshakeNoAuth(t *testing.T) {
	proxyAddr, stop := startMockSOCKS5(t, "", "")
	defer stop()
	targetHost, targetPort, stopTarget := startAcceptServer(t)
	defer stopTarget()

	conn, err := net.DialTimeout("tcp", proxyAddr, 3*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))

	ok, errStr := socks5Handshake(conn, targetHost, targetPort, "", "")
	if !ok {
		t.Errorf("socks5Handshake (no auth): %s", errStr)
	}
}

func TestSocks5HandshakeWithAuth(t *testing.T) {
	proxyAddr, stop := startMockSOCKS5(t, "user1", "pass1")
	defer stop()
	targetHost, targetPort, stopTarget := startAcceptServer(t)
	defer stopTarget()

	conn, err := net.DialTimeout("tcp", proxyAddr, 3*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))

	ok, errStr := socks5Handshake(conn, targetHost, targetPort, "user1", "pass1")
	if !ok {
		t.Errorf("socks5Handshake (with auth): %s", errStr)
	}
}

func TestSocks5HandshakeBadCredentials(t *testing.T) {
	proxyAddr, stop := startMockSOCKS5(t, "user1", "pass1")
	defer stop()
	targetHost, targetPort, stopTarget := startAcceptServer(t)
	defer stopTarget()

	conn, err := net.DialTimeout("tcp", proxyAddr, 3*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))

	ok, _ := socks5Handshake(conn, targetHost, targetPort, "wrong", "creds")
	if ok {
		t.Error("socks5Handshake with wrong credentials should return false")
	}
}

// ── socks4Handshake ───────────────────────────────────────────────────────────

func TestSocks4HandshakeIPv4(t *testing.T) {
	proxyAddr, stop := startMockSOCKS4(t)
	defer stop()
	targetHost, targetPort, stopTarget := startAcceptServer(t)
	defer stopTarget()

	conn, err := net.DialTimeout("tcp", proxyAddr, 3*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))

	ok, errStr := socks4Handshake(conn, targetHost, targetPort)
	if !ok {
		t.Errorf("socks4Handshake: %s", errStr)
	}
}

func TestSocks4HandshakeIPv6FailsGracefully(t *testing.T) {
	// SOCKS4 requires IPv4; passing a host that resolves only to IPv6 should
	// return a clear error rather than panic.
	proxyAddr, stop := startMockSOCKS4(t)
	defer stop()
	_, targetPort, stopTarget := startAcceptServer(t)
	defer stopTarget()

	conn, err := net.DialTimeout("tcp", proxyAddr, 3*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))

	// "::1" is pure IPv6 — To4() returns nil, so socks4Handshake must fail cleanly.
	ok, errStr := socks4Handshake(conn, "::1", targetPort)
	if ok {
		t.Error("socks4Handshake with IPv6 address should fail")
	}
	if errStr == "" {
		t.Error("expected non-empty error string for IPv6 target")
	}
}

// ── DialThroughProxy ──────────────────────────────────────────────────────────

func TestDialThroughProxySOCKS5(t *testing.T) {
	proxyAddr, stop := startMockSOCKS5(t, "", "")
	defer stop()
	targetHost, targetPort, stopTarget := startAcceptServer(t)
	defer stopTarget()

	p := proxyFromAddr(t, proxyAddr, "socks5")
	conn, err := DialThroughProxy(p, targetHost, targetPort, 5*time.Second)
	if err != nil {
		t.Fatalf("DialThroughProxy SOCKS5: %v", err)
	}
	conn.Close()
}

func TestDialThroughProxySOCKS4(t *testing.T) {
	proxyAddr, stop := startMockSOCKS4(t)
	defer stop()
	targetHost, targetPort, stopTarget := startAcceptServer(t)
	defer stopTarget()

	p := proxyFromAddr(t, proxyAddr, "socks4")
	conn, err := DialThroughProxy(p, targetHost, targetPort, 5*time.Second)
	if err != nil {
		t.Fatalf("DialThroughProxy SOCKS4: %v", err)
	}
	conn.Close()
}

func TestDialThroughProxyUnreachableProxy(t *testing.T) {
	// nothing listens on port 1 — connection should be refused immediately
	p := &Proxy{Host: "127.0.0.1", Port: 1, Proto: "socks5"}
	_, err := DialThroughProxy(p, "127.0.0.1", 80, 500*time.Millisecond)
	if err == nil {
		t.Error("DialThroughProxy to dead proxy should return error")
	}
}

// ── Validate ──────────────────────────────────────────────────────────────────

func TestValidateSOCKS5Success(t *testing.T) {
	proxyAddr, stop := startMockSOCKS5(t, "", "")
	defer stop()
	targetHost, targetPort, stopTarget := startAcceptServer(t)
	defer stopTarget()

	p := proxyFromAddr(t, proxyAddr, "socks5")
	ok, ms, errStr := Validate(p, 5*time.Second, targetHost, targetPort)
	if !ok {
		t.Errorf("Validate SOCKS5: %s", errStr)
	}
	if ms < 0 {
		t.Errorf("Validate latency = %f, want >= 0", ms)
	}
}

func TestValidateSOCKS4Success(t *testing.T) {
	proxyAddr, stop := startMockSOCKS4(t)
	defer stop()
	targetHost, targetPort, stopTarget := startAcceptServer(t)
	defer stopTarget()

	p := proxyFromAddr(t, proxyAddr, "socks4")
	ok, _, errStr := Validate(p, 5*time.Second, targetHost, targetPort)
	if !ok {
		t.Errorf("Validate SOCKS4: %s", errStr)
	}
}

func TestValidateDeadProxy(t *testing.T) {
	p := &Proxy{Host: "127.0.0.1", Port: 1, Proto: "socks5"}
	ok, _, _ := Validate(p, 500*time.Millisecond, "127.0.0.1", 80)
	if ok {
		t.Error("Validate to dead proxy should return false")
	}
}
