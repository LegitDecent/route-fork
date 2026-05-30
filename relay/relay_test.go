package relay

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"

	"rofk/proxy"
)

// ── socks4Reply ───────────────────────────────────────────────────────────────

func TestSocks4Reply(t *testing.T) {
	ip := []byte{1, 2, 3, 4}
	got := socks4Reply(0x5A, 8080, ip)
	if len(got) != 8 {
		t.Fatalf("socks4Reply length = %d, want 8", len(got))
	}
	if got[0] != 0x00 {
		t.Errorf("byte[0] = %02x, want 0x00", got[0])
	}
	if got[1] != 0x5A {
		t.Errorf("byte[1] = %02x, want 0x5A", got[1])
	}
	if binary.BigEndian.Uint16(got[2:4]) != 8080 {
		t.Errorf("port bytes = %d, want 8080", binary.BigEndian.Uint16(got[2:4]))
	}
	if got[4] != 1 || got[5] != 2 || got[6] != 3 || got[7] != 4 {
		t.Errorf("IP bytes = %v, want [1 2 3 4]", got[4:8])
	}
}

// ── readUntilNull ─────────────────────────────────────────────────────────────

func TestReadUntilNull(t *testing.T) {
	r, w := net.Pipe()
	defer r.Close()
	defer w.Close()

	go func() {
		w.Write([]byte{'h', 'e', 'l', 'l', 'o', 0x00})
	}()

	r.SetDeadline(time.Now().Add(2 * time.Second))
	err := readUntilNull(r)
	if err != nil {
		t.Errorf("readUntilNull: %v", err)
	}
}

func TestReadUntilNullImmediate(t *testing.T) {
	r, w := net.Pipe()
	defer r.Close()
	defer w.Close()

	go func() {
		w.Write([]byte{0x00}) // null byte immediately
	}()

	r.SetDeadline(time.Now().Add(2 * time.Second))
	err := readUntilNull(r)
	if err != nil {
		t.Errorf("readUntilNull (immediate null): %v", err)
	}
}

// ── readStringUntilNull ───────────────────────────────────────────────────────

func TestReadStringUntilNull(t *testing.T) {
	r, w := net.Pipe()
	defer r.Close()
	defer w.Close()

	go func() {
		w.Write(append([]byte("example.com"), 0x00))
	}()

	r.SetDeadline(time.Now().Add(2 * time.Second))
	s, err := readStringUntilNull(r)
	if err != nil {
		t.Fatalf("readStringUntilNull: %v", err)
	}
	if s != "example.com" {
		t.Errorf("got %q, want %q", s, "example.com")
	}
}

func TestReadStringUntilNullEmpty(t *testing.T) {
	r, w := net.Pipe()
	defer r.Close()
	defer w.Close()

	go func() {
		w.Write([]byte{0x00}) // empty string
	}()

	r.SetDeadline(time.Now().Add(2 * time.Second))
	s, err := readStringUntilNull(r)
	if err != nil {
		t.Fatalf("readStringUntilNull (empty): %v", err)
	}
	if s != "" {
		t.Errorf("got %q, want empty string", s)
	}
}

// ── mock SOCKS5 upstream ──────────────────────────────────────────────────────

// startMockSOCKS5Upstream starts a SOCKS5 server that forwards CONNECT to real targets.
func startMockSOCKS5Upstream(t *testing.T) (addr string, stop func()) {
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
			go serveMockSOCKS5(c)
		}
	}()
	return ln.Addr().String(), func() { ln.Close() }
}

func serveMockSOCKS5(client net.Conn) {
	defer client.Close()
	client.SetDeadline(time.Now().Add(5 * time.Second))

	// greeting
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
	if _, err := client.Write([]byte{0x05, 0x00}); err != nil {
		return
	}

	// CONNECT request
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
	case 0x03: // domain
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

	target, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", host, port), 3*time.Second)
	if err != nil {
		client.Write([]byte{0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}
	defer target.Close()

	client.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
	client.SetDeadline(time.Time{})

	done := make(chan struct{}, 2)
	go func() { io.Copy(target, client); done <- struct{}{} }()
	go func() { io.Copy(client, target); done <- struct{}{} }()
	<-done
}

// ── mock SOCKS4a upstream ─────────────────────────────────────────────────────

// startMockSOCKS4aUpstream starts a server that speaks SOCKS4/4a and forwards to real targets.
func startMockSOCKS4aUpstream(t *testing.T) (addr string, stop func()) {
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
			go serveMockSOCKS4a(c)
		}
	}()
	return ln.Addr().String(), func() { ln.Close() }
}

func serveMockSOCKS4a(client net.Conn) {
	defer client.Close()
	client.SetDeadline(time.Now().Add(5 * time.Second))

	hdr := make([]byte, 8)
	if _, err := io.ReadFull(client, hdr); err != nil {
		return
	}
	if hdr[0] != 0x04 || hdr[1] != 0x01 {
		return
	}
	dstPort := binary.BigEndian.Uint16(hdr[2:4])

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

	var dstHost string
	// SOCKS4a: IP is 0.0.0.x where x != 0
	if hdr[4] == 0 && hdr[5] == 0 && hdr[6] == 0 && hdr[7] != 0 {
		var hb []byte
		for {
			if _, err := client.Read(b); err != nil {
				return
			}
			if b[0] == 0x00 {
				break
			}
			hb = append(hb, b[0])
		}
		dstHost = string(hb)
	} else {
		dstHost = net.IP(hdr[4:8]).String()
	}

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

// ── target server helpers ─────────────────────────────────────────────────────

// startAcceptTarget accepts connections and closes them immediately (open port sim).
func startAcceptTarget(t *testing.T) (host string, port int, stop func()) {
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

// startEchoTarget accepts connections and echoes data back.
func startEchoTarget(t *testing.T) (host string, port int, stop func()) {
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
			go func(c net.Conn) {
				defer c.Close()
				io.Copy(c, c)
			}(c)
		}
	}()
	h, ps, _ := net.SplitHostPort(ln.Addr().String())
	p, _ := strconv.Atoi(ps)
	return h, p, func() { ln.Close() }
}

// proxyFromAddr builds a *proxy.Proxy from "host:port" and a proto string.
func proxyFromAddr(t *testing.T, addr, proto string) *proxy.Proxy {
	t.Helper()
	h, ps, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatal(err)
	}
	p, err := strconv.Atoi(ps)
	if err != nil {
		t.Fatal(err)
	}
	return &proxy.Proxy{Host: h, Port: p, Proto: proto}
}

// ── socks5Connect ─────────────────────────────────────────────────────────────

func TestSocks5ConnectNoAuth(t *testing.T) {
	upstreamAddr, stop := startMockSOCKS5Upstream(t)
	defer stop()
	targetHost, targetPort, stopTarget := startAcceptTarget(t)
	defer stopTarget()

	conn, err := net.DialTimeout("tcp", upstreamAddr, 3*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))

	if err := socks5Connect(conn, targetHost, targetPort, "", ""); err != nil {
		t.Errorf("socks5Connect: %v", err)
	}
}

// ── socks4aConnect ────────────────────────────────────────────────────────────

func TestSocks4aConnectIPv4(t *testing.T) {
	upstreamAddr, stop := startMockSOCKS4aUpstream(t)
	defer stop()
	targetHost, targetPort, stopTarget := startAcceptTarget(t)
	defer stopTarget()

	conn, err := net.DialTimeout("tcp", upstreamAddr, 3*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))

	if err := socks4aConnect(conn, targetHost, targetPort); err != nil {
		t.Errorf("socks4aConnect: %v", err)
	}
}

func TestSocks4aConnectHostname(t *testing.T) {
	upstreamAddr, stop := startMockSOCKS4aUpstream(t)
	defer stop()
	_, targetPort, stopTarget := startAcceptTarget(t)
	defer stopTarget()

	conn, err := net.DialTimeout("tcp", upstreamAddr, 3*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))

	// Use "localhost" — mock resolves it via DNS
	if err := socks4aConnect(conn, "localhost", targetPort); err != nil {
		t.Errorf("socks4aConnect(localhost): %v", err)
	}
}

// ── relay forward path ────────────────────────────────────────────────────────

// dialSOCKS4 connects to the relay and sends a SOCKS4 CONNECT for targetHost:targetPort.
// Returns the open connection (0x5A received) or fails the test.
func dialSOCKS4(t *testing.T, relayAddr, targetHost string, targetPort int) net.Conn {
	t.Helper()
	conn, err := net.DialTimeout("tcp", relayAddr, 3*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	conn.SetDeadline(time.Now().Add(5 * time.Second))

	ip := net.ParseIP(targetHost).To4()
	if ip == nil {
		addrs, err := net.LookupHost(targetHost)
		if err != nil || len(addrs) == 0 {
			conn.Close()
			t.Fatalf("cannot resolve %s", targetHost)
		}
		ip = net.ParseIP(addrs[0]).To4()
	}

	req := []byte{
		0x04, 0x01,
		byte(targetPort >> 8), byte(targetPort),
		ip[0], ip[1], ip[2], ip[3],
		0x00, // null userid
	}
	if _, err := conn.Write(req); err != nil {
		conn.Close()
		t.Fatal(err)
	}

	resp := make([]byte, 8)
	if _, err := io.ReadFull(conn, resp); err != nil {
		conn.Close()
		t.Fatalf("reading relay SOCKS4 response: %v", err)
	}
	if resp[1] != 0x5A {
		conn.Close()
		t.Fatalf("relay returned code %02x, want 0x5A", resp[1])
	}
	conn.SetDeadline(time.Time{})
	return conn
}

// dialSOCKS4a connects to the relay with a SOCKS4a CONNECT (hostname-based).
func dialSOCKS4a(t *testing.T, relayAddr, hostname string, port int) net.Conn {
	t.Helper()
	conn, err := net.DialTimeout("tcp", relayAddr, 3*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	conn.SetDeadline(time.Now().Add(5 * time.Second))

	req := []byte{
		0x04, 0x01,
		byte(port >> 8), byte(port),
		0x00, 0x00, 0x00, 0x01, // SOCKS4a marker
		0x00,                    // empty userid
	}
	req = append(req, []byte(hostname)...)
	req = append(req, 0x00) // null-terminate hostname

	if _, err := conn.Write(req); err != nil {
		conn.Close()
		t.Fatal(err)
	}

	resp := make([]byte, 8)
	if _, err := io.ReadFull(conn, resp); err != nil {
		conn.Close()
		t.Fatalf("reading relay SOCKS4a response: %v", err)
	}
	if resp[1] != 0x5A {
		conn.Close()
		t.Fatalf("relay (SOCKS4a) returned code %02x, want 0x5A", resp[1])
	}
	conn.SetDeadline(time.Time{})
	return conn
}

func TestRelayForwardSOCKS5Upstream(t *testing.T) {
	upstreamAddr, stopUpstream := startMockSOCKS5Upstream(t)
	defer stopUpstream()
	targetHost, targetPort, stopTarget := startAcceptTarget(t)
	defer stopTarget()

	px := proxyFromAddr(t, upstreamAddr, "socks5")
	_, relayAddr, err := Start(px, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}

	// dialSOCKS4 verifies the 0x5A reply internally — if it returns, the relay succeeded
	conn := dialSOCKS4(t, relayAddr, targetHost, targetPort)
	conn.Close()
}

func TestRelayForwardSOCKS4aUpstream(t *testing.T) {
	upstreamAddr, stopUpstream := startMockSOCKS4aUpstream(t)
	defer stopUpstream()
	targetHost, targetPort, stopTarget := startAcceptTarget(t)
	defer stopTarget()

	px := proxyFromAddr(t, upstreamAddr, "socks4")
	_, relayAddr, err := Start(px, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}

	conn := dialSOCKS4(t, relayAddr, targetHost, targetPort)
	conn.Close()
}

func TestRelaySOCKS4aHostnameRequest(t *testing.T) {
	// client sends SOCKS4a (hostname) to relay; relay forwards via SOCKS5 upstream
	upstreamAddr, stopUpstream := startMockSOCKS5Upstream(t)
	defer stopUpstream()
	targetHost, targetPort, stopTarget := startAcceptTarget(t)
	defer stopTarget()

	px := proxyFromAddr(t, upstreamAddr, "socks5")
	_, relayAddr, err := Start(px, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}

	conn := dialSOCKS4a(t, relayAddr, targetHost, targetPort)
	conn.Close()
}

func TestRelayDataFlowEndToEnd(t *testing.T) {
	upstreamAddr, stopUpstream := startMockSOCKS5Upstream(t)
	defer stopUpstream()
	echoHost, echoPort, stopEcho := startEchoTarget(t)
	defer stopEcho()

	px := proxyFromAddr(t, upstreamAddr, "socks5")
	_, relayAddr, err := Start(px, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}

	conn := dialSOCKS4(t, relayAddr, echoHost, echoPort)
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))

	msg := "ping\n"
	if _, err := conn.Write([]byte(msg)); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, len(msg))
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatal(err)
	}
	if string(buf) != msg {
		t.Errorf("echo got %q, want %q", string(buf), msg)
	}
}

// ── relay failure — no 0x5B ───────────────────────────────────────────────────

func TestRelayFailureNoRejectionCode(t *testing.T) {
	// Point relay at a dead upstream — nothing on port 1
	px := &proxy.Proxy{Host: "127.0.0.1", Port: 1, Proto: "socks5"}
	relay, relayAddr, err := Start(px, 300*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	defer relay.Stop()

	conn, err := net.DialTimeout("tcp", relayAddr, 3*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	// Send SOCKS4 CONNECT for port 80 on localhost
	req := []byte{0x04, 0x01, 0x00, 0x50, 127, 0, 0, 1, 0x00}
	conn.Write(req)

	// relay should close the connection (bare TCP close), NOT send 0x5B
	conn.SetDeadline(time.Now().Add(2 * time.Second))
	resp := make([]byte, 8)
	n, err := io.ReadFull(conn, resp)
	if err == nil && n == 8 {
		// Got a full 8-byte response — verify it's not a SOCKS4 rejection
		if resp[1] == 0x5B {
			t.Error("relay sent 0x5B rejection — should send bare TCP close instead")
		}
	}
	// Getting an error (EOF/reset) is the expected behavior
}

// ── Relay.Stop ────────────────────────────────────────────────────────────────

func TestRelayStop(t *testing.T) {
	px := &proxy.Proxy{Host: "127.0.0.1", Port: 1, Proto: "socks5"}
	r, addr, err := Start(px, 1*time.Second)
	if err != nil {
		t.Fatal(err)
	}

	// Should be listening now
	conn, err := net.DialTimeout("tcp", addr, 1*time.Second)
	if err != nil {
		t.Fatalf("relay not reachable before Stop: %v", err)
	}
	conn.Close()

	r.Stop()

	// After Stop, new connections should be refused
	_, err = net.DialTimeout("tcp", addr, 300*time.Millisecond)
	if err == nil {
		t.Error("relay still accepts connections after Stop")
	}
}

// ── NmapProxyArg ─────────────────────────────────────────────────────────────

func TestNmapProxyArgFormat(t *testing.T) {
	px := &proxy.Proxy{Host: "127.0.0.1", Port: 1, Proto: "socks5"}
	arg, stop, err := NmapProxyArg(px, 1*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer stop()

	if !strings.HasPrefix(arg, "socks4://127.0.0.1:") {
		t.Errorf("NmapProxyArg = %q, want socks4://127.0.0.1:PORT", arg)
	}
}
