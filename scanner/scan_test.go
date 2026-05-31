package scanner

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strconv"
	"testing"
	"time"

	"rofk/proxy"
)

// ── mock SOCKS5 proxy ─────────────────────────────────────────────────────────

// startMockSOCKS5 binds a random localhost port and serves SOCKS5 (no auth).
// CONNECT requests are forwarded to the real target.
func startMockSOCKS5(t *testing.T) (addr string, stop func()) {
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

// openPortFromAddr returns an open TCP listener on a random localhost port.
// The caller is responsible for closing the listener.
func openPort(t *testing.T) (host, portStr string, stop func()) {
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
	return h, ps, func() { ln.Close() }
}

// proxyFromAddr builds a *proxy.Proxy for the given "host:port" address.
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

// collectResults drains results until the channel is closed.
func collectResults(results <-chan Result) []Result {
	var out []Result
	for r := range results {
		out = append(out, r)
	}
	return out
}

// ── Scan ──────────────────────────────────────────────────────────────────────

func TestScanOpenPort(t *testing.T) {
	proxyAddr, stopProxy := startMockSOCKS5(t)
	defer stopProxy()

	targetHost, portStr, stopTarget := openPort(t)
	defer stopTarget()

	px := proxyFromAddr(t, proxyAddr, "socks5")
	opts := Options{Ports: portStr, Concurrency: 10, Timeout: 5 * time.Second}
	results := make(chan Result, 32)

	var found []Result
	done := make(chan struct{})
	go func() {
		found = collectResults(results)
		close(done)
	}()

	err := Scan(context.Background(), func() *proxy.Proxy { return px }, targetHost, opts, results, nil)
	close(results)
	<-done

	if err != nil {
		t.Fatalf("Scan: %v", err)
	}

	port, _ := strconv.Atoi(portStr)
	if len(found) != 1 {
		t.Fatalf("got %d results, want 1", len(found))
	}
	r := found[0]
	if !r.Open {
		t.Error("result.Open = false, want true")
	}
	if r.Port != port {
		t.Errorf("result.Port = %d, want %d", r.Port, port)
	}
	if r.Host != targetHost {
		t.Errorf("result.Host = %q, want %q", r.Host, targetHost)
	}
}

func TestScanProxyPopulated(t *testing.T) {
	proxyAddr, stopProxy := startMockSOCKS5(t)
	defer stopProxy()

	targetHost, portStr, stopTarget := openPort(t)
	defer stopTarget()

	px := proxyFromAddr(t, proxyAddr, "socks5")
	opts := Options{Ports: portStr, Concurrency: 10, Timeout: 5 * time.Second}
	results := make(chan Result, 32)

	var found []Result
	done := make(chan struct{})
	go func() {
		found = collectResults(results)
		close(done)
	}()

	Scan(context.Background(), func() *proxy.Proxy { return px }, targetHost, opts, results, nil)
	close(results)
	<-done

	if len(found) == 0 {
		t.Fatal("no results - cannot check Proxy field")
	}
	if found[0].Proxy == nil {
		t.Error("Result.Proxy is nil; should carry the proxy that opened the connection")
	}
	if found[0].Proxy != px {
		t.Error("Result.Proxy is not the proxy passed to Scan")
	}
}

func TestScanClosedPort(t *testing.T) {
	proxyAddr, stopProxy := startMockSOCKS5(t)
	defer stopProxy()

	// grab a port then close it so nothing is listening
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	_, portStr, _ := net.SplitHostPort(ln.Addr().String())
	ln.Close()

	px := proxyFromAddr(t, proxyAddr, "socks5")
	opts := Options{Ports: portStr, Concurrency: 10, Timeout: 2 * time.Second}
	results := make(chan Result, 32)

	var found []Result
	done := make(chan struct{})
	go func() {
		found = collectResults(results)
		close(done)
	}()

	Scan(context.Background(), func() *proxy.Proxy { return px }, "127.0.0.1", opts, results, nil)
	close(results)
	<-done

	if len(found) != 0 {
		t.Errorf("got %d results for closed port, want 0", len(found))
	}
}

func TestScanProgressCallback(t *testing.T) {
	proxyAddr, stopProxy := startMockSOCKS5(t)
	defer stopProxy()

	// scan a small fixed port range (no target listening - that's OK, progress fires regardless)
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	_, portStr, _ := net.SplitHostPort(ln.Addr().String())
	ln.Close()

	px := proxyFromAddr(t, proxyAddr, "socks5")
	opts := Options{Ports: portStr, Concurrency: 10, Timeout: 500 * time.Millisecond}
	results := make(chan Result, 32)

	var lastScanned, lastTotal int
	progressCalled := false
	progress := func(scanned, total int) {
		progressCalled = true
		lastScanned = scanned
		lastTotal = total
	}

	done := make(chan struct{})
	go func() {
		for range results {
		}
		close(done)
	}()

	Scan(context.Background(), func() *proxy.Proxy { return px }, "127.0.0.1", opts, results, progress)
	close(results)
	<-done

	if !progressCalled {
		t.Error("progress callback was never called")
	}
	if lastTotal <= 0 {
		t.Errorf("progress total = %d, want > 0", lastTotal)
	}
	_ = lastScanned
}

func TestScanContextPreCancelled(t *testing.T) {
	proxyAddr, stopProxy := startMockSOCKS5(t)
	defer stopProxy()

	px := proxyFromAddr(t, proxyAddr, "socks5")
	opts := Options{Ports: "1-100", Concurrency: 10, Timeout: 1 * time.Second}
	results := make(chan Result, 200)

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel before Scan starts

	done := make(chan struct{})
	go func() {
		for range results {
		}
		close(done)
	}()

	err := Scan(ctx, func() *proxy.Proxy { return px }, "127.0.0.1", opts, results, nil)
	close(results)
	<-done

	if err != context.Canceled {
		t.Errorf("Scan with pre-cancelled ctx: err = %v, want context.Canceled", err)
	}
}

func TestScanMultiplePorts(t *testing.T) {
	proxyAddr, stopProxy := startMockSOCKS5(t)
	defer stopProxy()

	// open two ports
	ln1, _ := net.Listen("tcp", "127.0.0.1:0")
	ln2, _ := net.Listen("tcp", "127.0.0.1:0")
	defer ln1.Close()
	defer ln2.Close()
	go func() {
		for {
			c, err := ln1.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()
	go func() {
		for {
			c, err := ln2.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()

	_, p1s, _ := net.SplitHostPort(ln1.Addr().String())
	_, p2s, _ := net.SplitHostPort(ln2.Addr().String())
	portSpec := p1s + "," + p2s

	px := proxyFromAddr(t, proxyAddr, "socks5")
	opts := Options{Ports: portSpec, Concurrency: 10, Timeout: 5 * time.Second}
	results := make(chan Result, 32)

	var found []Result
	done := make(chan struct{})
	go func() {
		found = collectResults(results)
		close(done)
	}()

	Scan(context.Background(), func() *proxy.Proxy { return px }, "127.0.0.1", opts, results, nil)
	close(results)
	<-done

	if len(found) != 2 {
		t.Errorf("got %d open ports, want 2", len(found))
	}
	for _, r := range found {
		if !r.Open {
			t.Errorf("port %d: Open = false", r.Port)
		}
		if r.Proxy == nil {
			t.Errorf("port %d: Proxy is nil", r.Port)
		}
	}
}
