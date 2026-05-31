package scanner

import (
	"context"
	"net"
	"testing"
	"time"

	"rofk/proxy"
)

// TestScanIdentifiesBannerService verifies scanner.Scan parses a service and
// version from a banner the target volunteers (shared probe logic).
func TestScanIdentifiesBannerService(t *testing.T) {
	socksAddr, stopProxy := startMockSOCKS5(t)
	defer stopProxy()
	prox := proxyFromAddr(t, socksAddr, "socks5")

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			_, _ = c.Write([]byte("SSH-2.0-OpenSSH_9.6\r\n"))
			time.Sleep(50 * time.Millisecond)
			_ = c.Close()
		}
	}()
	_, portStr, _ := net.SplitHostPort(ln.Addr().String())

	opts := Options{Ports: portStr, Concurrency: 4, Timeout: 3 * time.Second}
	results := make(chan Result, 4)
	go func() {
		_ = Scan(context.Background(), func() *proxy.Proxy { return prox }, "127.0.0.1", opts, results, nil)
		close(results)
	}()

	var found *Result
	for r := range results {
		if r.Open {
			rr := r
			found = &rr
		}
	}
	if found == nil {
		t.Fatal("expected an open port")
	}
	if found.Service != "ssh" || found.Version == "" {
		t.Fatalf("want ssh + version, got service=%q version=%q banner=%q",
			found.Service, found.Version, found.Banner)
	}
}
