// Package e2e holds subprocess end-to-end tests that build and run the real
// rofk binary against local mock services. These tests are deterministic and
// offline-only (everything binds 127.0.0.1:0); no external network is touched.
//
// They live outside the core packages so they never affect their coverage or
// import graph, and they exercise the shipped CLI exactly as a user would.
package e2e

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

const e2eTimeout = 90 * time.Second

// ── mock target ─────────────────────────────────────────────────────────────

// startMockTarget opens a TCP listener that accepts and immediately closes
// connections (an "open" port with no banner). Returns host, port, stop.
func startMockTarget(t *testing.T) (host string, port int, stop func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("mock target listen: %v", err)
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			_ = c.Close()
		}
	}()
	h, ps, _ := net.SplitHostPort(ln.Addr().String())
	p, _ := net.LookupPort("tcp", ps)
	return h, p, func() { _ = ln.Close() }
}

// ── recording mock SOCKS5 proxy ─────────────────────────────────────────────

// recordingSOCKS5 is a minimal SOCKS5 (no-auth) proxy that records every
// CONNECT target it is asked to reach, then forwards the stream to the real
// target. The recording is what lets the test prove the proxy path was used.
type recordingSOCKS5 struct {
	ln   net.Listener
	mu   sync.Mutex
	seen []string // "host:port" of each CONNECT request observed
}

func startRecordingSOCKS5(t *testing.T) *recordingSOCKS5 {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("mock socks listen: %v", err)
	}
	s := &recordingSOCKS5{ln: ln}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go s.serve(c)
		}
	}()
	return s
}

func (s *recordingSOCKS5) addr() string { return s.ln.Addr().String() }
func (s *recordingSOCKS5) stop()        { _ = s.ln.Close() }

// connects returns a copy of the CONNECT targets observed so far.
func (s *recordingSOCKS5) connects() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]string, len(s.seen))
	copy(out, s.seen)
	return out
}

func (s *recordingSOCKS5) sawConnectTo(hostPort string) bool {
	for _, c := range s.connects() {
		if c == hostPort {
			return true
		}
	}
	return false
}

func (s *recordingSOCKS5) serve(client net.Conn) {
	defer client.Close()
	_ = client.SetDeadline(time.Now().Add(10 * time.Second))

	// greeting: VER, NMETHODS, METHODS...
	hdr := make([]byte, 2)
	if _, err := io.ReadFull(client, hdr); err != nil || hdr[0] != 0x05 {
		return
	}
	methods := make([]byte, hdr[1])
	if _, err := io.ReadFull(client, methods); err != nil {
		return
	}
	if _, err := client.Write([]byte{0x05, 0x00}); err != nil { // no-auth
		return
	}

	// request: VER, CMD, RSV, ATYP, ADDR, PORT
	reqHdr := make([]byte, 4)
	if _, err := io.ReadFull(client, reqHdr); err != nil {
		return
	}
	var host string
	switch reqHdr[3] {
	case 0x01: // IPv4
		b := make([]byte, 4)
		if _, err := io.ReadFull(client, b); err != nil {
			return
		}
		host = net.IP(b).String()
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
		_, _ = client.Write([]byte{0x05, 0x08, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}
	portBuf := make([]byte, 2)
	if _, err := io.ReadFull(client, portBuf); err != nil {
		return
	}
	port := binary.BigEndian.Uint16(portBuf)

	// Record the CONNECT target. This is the proof of proxy use.
	s.mu.Lock()
	s.seen = append(s.seen, fmt.Sprintf("%s:%d", host, port))
	s.mu.Unlock()

	target, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", host, port), 3*time.Second)
	if err != nil {
		_, _ = client.Write([]byte{0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0}) // failure
		return
	}
	defer target.Close()

	if _, err := client.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0}); err != nil { // success
		return
	}
	_ = client.SetDeadline(time.Time{})

	done := make(chan struct{}, 2)
	go func() { _, _ = io.Copy(target, client); done <- struct{}{} }()
	go func() { _, _ = io.Copy(client, target); done <- struct{}{} }()
	<-done
}

// ── build the binary once per test binary run ───────────────────────────────

var (
	buildOnce sync.Once
	builtPath string
	buildErr  error
)

// rofkBinary builds the rofk binary into a temp dir (once) and returns its path.
func rofkBinary(t *testing.T) string {
	t.Helper()
	buildOnce.Do(func() {
		dir, err := os.MkdirTemp("", "rofk-e2e-*")
		if err != nil {
			buildErr = err
			return
		}
		bin := filepath.Join(dir, "rofk")
		// Module root is two levels up from test/e2e.
		repoRoot, err := filepath.Abs(filepath.Join("..", ".."))
		if err != nil {
			buildErr = err
			return
		}
		ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, "go", "build", "-o", bin, ".")
		cmd.Dir = repoRoot
		if out, err := cmd.CombinedOutput(); err != nil {
			buildErr = fmt.Errorf("go build failed: %v\n%s", err, out)
			return
		}
		builtPath = bin
	})
	if buildErr != nil {
		t.Fatalf("building rofk: %v", buildErr)
	}
	return builtPath
}

// runRofk runs the built binary with args, returns stdout, stderr, err.
func runRofk(t *testing.T, args ...string) (string, string, error) {
	t.Helper()
	bin := rofkBinary(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, bin, args...)
	var stdout, stderr []byte
	var wg sync.WaitGroup
	outPipe, _ := cmd.StdoutPipe()
	errPipe, _ := cmd.StderrPipe()
	if err := cmd.Start(); err != nil {
		t.Fatalf("starting rofk: %v", err)
	}
	wg.Add(2)
	go func() { defer wg.Done(); stdout, _ = io.ReadAll(outPipe) }()
	go func() { defer wg.Done(); stderr, _ = io.ReadAll(errPipe) }()
	wg.Wait()
	err := cmd.Wait()
	return string(stdout), string(stderr), err
}

// writeProxyList writes a one-line proxy file pointing at addr and returns its path.
func writeProxyList(t *testing.T, addr string) string {
	t.Helper()
	f := filepath.Join(t.TempDir(), "proxies.txt")
	if err := os.WriteFile(f, []byte("socks5://"+addr+"\n"), 0o600); err != nil {
		t.Fatalf("write proxy list: %v", err)
	}
	return f
}

// ── the E2E test ─────────────────────────────────────────────────────────────

func TestE2E_ScanThroughProxyEmitsJSON(t *testing.T) {
	if testing.Short() {
		t.Skip("e2e: skipped in -short mode")
	}
	deadline := time.Now().Add(e2eTimeout)
	defer func() {
		if time.Now().After(deadline) {
			t.Fatal("e2e exceeded overall timeout")
		}
	}()

	// 1. mock target (an open port) + 2. recording SOCKS5 proxy
	targetHost, targetPort, stopTarget := startMockTarget(t)
	defer stopTarget()
	prox := startRecordingSOCKS5(t)
	defer prox.stop()

	// 3. proxy list pointing at the mock proxy
	proxyList := writeProxyList(t, prox.addr())

	// 4./5. run the built binary: single host, the open port, JSON to stdout,
	//       confirm=1 (one proxy in the pool), built-in scanner.
	portArg := fmt.Sprintf("%d", targetPort)
	stdout, stderr, err := runRofk(t,
		"-proxlist", proxyList,
		"-ip", targetHost,
		"-p", portArg,
		"-tool", "builtin",
		"-confirm", "1",
		"-type", "json",
		"-out", "-",
	)
	if err != nil {
		t.Fatalf("rofk exited with error: %v\nstderr:\n%s", err, stderr)
	}

	// 6. assert JSON output contains the expected open host:port
	results := parseResults(t, stdout, stderr)
	if !hasOpen(results, targetHost, targetPort) {
		t.Fatalf("expected open %s:%d in JSON output, got: %+v\nstdout:\n%s\nstderr:\n%s",
			targetHost, targetPort, results, stdout, stderr)
	}

	// 7. assert the proxy actually saw a CONNECT to the target host:port.
	want := fmt.Sprintf("%s:%d", targetHost, targetPort)
	if !prox.sawConnectTo(want) {
		t.Fatalf("proxy path NOT used: mock SOCKS5 never saw CONNECT to %s; observed=%v",
			want, prox.connects())
	}
}

// TestE2E_DeadProxyYieldsNoOpen is the kill-switch: with the proxy pointed at a
// dead port (proxy path unusable), the SAME scan must report NO open port.
// This proves the open result in the test above depends on the proxy actually
// being used - rofk never falls back to a direct connection. If product code
// ever silently bypassed the proxy, this test would start finding the port open
// and fail.
func TestE2E_DeadProxyYieldsNoOpen(t *testing.T) {
	if testing.Short() {
		t.Skip("e2e: skipped in -short mode")
	}
	targetHost, targetPort, stopTarget := startMockTarget(t)
	defer stopTarget()

	// A SOCKS5 address that is NOT listening: grab a port, then close it.
	deadLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve dead port: %v", err)
	}
	deadAddr := deadLn.Addr().String()
	_ = deadLn.Close() // nothing listens here now

	proxyList := writeProxyList(t, deadAddr)

	stdout, stderr, _ := runRofk(t,
		"-proxlist", proxyList,
		"-ip", targetHost,
		"-p", fmt.Sprintf("%d", targetPort),
		"-tool", "builtin",
		"-confirm", "1",
		"-type", "json",
		"-out", "-",
	)
	results := parseResults(t, stdout, stderr)
	if hasOpen(results, targetHost, targetPort) {
		t.Fatalf("port reported OPEN with a dead proxy - rofk bypassed the proxy path "+
			"(direct-connection leak). results=%+v\nstdout:\n%s", results, stdout)
	}
}

// ── helpers ──────────────────────────────────────────────────────────────────

// result mirrors the fields of cli.ScanResult we assert on. The CLI only emits
// a record for an OPEN port, so presence in the array means open.
type result struct {
	Host  string `json:"host"`
	Port  int    `json:"port"`
	Proxy string `json:"proxy"`
}

// parseResults extracts the JSON array from stdout. rofk writes only the JSON
// document to stdout (logs go to stderr), so stdout should be a clean array.
func parseResults(t *testing.T, stdout, stderr string) []result {
	t.Helper()
	trimmed := stdout
	// Be tolerant of an empty stdout (no findings -> "null" or "[]" or empty).
	if len(trimmed) == 0 {
		return nil
	}
	var rs []result
	if err := json.Unmarshal([]byte(trimmed), &rs); err != nil {
		// An empty/`null` document is valid "no results", not a failure.
		if trimmed == "null\n" || trimmed == "null" {
			return nil
		}
		t.Fatalf("stdout is not valid JSON array: %v\nstdout:\n%q\nstderr:\n%s", err, stdout, stderr)
	}
	return rs
}

func hasOpen(results []result, host string, port int) bool {
	for _, r := range results {
		if r.Port == port && (r.Host == host || r.Host == "") {
			return true
		}
	}
	return false
}
