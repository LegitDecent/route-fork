package cli

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"regexp"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"rofk/pool"
	"rofk/proxy"
	"rofk/relay"
	"rofk/scanner"
)

var openPortRE = regexp.MustCompile(`\d+/(tcp|udp)\s+open`)

const usage = `SOCKS Proxy Manager — CLI

Usage:
  rofk validate [flags]
  rofk scan     [flags]
  rofk help

Validate flags:
  -f  string   Input proxy file (default: stdin)
  -o  string   Output file for valid proxies (default: stdout)
  -t  int      Threads (default: 100)
  -T  float    Timeout seconds (default: 10)
  -H  string   Test host (default: www.google.com)
  -P  int      Test port (default: 80)

Scan flags:
  -pool    string  Proxy pool file (required)
  -target  string  Target host/IP (required)
  -ports   string  Port spec: "1-1024", "22,80,443", "1-65535" (default: 1-65535)
  -tool    string  builtin | nmap  (default: builtin)
  -conc    int     Concurrent dials — builtin only (default: 200)
  -T       float   Dial/connect timeout seconds (default: 5)
  -extra   string  Extra args appended to nmap command
  -rotate         Rotate proxy after each target (default: true)
  -wrap           Wrap pool when exhausted (default: true)

nmap is routed through a local SOCKS4->SOCKS5 relay — no proxychains needed.
nmap must be installed: brew install nmap  /  apt install nmap  /  winget install nmap
`

func Run(args []string) {
	if len(args) == 0 {
		fmt.Print(usage)
		return
	}
	switch args[0] {
	case "validate":
		runValidate(args[1:])
	case "scan":
		runScan(args[1:])
	default:
		fmt.Print(usage)
	}
}

// RunValidate is the exported entry point for the validate subcommand.
func RunValidate(args []string) { runValidate(args) }

// RunScan is the exported entry point for the scan subcommand.
func RunScan(args []string) { runScan(args) }

// ── validate ──────────────────────────────────────────────────────────────────

func runValidate(args []string) {
	fs := flag.NewFlagSet("validate", flag.ExitOnError)
	inFile   := fs.String("f", "", "input proxy file (default stdin)")
	outFile  := fs.String("o", "", "output valid proxies (default stdout)")
	threads  := fs.Int("t", 100, "concurrent threads")
	timeout  := fs.Float64("T", 10, "timeout seconds")
	testHost := fs.String("H", "www.google.com", "test host")
	testPort := fs.Int("P", 80, "test port")
	fs.Parse(args)

	text := readText(*inFile)
	proxies := proxy.ParseAll(text)
	if len(proxies) == 0 {
		fmt.Fprintln(os.Stderr, "no proxies parsed from input")
		os.Exit(1)
	}
	fmt.Fprintf(os.Stderr, "[*] Validating %d proxies (threads=%d, timeout=%.0fs)\n",
		len(proxies), *threads, *timeout)

	out := os.Stdout
	if *outFile != "" {
		f, err := os.Create(*outFile)
		if err != nil {
			fmt.Fprintln(os.Stderr, "create:", err)
			os.Exit(1)
		}
		defer f.Close()
		out = f
	}

	var mu sync.Mutex
	var validProxies []*proxy.Proxy
	var valid, failed atomic.Int64
	sem := make(chan struct{}, *threads)
	var wg sync.WaitGroup
	to := time.Duration(float64(time.Second) * *timeout)

	for _, p := range proxies {
		sem <- struct{}{}
		wg.Add(1)
		go func(p *proxy.Proxy) {
			defer wg.Done()
			defer func() { <-sem }()
			ok, ms, errStr := proxy.Validate(p, to, *testHost, *testPort)
			if ok {
				p.LatencyMs = ms
				_, _ = proxy.FetchEgressIP(p, to)
				valid.Add(1)
				mu.Lock()
				fmt.Fprintln(out, p.URI())
				validProxies = append(validProxies, p)
				mu.Unlock()
				egStr := ""
				if p.EgressIP != "" {
					egStr = "  egress:" + p.EgressIP
				}
				fmt.Fprintf(os.Stderr, "[+] %-26s  %.0f ms%s\n", p.Address(), ms, egStr)
			} else {
				failed.Add(1)
				fmt.Fprintf(os.Stderr, "[-] %-26s  %s\n", p.Address(), errStr)
			}
		}(p)
	}
	wg.Wait()
	fmt.Fprintf(os.Stderr, "[=] Done: %d valid, %d failed\n", valid.Load(), failed.Load())
	printEgressSummary(validProxies)
}

// printEgressSummary prints a warning when multiple valid proxies share the same egress IP.
func printEgressSummary(proxies []*proxy.Proxy) {
	byEgress := make(map[string]int)
	for _, p := range proxies {
		if p.EgressIP != "" {
			byEgress[p.EgressIP]++
		}
	}
	if len(byEgress) == 0 {
		return
	}
	fmt.Fprintf(os.Stderr, "[=] Unique egress IPs: %d\n", len(byEgress))

	var dupeIPs []string
	for ip, count := range byEgress {
		if count > 1 {
			dupeIPs = append(dupeIPs, ip)
		}
	}
	if len(dupeIPs) == 0 {
		return
	}
	sort.Strings(dupeIPs)
	fmt.Fprintf(os.Stderr, "[!] %d egress IP(s) shared by multiple proxies — these are redundant:\n", len(dupeIPs))
	for _, ip := range dupeIPs {
		fmt.Fprintf(os.Stderr, "    %s  (%d proxies)\n", ip, byEgress[ip])
	}
	fmt.Fprintln(os.Stderr, "[!] Consider removing duplicates — they provide no additional anonymity.")
}

// ── scan ──────────────────────────────────────────────────────────────────────

func runScan(args []string) {
	fs := flag.NewFlagSet("scan", flag.ExitOnError)
	poolFile := fs.String("pool", "", "proxy pool file (required)")
	target   := fs.String("target", "", "target host/IP (required)")
	ports    := fs.String("ports", "1-65535", "port spec")
	tool     := fs.String("tool", "builtin", "builtin | nmap")
	conc     := fs.Int("conc", 200, "concurrent dials (builtin only)")
	timeout  := fs.Float64("T", 5, "timeout seconds")
	extra    := fs.String("extra", "", "extra nmap args")
	rotate   := fs.Bool("rotate", true, "rotate proxy per scan")
	wrap     := fs.Bool("wrap", true, "wrap pool when exhausted")
	fs.Parse(args)

	if *poolFile == "" || *target == "" {
		fmt.Fprintln(os.Stderr, "error: -pool and -target are required")
		fmt.Print(usage)
		os.Exit(1)
	}

	pl := loadPool(*poolFile)
	fmt.Fprintf(os.Stderr, "[*] Pool: %d proxies\n", pl.ValidCount())

	ctx, cancel := context.WithCancel(context.Background())
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sig
		fmt.Fprintln(os.Stderr, "\n[!] Interrupted")
		cancel()
	}()
	defer cancel()

	px := pl.Next(*wrap)
	if px == nil {
		fmt.Fprintln(os.Stderr, "pool empty")
		os.Exit(1)
	}

	to := time.Duration(float64(time.Second) * *timeout)

	switch strings.ToLower(*tool) {
	case "nmap":
		runNmap(ctx, px, *target, *ports, *extra, to)
	default:
		runBuiltin(ctx, px, *target, *ports, *conc, to)
	}

	if *rotate {
		pl.Advance()
	}
}

// runBuiltin performs a TCP-connect scan through the proxy in pure Go.
func runBuiltin(ctx context.Context, px *proxy.Proxy, target, ports string,
	conc int, timeout time.Duration) {

	fmt.Fprintf(os.Stderr, "[*] Built-in scan: %s:%s via %s\n", target, ports, px.URI())
	opts := scanner.Options{Ports: ports, Concurrency: conc, Timeout: timeout}
	results := make(chan scanner.Result, 256)

	go func() {
		err := scanner.Scan(ctx, func() *proxy.Proxy { return px }, target, opts, results,
			func(scanned, total int) {
				if scanned%2000 == 0 || scanned == total {
					fmt.Fprintf(os.Stderr, "\r[*] %d/%d ports", scanned, total)
				}
			})
		close(results)
		if err != nil && err != context.Canceled {
			fmt.Fprintln(os.Stderr, "\n[-] Scan error:", err)
		}
	}()

	var open int
	for r := range results {
		if r.Open {
			open++
			fmt.Printf("%s:%d\n", r.Host, r.Port)
		}
	}
	fmt.Fprintf(os.Stderr, "\n[+] Done — %d open ports\n", open)
}

const commonPortSpec = "21,22,23,25,53,80,110,111,135,139,143,443,445,993,995," +
	"1723,3306,3389,5900,8080,8443,8888"

func mergeCommonPorts(spec string) string {
	s := strings.TrimSpace(spec)
	if s == "1-65535" || s == "0-65535" {
		return s
	}
	return scanner.MergePortSpecs(s, commonPortSpec)
}

// runNmap starts the local relay then runs nmap with automatic -Pn retry on 0 results.
func runNmap(ctx context.Context, px *proxy.Proxy, target, ports, extra string,
	timeout time.Duration) {

	proxyArg, stop, err := relay.NmapProxyArg(px, timeout)
	if err != nil {
		fmt.Fprintln(os.Stderr, "[-] relay:", err)
		return
	}
	defer stop()

	fmt.Fprintf(os.Stderr, "[*] nmap scan  %s  ports:%s  relay:%s → %s\n",
		target, ports, proxyArg, px.URI())

	open, hostDown := execNmapParsed(ctx, buildNmapArgv(ports, extra, proxyArg, target, false))

	fmt.Fprintf(os.Stderr, "[+] %d open port(s) on %s\n", open, target)

	if open == 0 {
		if hostDown {
			fmt.Fprintln(os.Stderr, "[!] nmap reports host seems down (blocking ping).")
		} else {
			fmt.Fprintln(os.Stderr, "[!] 0 open ports on initial scan.")
		}
		retryPorts := mergeCommonPorts(ports)
		fmt.Fprintln(os.Stderr, "[*] Retrying with -Pn + common ports...")
		open2, _ := execNmapParsed(ctx, buildNmapArgv(retryPorts, extra, proxyArg, target, true))
		fmt.Fprintf(os.Stderr, "[+] Retry: %d open port(s) on %s\n", open2, target)
		if open2 == 0 {
			fmt.Fprintln(os.Stderr, "[!] Still 0. Host may be down or all ports filtered.")
		}
	}
}

func buildNmapArgv(ports, extra, proxyArg, target string, addPn bool) []string {
	args := []string{"nmap", "-sT", "-p", ports,
		"--proxies=" + proxyArg, "--open", target}
	if addPn {
		args = append(args, "-Pn")
	}
	for _, a := range strings.Fields(extra) {
		if (a == "-Pn" || a == "-P0") && addPn {
			continue
		}
		args = append(args, a)
	}
	return args
}

// execNmapParsed runs nmap, prints open ports prominently, returns (openCount, hostDown).
func execNmapParsed(ctx context.Context, cmd []string) (openPorts int, hostDown bool) {
	fmt.Fprintln(os.Stderr, "  CMD:", strings.Join(cmd, " "))
	c := exec.CommandContext(ctx, cmd[0], cmd[1:]...)
	c.Stderr = os.Stderr

	stdout, err := c.StdoutPipe()
	if err != nil {
		fmt.Fprintln(os.Stderr, "[-] pipe:", err)
		return
	}
	if err := c.Start(); err != nil {
		fmt.Fprintln(os.Stderr, "[-] nmap start:", err)
		return
	}

	sc := bufio.NewScanner(stdout)
	for sc.Scan() {
		line := sc.Text()
		if openPortRE.MatchString(line) {
			openPorts++
			fmt.Println("  ► OPEN ", line)
		} else {
			fmt.Println("  ", line)
		}
		if strings.Contains(line, "Host seems down") {
			hostDown = true
		}
	}
	c.Wait()
	return
}

// ── helpers ───────────────────────────────────────────────────────────────────

func readText(path string) string {
	var sc *bufio.Scanner
	if path != "" {
		f, err := os.Open(path)
		if err != nil {
			fmt.Fprintln(os.Stderr, "open:", err)
			os.Exit(1)
		}
		defer f.Close()
		sc = bufio.NewScanner(f)
	} else {
		sc = bufio.NewScanner(os.Stdin)
	}
	var sb strings.Builder
	for sc.Scan() {
		sb.WriteString(sc.Text())
		sb.WriteByte('\n')
	}
	return sb.String()
}

func loadPool(path string) *pool.Pool {
	text := readText(path)
	pl := pool.New()
	for _, p := range proxy.ParseAll(text) {
		p.Status = proxy.StatusValid
		pl.AddValid(p)
	}
	if pl.ValidCount() == 0 {
		fmt.Fprintln(os.Stderr, "no proxies in pool file")
		os.Exit(1)
	}
	return pl
}
