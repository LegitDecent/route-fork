package cli

import (
	"bufio"
	"context"
	"fmt"
	"math/rand"
	"os"
	"os/exec"
	"os/signal"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"rofk/pool"
	"rofk/proxy"
	"rofk/relay"
	"rofk/scanner"
)

// flatArgs holds the rofk-specific flags extracted from the CLI.
// Everything not consumed here ends up in NmapExtra and is forwarded to nmap verbatim.
type flatArgs struct {
	proxList  string
	targets   []string // one or more host/IP/CIDR targets
	ports     string   // extracted from -p for rofk awareness; also forwarded to nmap
	outFile   string
	outType   string
	tool      string
	conc      int
	confirm   int // built-in scan: proxies that must agree a port is open (quorum)
	timeout   float64
	rotate    bool
	wrap      bool
	nmapPath  string
	nmapExtra []string // forwarded verbatim to nmap
}

// nmapValueFlags lists nmap flags that consume the following argument as their value.
// Used by the pass-through parser so "-oX /tmp/out.xml" is correctly forwarded as two tokens.
var nmapValueFlags = map[string]bool{
	"--script": true, "--script-args": true, "--script-timeout": true,
	"-oX": true, "-oN": true, "-oG": true, "-oA": true, "-oS": true,
	"--min-rate": true, "--max-rate": true,
	"--max-retries": true, "--host-timeout": true,
	"--scan-delay": true, "--max-scan-delay": true,
	"--min-parallelism": true, "--max-parallelism": true,
	"--min-hostgroup": true, "--max-hostgroup": true,
	"--min-rtt-timeout": true, "--max-rtt-timeout": true, "--initial-rtt-timeout": true,
	"--exclude": true, "--excludefile": true,
	"-iL": true, "-iR": true,
	"-e": true, "-S": true, "--source-port": true, "-g": true, "-D": true,
	"--proxies": true,
	"--data":    true, "--data-string": true, "--data-length": true,
	"--ip-options": true,
	"--ttl":        true, "--spoof-mac": true,
	"--port-ratio": true, "--top-ports": true,
	"--version-intensity": true,
}

func parseFlatArgs(args []string) flatArgs {
	fa := flatArgs{
		tool:    "builtin",
		conc:    200,
		confirm: 1,
		timeout: 5,
		rotate:  true,
		wrap:    true,
		outType: "txt",
	}

	i := 0
	for i < len(args) {
		arg := args[i]

		// helper: peek at next token
		nextVal := func() string {
			if i+1 < len(args) {
				return args[i+1]
			}
			return ""
		}
		consume := func() string {
			i++
			if i < len(args) {
				return args[i]
			}
			return ""
		}

		switch {
		// ── rofk-specific flags ────────────────────────────────────────
		case arg == "-proxlist" || arg == "--proxlist" || arg == "-pl" || arg == "--pl":
			fa.proxList = consume()

		case arg == "-ip" || arg == "--ip" || arg == "-target" || arg == "--target":
			fa.targets = append(fa.targets, consume())

		case arg == "-p" || arg == "--ports":
			// extracted for rofk rotation awareness; also forwarded to nmap
			val := nextVal()
			if val != "" && !strings.HasPrefix(val, "-") {
				fa.ports = val
				fa.nmapExtra = append(fa.nmapExtra, "-p", consume())
			} else {
				// bare -p with no value → forward as-is
				fa.nmapExtra = append(fa.nmapExtra, arg)
			}

		case arg == "-out" || arg == "--out":
			fa.outFile = consume()

		case arg == "-type" || arg == "--type":
			fa.outType = consume()

		case arg == "-tool" || arg == "--tool":
			fa.tool = consume()

		case arg == "-conc" || arg == "--conc":
			fa.conc, _ = strconv.Atoi(consume())

		case arg == "-confirm" || arg == "--confirm":
			fa.confirm, _ = strconv.Atoi(consume())

		case arg == "-timeout" || arg == "--timeout":
			fa.timeout, _ = strconv.ParseFloat(consume(), 64)

		case arg == "-nmap-path" || arg == "--nmap-path":
			fa.nmapPath = consume()

		case arg == "-rotate" || arg == "--rotate":
			fa.rotate = true
		case arg == "-no-rotate" || arg == "--no-rotate":
			fa.rotate = false

		case arg == "-wrap" || arg == "--wrap":
			fa.wrap = true
		case arg == "-no-wrap" || arg == "--no-wrap":
			fa.wrap = false

		// ── positional → target ────────────────────────────────────────────
		case !strings.HasPrefix(arg, "-"):
			fa.targets = append(fa.targets, arg)

		// ── nmap pass-through ──────────────────────────────────────────────
		default:
			fa.nmapExtra = append(fa.nmapExtra, arg)
			if nmapValueFlags[arg] {
				if v := nextVal(); v != "" {
					fa.nmapExtra = append(fa.nmapExtra, consume())
				}
			}
		}
		i++
	}
	return fa
}

// RunFlatMode is the primary CLI entry point for the nmap-style interface.
func RunFlatMode(args []string) {
	// early help intercept
	for _, a := range args {
		if a == "--help" || a == "-h" || a == "-help" {
			PrintUsage()
			return
		}
	}

	fa := parseFlatArgs(args)

	if fa.proxList == "" {
		fmt.Fprintln(os.Stderr, "error: -proxlist <file> is required")
		fmt.Fprintln(os.Stderr, "Run: rofk help")
		os.Exit(1)
	}
	if len(fa.targets) == 0 {
		fmt.Fprintln(os.Stderr, "error: no target specified (use -ip <host> or pass as positional arg)")
		os.Exit(1)
	}

	// persist custom nmap path if given
	if fa.nmapPath != "" {
		if err := SetConfigKey("nmap_path", fa.nmapPath); err != nil {
			fmt.Fprintln(os.Stderr, "[!] Could not save nmap path:", err)
		}
	}

	nmapBin, nmapFound := FindNmap(fa.nmapPath)
	if strings.ToLower(fa.tool) == "nmap" && !nmapFound {
		fmt.Fprint(os.Stderr, nmapMissingMsg(fa.nmapPath))
		os.Exit(1)
	}
	if strings.ToLower(fa.tool) == "nmap" {
		for _, t := range fa.targets {
			if strings.Contains(t, "/") {
				fmt.Fprint(os.Stderr, "[!] WARNING: nmap on a CIDR runs real nmap through a SOCKS relay. "+
					"nmap's --proxies can silently fall back to a DIRECT connection if a proxy fails, "+
					"leaking this box's IP (your VPN exit, if any) to some targets. This is nmap behaviour, "+
					"not rofk's. Use -tool builtin for leak-safe, always-proxied scanning.\n")
				break
			}
		}
	}

	// load proxies
	pl := loadPool(fa.proxList)
	fmt.Fprintf(os.Stderr, "[*] Pool: %d proxies  target(s): %s\n",
		pl.ValidCount(), strings.Join(fa.targets, ", "))

	// signal handling
	ctx, cancel := context.WithCancel(context.Background())
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	go func() { <-sig; fmt.Fprintln(os.Stderr, "\n[!] Interrupted"); cancel() }()
	defer cancel()

	to := time.Duration(float64(time.Second) * fa.timeout)
	var allResults []ScanResult

	for _, target := range fa.targets {
		if ctx.Err() != nil {
			break // interrupted; stop processing further targets
		}

		px := pl.Next(fa.wrap)
		if px == nil {
			fmt.Fprintln(os.Stderr, "[-] Proxy pool exhausted")
			break
		}

		switch strings.ToLower(fa.tool) {
		case "nmap":
			r := flatRunNmap(ctx, px, target, fa.nmapExtra, nmapBin, to)
			allResults = append(allResults, r...)
		default:
			ports := fa.ports
			if ports == "" {
				ports = "1-1024"
			}
			r := flatRunBuiltin(ctx, pl, target, ports, fa.confirm, fa.conc, to)
			allResults = append(allResults, r...)
		}

		if fa.rotate {
			pl.Advance()
		}
	}

	// ── summary ──────────────────────────────────────────────────────────────
	fmt.Fprintf(os.Stderr, "\n[=] %d open port(s) found across %d target(s)\n",
		len(allResults), len(fa.targets))

	// ── output file ──────────────────────────────────────────────────────────
	if fa.outFile != "" {
		if err := writeOutputFile(fa.outFile, fa.outType, allResults); err != nil {
			fmt.Fprintln(os.Stderr, "[-] output:", err)
		} else {
			fmt.Fprintf(os.Stderr, "[+] Saved to %s (%s)\n", fa.outFile, fa.outType)
		}
	}
}

func writeOutputFile(path, format string, results []ScanResult) error {
	// "-" is the Unix convention for stdout.
	if path == "-" {
		return WriteResults(os.Stdout, results, format)
	}
	f, err := os.Create(path) //#nosec G304 -- path is the operator-supplied output file
	if err != nil {
		return err
	}
	defer f.Close()
	return WriteResults(f, results, format)
}

// ── nmap runner ───────────────────────────────────────────────────────────────

func flatRunNmap(ctx context.Context, px *proxy.Proxy, target string,
	nmapExtra []string, nmapBin string, to time.Duration) []ScanResult {

	proxyArg, stop, err := relay.NmapProxyArg(px, to)
	if err != nil {
		fmt.Fprintln(os.Stderr, "[-] relay:", err)
		return nil
	}
	defer stop()

	fmt.Fprintf(os.Stderr, "[*] nmap  %s  relay:%s → %s\n", target, proxyArg, px.URI())

	cmd := buildFlatNmapCmd(nmapBin, proxyArg, target, nmapExtra, true)
	results, hostDown := execFlatNmap(ctx, cmd, px.URI())
	fmt.Fprintf(os.Stderr, "[+] %d open port(s)\n", len(results))

	if len(results) == 0 {
		if hostDown {
			fmt.Fprintln(os.Stderr, "[!] Host seems down. Retrying with -Pn...")
		} else {
			fmt.Fprintln(os.Stderr, "[!] 0 open ports. Retrying with -Pn...")
		}
		cmd2 := buildFlatNmapCmd(nmapBin, proxyArg, target, nmapExtra, true)
		retry, _ := execFlatNmap(ctx, cmd2, px.URI())
		fmt.Fprintf(os.Stderr, "[+] Retry: %d open port(s)\n", len(retry))
		results = append(results, retry...)
	}

	return results
}

func buildFlatNmapCmd(bin, proxyArg, target string, extra []string, addPn bool) []string {
	args := []string{bin, "-sT", "--proxies=" + proxyArg, "--open"}
	hasPn := false
	for _, a := range extra {
		if a == "-Pn" || a == "-P0" {
			hasPn = true
		}
	}
	if addPn && !hasPn {
		args = append(args, "-Pn")
	}
	args = append(args, extra...)
	args = append(args, strings.Fields(target)...)
	return args
}

var (
	flatReportRE = regexp.MustCompile(`Nmap scan report for (\S+)`)
	flatOpenRE   = regexp.MustCompile(`(\d+)/(tcp|udp)\s+open`)
	flatDetailRE = regexp.MustCompile(`^(\d+)/(tcp|udp)\s+\S+\s*(\S*)\s*(.*)$`)
)

func execFlatNmap(ctx context.Context, cmd []string, proxyURI string) (results []ScanResult, hostDown bool) {
	fmt.Fprintln(os.Stderr, "  CMD:", strings.Join(cmd, " "))
	c := exec.CommandContext(ctx, cmd[0], cmd[1:]...) //#nosec G204 -- nmap argv is built from operator-supplied scan flags, run locally
	c.Stderr = os.Stderr
	stdout, err := c.StdoutPipe()
	if err != nil {
		fmt.Fprintln(os.Stderr, "[-] pipe:", err)
		return
	}
	if err := c.Start(); err != nil {
		fmt.Fprintln(os.Stderr, "[-] start:", err)
		return
	}

	var currentHost string
	sc := bufio.NewScanner(stdout)
	for sc.Scan() {
		line := sc.Text()
		if m := flatReportRE.FindStringSubmatch(line); m != nil {
			currentHost = m[1]
		}
		if flatOpenRE.MatchString(line) {
			// Live output to stderr; stdout is reserved for the result document.
			fmt.Fprintln(os.Stderr, "  ► OPEN ", line)
			var port int
			var proto, service, version string
			if m := flatDetailRE.FindStringSubmatch(strings.TrimSpace(line)); m != nil {
				port, _ = strconv.Atoi(m[1])
				proto = m[2]
				service = m[3]
				version = strings.TrimSpace(m[4])
			}
			results = append(results, ScanResult{
				Host:    currentHost,
				Port:    port,
				Proto:   proto,
				Service: service,
				Version: version,
				Proxy:   proxyURI,
			})
		} else {
			fmt.Fprintln(os.Stderr, "  ", line)
		}
		if strings.Contains(line, "Host seems down") {
			hostDown = true
		}
	}
	c.Wait()
	return
}

// ── built-in runner ───────────────────────────────────────────────────────────

func flatRunBuiltin(ctx context.Context, pl *pool.Pool, target, ports string,
	confirm, conc int, to time.Duration) []ScanResult {

	parsed, err := scanner.ParsePorts(ports)
	if err != nil || len(parsed) == 0 {
		fmt.Fprintln(os.Stderr, "[-] bad port spec:", err)
		return nil
	}
	if confirm < 1 {
		confirm = 1
	}
	fmt.Fprintf(os.Stderr, "[*] Built-in scan  %s  ports:%s  (need %d proxy/proxies to agree open)\n",
		target, ports, confirm)

	// Live "open" lines go to stderr so stdout stays a clean machine-readable
	// document when -out - streams JSON/XML/CSV to stdout for piping.
	printOpen := func(host string, port int, svc, ver, banner string) {
		if svc == "" {
			svc = "unknown"
		}
		line := fmt.Sprintf("  ► OPEN  %s:%d  [%s]", host, port, svc)
		if ver != "" {
			line += "  " + ver
		}
		if banner != "" {
			line += "  " + banner
		}
		fmt.Fprintln(os.Stderr, line)
	}

	var deadMu sync.Mutex
	dead := map[string]bool{}

	// Same Go-native rotating scanner the GUI uses: always proxied, quorum-
	// confirmed, dead proxies pruned. No nmap, no direct fallback.
	hostResults := scanner.RunScan(ctx, scanner.DialThroughProxyCtx,
		func() []*proxy.Proxy { return pl.Valid() },
		scanner.ScanRequest{
			Targets:     []string{target},
			Ports:       parsed,
			Quorum:      confirm,
			Concurrency: conc,
			Timeout:     to,
			Label:       func(p *proxy.Proxy) string { return p.URI() },
			Shuffle:     func(ps []*proxy.Proxy) { rand.Shuffle(len(ps), func(i, j int) { ps[i], ps[j] = ps[j], ps[i] }) }, //#nosec G404 -- non-cryptographic proxy rotation
		},
		scanner.ScanHooks{
			Progress: func(done, total int) {
				if total > 0 && (done%5000 == 0 || done == total) {
					fmt.Fprintf(os.Stderr, "\r[*] %d/%d  (%.0f%%)", done, total, float64(done)/float64(total)*100)
				}
			},
			Outcome: func(oc scanner.PortOutcome) {
				if oc.Verdict == scanner.QuorumOpen {
					printOpen(oc.Host, oc.Port, oc.Service, oc.Version, oc.Banner)
				}
			},
			ProxyDead: func(p *proxy.Proxy) {
				deadMu.Lock()
				dead[p.Address()] = true
				deadMu.Unlock()
			},
		})
	fmt.Fprintln(os.Stderr)

	// Prune proxy-side-dead proxies once (race-free).
	if len(dead) > 0 {
		var survivors []*proxy.Proxy
		for _, p := range pl.Valid() {
			if !dead[p.Address()] {
				survivors = append(survivors, p)
			}
		}
		pl.SetValid(survivors)
		fmt.Fprintf(os.Stderr, "[=] Pruned %d dead proxy/proxies (%d left)\n", len(dead), len(survivors))
	}

	var results []ScanResult
	for _, hr := range hostResults {
		for _, f := range hr.Findings {
			svc := f.Service
			if svc == "" {
				svc = scanner.PortService(f.Port)
			}
			if svc == "" {
				svc = "unknown"
			}
			results = append(results, ScanResult{
				Host:    f.Host,
				Port:    f.Port,
				Proto:   f.Proto,
				Service: svc,
				Version: f.Version,
				Banner:  f.Banner,
				Proxy:   f.Primary,
			})
		}
	}
	return results
}

// ── usage / man ───────────────────────────────────────────────────────────────

const flatUsage = `SOCKS Proxy Manager

USAGE
  rofk -proxlist <file> -ip <target> [options] [nmap-flags...]
  rofk validate [flags]
  rofk scan     [flags]
  rofk man
  rofk help

PROXY-MANAGER FLAGS
  -proxlist <file>     Proxy list file (socks4/5://host:port, one per line)
  -ip <host>           Target host, IP, or CIDR  (also accepted as positional)
  -p <ports>           Port spec: "80,443"  "1-1024"  (scanner; forwarded to nmap with -tool nmap)
  -out <file>          Output file path; use "-" for stdout
  -type <fmt>          Output format: txt | json | xml | csv  (default: txt)
  -tool <name>         Scanner: builtin | nmap  (default: builtin; nmap warns on CIDR)
  -confirm <N>         Built-in quorum: proxies that must agree open  (default: 1)
  -conc <N>            Concurrency for builtin scanner  (default: 200)
  -timeout <sec>       Connect timeout  (default: 5)
  -rotate              Rotate proxy between targets  (default: on)
  -no-rotate           Disable rotation
  -wrap                Wrap pool when exhausted  (default: on)
  -nmap-path <path>    Path to nmap binary (saved to config)

THE BUILT-IN SCANNER (default) is always proxied with no fallback, and detects
services/versions (banners, an HTTP probe, and a TLS handshake on TLS ports).

NMAP (opt-in, -tool nmap) is for version detection / NSE on ranges. WARNING: on
a CIDR, nmap runs through a SOCKS relay whose --proxies can silently fall back to
a DIRECT connection if a proxy fails, leaking this host's IP. nmap cannot avoid
this; rofk warns and recommends the built-in scanner.

NMAP PASS-THROUGH
  Any flag not listed above is forwarded to nmap unchanged (used only with -tool nmap).
  Examples: -sV  -sC  -A  -O  -T4  -Pn  --script=vuln  -oX /tmp/out.xml

EXAMPLES
  rofk -proxlist ~/proxies.txt -ip 192.168.1.2 -p 80,443
  rofk -proxlist ~/proxies.txt -ip target.com -p 1-1024 -confirm 2
  rofk -proxlist ~/proxies.txt -ip 10.0.0.0/24 -p 1-1024 -tool nmap -sV
  rofk -proxlist ~/proxies.txt -ip target.com -type json -out results.json

NMAP DETECTION
  nmap must be installed separately.  Install it:
    macOS:    brew install nmap
    Debian:   apt install nmap
    Fedora:   dnf install nmap
    Windows:  winget install nmap

  If nmap is in a non-standard location:
    rofk -nmap-path /opt/nmap/bin/nmap ...
  The path is saved to ~/.config/rofk/config for future runs.

MAN PAGE
  rofk man            Print man page to stdout
  man rofk            After running: make install-man

LEGACY SUB-COMMANDS (still work)
  rofk validate -f proxies.txt -o valid.txt
  rofk scan     -pool valid.txt -target host -tool nmap
`

// PrintUsage prints the full usage to stdout.
func PrintUsage() {
	fmt.Print(flatUsage)
}

// PrintManPage writes the man page to stdout (pipe through man -l - to render).
func PrintManPage() {
	fmt.Print(manPageContent)
}

func nmapMissingMsg(tried string) string {
	var sb strings.Builder
	sb.WriteString("\nNmap is required but was not found")
	if tried != "" {
		fmt.Fprintf(&sb, " at %q", tried)
	}
	sb.WriteString(".\n\n")
	sb.WriteString("Install it from https://nmap.org or your package manager:\n")
	sb.WriteString("  macOS:    brew install nmap\n")
	sb.WriteString("  Debian:   apt install nmap\n")
	sb.WriteString("  Fedora:   dnf install nmap\n")
	sb.WriteString("  Windows:  winget install nmap  (or nmap.org installer)\n\n")
	sb.WriteString("Or specify the binary path:\n")
	sb.WriteString("  rofk -nmap-path /path/to/nmap ...\n\n")
	return sb.String()
}
