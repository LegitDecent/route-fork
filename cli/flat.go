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
	"syscall"
	"time"

	"proxymgr/pool"
	"proxymgr/proxy"
	"proxymgr/relay"
	"proxymgr/scanner"
)

// flatArgs holds the proxy-manager-specific flags extracted from the CLI.
// Everything not consumed here ends up in NmapExtra and is forwarded to nmap verbatim.
type flatArgs struct {
	proxList  string
	targets   []string // one or more host/IP/CIDR targets
	ports     string   // extracted from -p for proxymgr awareness; also forwarded to nmap
	outFile   string
	outType   string
	tool      string
	conc      int
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
	"--data": true, "--data-string": true, "--data-length": true,
	"--ip-options": true,
	"--ttl": true, "--spoof-mac": true,
	"--port-ratio": true, "--top-ports": true,
	"--version-intensity": true,
}

func parseFlatArgs(args []string) flatArgs {
	fa := flatArgs{
		tool:    "nmap",
		conc:    200,
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
		// ── proxymgr-specific flags ────────────────────────────────────────
		case arg == "-proxlist" || arg == "--proxlist" || arg == "-pl" || arg == "--pl":
			fa.proxList = consume()

		case arg == "-ip" || arg == "--ip" || arg == "-target" || arg == "--target":
			fa.targets = append(fa.targets, consume())

		case arg == "-p" || arg == "--ports":
			// extracted for proxymgr rotation awareness; also forwarded to nmap
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
		fmt.Fprintln(os.Stderr, "Run: proxy-manager help")
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
		select {
		case <-ctx.Done():
			break
		default:
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
			r := flatRunBuiltin(ctx, pl, target, ports, fa.conc, to, fa.wrap)
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
	f, err := os.Create(path)
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

	cmd := buildFlatNmapCmd(nmapBin, proxyArg, target, nmapExtra, false)
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
	c := exec.CommandContext(ctx, cmd[0], cmd[1:]...)
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
			fmt.Println("  ► OPEN ", line)
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
			fmt.Println("  ", line)
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
	conc int, to time.Duration, wrap bool) []ScanResult {

	fmt.Fprintf(os.Stderr, "[*] Built-in scan  %s  ports:%s\n", target, ports)
	opts := scanner.Options{Ports: ports, Concurrency: conc, Timeout: to}
	resCh := make(chan scanner.Result, 256)

	snap := pl.Valid()
	getProxy := func() *proxy.Proxy {
		if len(snap) == 0 {
			return pl.Next(wrap)
		}
		return snap[rand.Intn(len(snap))]
	}

	go func() {
		err := scanner.Scan(ctx, getProxy, target, opts, resCh,
			func(scanned, total int) {
				if total > 0 && (scanned%5000 == 0 || scanned == total) {
					fmt.Fprintf(os.Stderr, "\r[*] %d/%d  (%.0f%%)",
						scanned, total, float64(scanned)/float64(total)*100)
				}
			})
		close(resCh)
		if err != nil && err != context.Canceled {
			fmt.Fprintln(os.Stderr, "\n[-] scan error:", err)
		}
	}()

	var results []ScanResult
	for r := range resCh {
		if r.Open {
			fmt.Printf("  ► OPEN  %s:%d\n", r.Host, r.Port)
			results = append(results, ScanResult{Host: r.Host, Port: r.Port, Proto: "tcp"})
		}
	}
	fmt.Fprintln(os.Stderr)
	return results
}

// ── usage / man ───────────────────────────────────────────────────────────────

const flatUsage = `SOCKS Proxy Manager

USAGE
  proxy-manager -proxlist <file> -ip <target> [options] [nmap-flags...]
  proxy-manager validate [flags]
  proxy-manager scan     [flags]
  proxy-manager man
  proxy-manager help

PROXY-MANAGER FLAGS
  -proxlist <file>     Proxy list file (socks4/5://host:port, one per line)
  -ip <host>           Target host, IP, or CIDR  (also accepted as positional)
  -p <ports>           Port spec: "80,443"  "1-1024"  (forwarded to nmap too)
  -out <file>          Output file path
  -type <fmt>          Output format: txt | json | xml | csv  (default: txt)
  -tool <name>         Scanner: nmap | builtin  (default: nmap)
  -conc <N>            Concurrency for builtin scanner  (default: 200)
  -timeout <sec>       Connect timeout  (default: 5)
  -rotate              Rotate proxy between targets  (default: on)
  -no-rotate           Disable rotation
  -wrap                Wrap pool when exhausted  (default: on)
  -nmap-path <path>    Path to nmap binary (saved to config)

NMAP PASS-THROUGH
  Any flag not listed above is forwarded to nmap unchanged.
  Examples: -sV  -sC  -A  -O  -T4  -Pn  --script=vuln  -oX /tmp/out.xml

EXAMPLES
  proxy-manager -proxlist ~/proxies.txt -ip 192.168.1.2 -p 80,443 -sV
  proxy-manager -proxlist ~/proxies.txt -ip 10.0.0.0/24 -p 1-1024 -T4 -A
  proxy-manager -proxlist ~/proxies.txt -ip target.com -type json -out results.json -sV
  proxy-manager -proxlist ~/proxies.txt -ip target.com -- -sV --script vuln

NMAP DETECTION
  nmap must be installed separately.  Install it:
    macOS:    brew install nmap
    Debian:   apt install nmap
    Fedora:   dnf install nmap
    Windows:  winget install nmap

  If nmap is in a non-standard location:
    proxy-manager -nmap-path /opt/nmap/bin/nmap ...
  The path is saved to ~/.config/proxymgr/config for future runs.

MAN PAGE
  proxy-manager man            Print man page to stdout
  man proxy-manager            After running: make install-man

LEGACY SUB-COMMANDS (still work)
  proxy-manager validate -f proxies.txt -o valid.txt
  proxy-manager scan     -pool valid.txt -target host -tool nmap
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
	sb.WriteString("  proxy-manager -nmap-path /path/to/nmap ...\n\n")
	return sb.String()
}
