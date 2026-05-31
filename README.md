# Route Fork

[![CI](https://github.com/LegitDecent/route-fork/actions/workflows/ci.yml/badge.svg)](https://github.com/LegitDecent/route-fork/actions/workflows/ci.yml)
[![CodeQL](https://github.com/LegitDecent/route-fork/actions/workflows/codeql.yml/badge.svg)](https://github.com/LegitDecent/route-fork/actions/workflows/codeql.yml)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/LegitDecent/route-fork/badge)](https://scorecard.dev/viewer/?uri=github.com/LegitDecent/route-fork)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)

> **Putting it plainly: this tool can take down servers if you use it like an idiot.**
> It routes scans through proxy pools and can overwhelm connection tracking, SNAT, or fragile services if misconfigured.
> **Use it only on systems you own or have explicit written permission to test. Don't be stupid.**

A SOCKS4/5 proxy-aware port scanner with a GUI and a full nmap-compatible CLI.
Routes nmap (or its own built-in TCP scanner) through rotating proxy pools, no proxychains required.

---

## Features

- **GUI** — proxy validator, scanner, Zenmap-style Hosts tab with drill-down, real-time log
- **CLI** — nmap-style flat interface; unknown flags pass straight through to nmap in nmap mode
- **Scan modes** — Fast / Confirmed / Paranoid: require 1, 2, or 3 proxies to independently
  agree a port is open, defeating proxies that fake a successful connection (false positives)
- **Service + banner detection** — common-port service names plus a live banner grab
  (SSH version, FTP/IMAP/POP3 greetings, etc.)
- **nmap integration** — local SOCKS4↔SOCKS5 relay so nmap works without proxychains
- **Built-in TCP scanner** — pure Go, zero dependencies, works when nmap isn't available
- **Self-healing pool** — dead proxies are retried-past and pruned mid-scan; optional
  auto-revalidation re-checks the pool on an interval
- **Proxy burn protection** (opt-in) — paces reuse of each proxy so a free SOCKS pool
  isn't hammered into rate-limits or bans mid-scan (protects *your* infrastructure)
- **Output formats** — txt, json, xml, csv (CLI `-out -` streams to stdout for piping)

---

## Install

Download the binary for your platform from the [Releases](../../releases) page.

### macOS
Apple Silicon (M1/M2/M3) → `rofk-macos-arm64`; Intel → `rofk-macos-amd64`.
```bash
chmod +x rofk-macos-arm64        # rofk-macos-amd64 on Intel
sudo mv rofk-macos-arm64 /usr/local/bin/rofk
```

### Linux
x86_64 → `rofk-linux-amd64`; arm64 → `rofk-linux-arm64`.
```bash
chmod +x rofk-linux-amd64        # rofk-linux-arm64 on ARM
sudo mv rofk-linux-amd64 /usr/local/bin/rofk
```

### Windows
Download `rofk-windows-amd64.exe`, rename to `rofk.exe`, add to `PATH`.

### Man page (optional)
```bash
sudo install -m644 docs/rofk.1 /usr/local/share/man/man1/
man rofk
```

---

## nmap

nmap is required for nmap mode. The built-in scanner works without it.

```
macOS:   brew install nmap
Linux:   apt install nmap  /  dnf install nmap
Windows: winget install nmap
```

If nmap is in a non-standard location, set the path once:
```bash
rofk -nmap-path /opt/nmap/bin/nmap -proxlist proxies.txt -ip target
```
The path is saved to `~/.config/rofk/config`.

---

## CLI Usage

```
rofk -proxlist <file> -ip <target> [options] [nmap-flags...]
```

| Flag | Description |
|------|-------------|
| `-proxlist file` | Proxy list (one per line: `socks5://host:port`, `host:port`, etc.) |
| `-ip host` | Target host, IP, or CIDR. Also accepted as a positional arg. |
| `-p ports` | Port spec: `80,443` or `1-1024`. Forwarded to nmap too. |
| `-out file` | Output file path; use `-` for stdout |
| `-type fmt` | `txt` (default) · `json` · `xml` · `csv` |
| `-tool name` | `nmap` (default) · `builtin` |
| `-timeout sec` | Connect timeout (default: 5) |
| `-rotate` / `-no-rotate` | Rotate proxy between targets (default: on) |
| `-nmap-path path` | Path to nmap binary (saved to config) |

**Any flag not listed above is forwarded to nmap unchanged** — `-sV`, `-A`, `-T4`, `--script`, `-oX`, etc.

### Examples

```bash
# Service version detection
rofk -proxlist ~/proxies.txt -ip 192.168.1.2 -p 80,443 -sV

# Authorized Nmap aggressive scan (-A), save JSON
rofk -proxlist ~/proxies.txt -ip 10.0.0.0/24 -p 1-1024 -T4 -A \
  -type json -out results.json

# NSE scripts + nmap XML output
rofk -proxlist proxies.txt -ip target.com -sV --script=vuln -oX nmap.xml

# Built-in scanner (no nmap needed)
rofk -proxlist proxies.txt -ip target.com -p 1-65535 -tool builtin
```

### Legacy subcommands (still work)

```bash
rofk validate -f raw.txt -o live.txt -t 200 -T 8
rofk scan -pool live.txt -target host -tool nmap
rofk man
rofk help
```

---

## GUI

Run with no arguments:
```bash
rofk
```

**Proxies tab** — paste or import proxy lists, validate concurrently, export live proxies.  
**Scanner tab** — configure target, ports (with an "add common ports" toggle), timing presets (T3/T4/T5), **Scan mode** (Fast/Confirmed/Paranoid open-port confirmation), and optional **proxy burn protection** (per-proxy reuse gap), with a real-time log.  
**Hosts tab** — Zenmap-style three-pane drill-down: pick a host → see its deduplicated open ports → click a port to list every proxy that validated it, with service, version, and banner.  
**Settings tab** — nmap path detection, validation settings, and auto-revalidation interval.

---

## Proxy formats

```
host:port
socks4://host:port
socks5://host:port
socks5://user:pass@host:port
host:port:user:pass
```

---

## Build from source

Requires [Go 1.25+](https://go.dev/dl/).

```bash
git clone https://github.com/LegitDecent/route-fork
cd route-fork
make install        # build + install binary + man page
# or
go build -o rofk .
```

---

## Development

```bash
go test ./...
```

Tests cover the SOCKS4/5 handshake and proxy-dial logic, the local relay
(forward path, SOCKS4a hostname handling, failure behaviour), the port
scanner (open/closed ports, per-connection proxy tracking, context
cancellation), the quorum decision and burn-protection throttle, the proxy
error classifier, and pool management. All tests use local mock servers and
need no external network access.

CI also runs [`govulncheck`](https://pkg.go.dev/golang.org/x/vuln/cmd/govulncheck)
on every push and pull request, so known vulnerabilities in dependencies are
caught automatically.

---

## Legal

This tool is for **authorised security testing only**.  
Scanning systems without explicit permission is illegal in most jurisdictions.  
You are responsible for your own use. The authors are not responsible for misuse.

---

## License

[Apache License 2.0](LICENSE). Provided "as is", without warranty of any kind;
see the Disclaimer of Warranty and Limitation of Liability sections of the license.
