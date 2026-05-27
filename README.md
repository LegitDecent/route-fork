# proxy-manager

> **Putting it plainly: this tool can MANAGE to take down servers.**
> It routes scans through proxy pools and can slow loris, overwhelm SNAT, and generate DoS-level traffic if misused.
> **Use it only on systems you own or have explicit written permission to test. Don't be a moron.**

A SOCKS4/5 proxy-aware port scanner with a GUI and a full nmap-compatible CLI.
Routes nmap (or its own built-in TCP scanner) through rotating proxy pools — no proxychains, no wrappers.

---

## Features

- **GUI** — proxy validator, scanner, Zenmap-style Hosts tab, real-time log
- **CLI** — nmap-style flat interface; every flag you don't recognise passes straight through to nmap
- **nmap integration** — local SOCKS4↔SOCKS5 relay so nmap works without proxychains
- **Built-in TCP scanner** — pure Go, zero dependencies, works when nmap isn't available
- **Proxy rotation** — per-scan, per-port, or parallel chunk rotation across the pool
- **Output formats** — txt, json, xml, csv

---

## Install

Download the binary for your platform from the [Releases](../../releases) page.

### macOS (M1/M2/M3 + Intel via Rosetta 2)
```bash
chmod +x proxy-manager-macos-arm64
sudo mv proxy-manager-macos-arm64 /usr/local/bin/proxy-manager
```

### Linux
```bash
chmod +x proxy-manager-linux-amd64
sudo mv proxy-manager-linux-amd64 /usr/local/bin/proxy-manager
```

### Windows
Download `proxy-manager-windows-amd64.exe`, rename to `proxy-manager.exe`, add to `PATH`.

### Man page (optional)
```bash
sudo install -m644 docs/proxy-manager.1 /usr/local/share/man/man1/
man proxy-manager
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
proxy-manager -nmap-path /opt/nmap/bin/nmap -proxlist proxies.txt -ip target
```
The path is saved to `~/.config/proxymgr/config`.

---

## CLI Usage

```
proxy-manager -proxlist <file> -ip <target> [options] [nmap-flags...]
```

| Flag | Description |
|------|-------------|
| `-proxlist file` | Proxy list (one per line: `socks5://host:port`, `host:port`, etc.) |
| `-ip host` | Target host, IP, or CIDR. Also accepted as a positional arg. |
| `-p ports` | Port spec: `80,443` or `1-1024`. Forwarded to nmap too. |
| `-out file` | Output file path |
| `-type fmt` | `txt` (default) · `json` · `xml` · `csv` |
| `-tool name` | `nmap` (default) · `builtin` |
| `-timeout sec` | Connect timeout (default: 5) |
| `-rotate` / `-no-rotate` | Rotate proxy between targets (default: on) |
| `-nmap-path path` | Path to nmap binary (saved to config) |

**Any flag not listed above is forwarded to nmap unchanged** — `-sV`, `-A`, `-T4`, `--script`, `-oX`, etc.

### Examples

```bash
# Service version detection
proxy-manager -proxlist ~/proxies.txt -ip 192.168.1.2 -p 80,443 -sV

# Aggressive scan of a /24, save JSON
proxy-manager -proxlist ~/proxies.txt -ip 10.0.0.0/24 -p 1-1024 -T4 -A \
  -type json -out results.json

# NSE scripts + nmap XML output
proxy-manager -proxlist proxies.txt -ip target.com -sV --script=vuln -oX nmap.xml

# Built-in scanner (no nmap needed)
proxy-manager -proxlist proxies.txt -ip target.com -p 1-65535 -tool builtin
```

### Legacy subcommands (still work)

```bash
proxy-manager validate -f raw.txt -o live.txt -t 200 -T 8
proxy-manager scan -pool live.txt -target host -tool nmap
proxy-manager man
proxy-manager help
```

---

## GUI

Run with no arguments:
```bash
proxy-manager
```

**Proxies tab** — paste or import proxy lists, validate concurrently, export live proxies.  
**Scanner tab** — configure target, ports, tool, timing presets (T3/T4/T5), rotate options, real-time log.  
**Hosts tab** — Zenmap-style view: click a discovered IP to see open ports, services, versions, and which proxy found them.  
**Settings tab** — nmap path detection and configuration, validation settings.

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

Requires [Go 1.21+](https://go.dev/dl/).

```bash
git clone https://github.com/LegitDecent/proxy-manager
cd proxy-manager
make install        # build + install binary + man page
# or
go build -o proxy-manager .
```

---

## Legal

This tool is for **authorised security testing only**.  
Scanning systems without explicit permission is illegal in most jurisdictions.  
The authors take no responsibility for misuse.
