# Changelog

All notable changes to Route Fork are documented here.

---

## [v1.1.0] — 2026-05-30

### Added
- **Egress IP validation** — after a proxy passes the SOCKS handshake, Route Fork
  opens a live tunnel through it and fetches the real outbound IP the target would
  see (via `api.ipify.org` / `checkip.amazonaws.com`). The exit IP is stored on the
  proxy and shown in all display lines (`egress:x.x.x.x`).
- **Duplicate egress detection (GUI)** — when validation completes, proxies are
  grouped by egress IP. If any group has more than one member a dialog appears
  showing every duplicate group with `[keep]` on the fastest proxy and `[dupe]` on
  the rest.
  - **Remove Duplicates** — keeps the fastest proxy per exit IP, drops the rest,
    and rebuilds the valid pool atomically.
  - **Keep All** — closes the dialog without touching the pool.
- **Egress summary (CLI)** — `rofk validate` now prints the egress IP inline on
  each `[+]` line. At the end a summary shows the count of unique egress IPs and
  lists any that are shared by multiple proxies with a warning to remove them.

### Changed
- Progress counter in the GUI now increments *after* the egress fetch completes,
  so the percentage reflects fully-processed proxies rather than just handshake
  results.

---

## [v1.0.0] — 2026-05-28

Initial release.

### Features
- **SOCKS4 / SOCKS5 validation** — raw handshake, no external dependencies.
  Reports latency in ms and failure reason per proxy.
- **Built-in TCP port scanner** — pure-Go connect scan routed through any proxy
  in the pool; no nmap required.
- **nmap integration** — local SOCKS4↔SOCKS5 relay lets nmap scan through proxies
  without proxychains. Automatic `-Pn` retry on zero results.
- **Proxy pool management** — valid / failed buckets, round-robin rotation, wrap
  on exhaustion, clear, retry-failed.
- **Multiple input formats** — `host:port`, `host:port:user:pass`,
  `socks5://user:pass@host:port`, space-separated.
- **Export** — write valid proxies back to file in URI format.
- **GUI** (Fyne, dark theme) — Proxies tab, Scanner tab, Hosts tab, Settings tab.
- **CLI** — `rofk validate` and `rofk scan` subcommands; unknown flags pass
  straight through to nmap in nmap mode.
- **Output formats** — plain text, JSON, XML, CSV for scan results.
- **Hosts tab** — aggregates open-port findings per discovered host across scans.
