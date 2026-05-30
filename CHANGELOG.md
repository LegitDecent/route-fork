# Changelog

All notable changes to Route Fork are documented here.

---

## [v1.3.0] — 2026-05-30

### Fixed
- **Proxy routing** — all scan traffic now flows through the SOCKS proxy. Previous
  versions silently fell back to a direct connection whenever nmap's `--proxies`
  path had any failure; the nmap path has been replaced with a pure-Go TCP connect
  scan for all proxy-routing modes.
- **Per-port rotation** — when "rotate proxy per port" is enabled and the port
  count is smaller than the proxy pool, each port is now assigned a distinct,
  randomly-selected proxy. Previously all ports went through the same proxy
  (chunk-size math produced 1, loop broke on the second iteration).
- **"Via" label accuracy** — the displayed proxy address now shows the actual
  egress IP the target server sees (`[exit: x.x.x.x]` suffix), not the proxy
  entry IP. Previously the label reflected whichever entry address was stored in
  memory at display time, which could differ from the real exit node.
- **Per-connection proxy tracking** — the built-in scanner now reports which exact
  proxy each open port was found through instead of "one of N proxies".

### Added
- **Unit tests** — new test coverage across four packages:
  - `proxy/validate_test.go` — `extractPublicIP`, `socks5Handshake`,
    `socks4Handshake`, `DialThroughProxy`, `Validate`
  - `relay/relay_test.go` — `socks4Reply`, `readUntilNull`,
    `readStringUntilNull`, `socks5Connect`, `socks4aConnect`, relay forward
    path (SOCKS5 and SOCKS4a upstream), SOCKS4a hostname request handling,
    failure path (bare TCP close, no 0x5B), `Stop`, `NmapProxyArg`
  - `scanner/scan_test.go` — `Scan` open port, closed port, `Result.Proxy`
    field, progress callback, context cancellation, multi-port scan
  - `pool/pool_test.go` — `SetValid` (replace, index reset, nil, isolation)
- **CI** — GitHub Actions workflow runs `go test ./...` on every push and PR.

---

## [v1.2.0] — 2026-05-30

### Changed
- **Unknown egress = cut, not keep** — proxies where egress IP fetch fails are now
  treated the same as confirmed duplicates. Their exit node is unknown and they
  cannot be trusted. Previously they were silently kept; now they show as `[cut]`
  in the cleanup dialog and are dropped when the user clicks Remove.
- **GUI dialog triggers on unknowns too** — the cleanup dialog now appears whenever
  there are unverified proxies, even if no duplicate egress groups exist.
- **Dialog button** label now shows the total count being removed
  (e.g. "Remove 7 Bad Proxies") instead of the generic "Remove Duplicates".
- **CLI warning** — `rofk validate` separately reports the count of proxies with
  no verifiable egress IP and tells you to remove them.

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
