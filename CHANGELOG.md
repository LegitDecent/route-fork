# Changelog

All notable changes to Route Fork are documented here.

---

## [v1.4.3] — 2026-05-31

Production-readiness pass: static analysis, supply-chain integrity, fuzzing, and
project governance. Two real robustness bugs (found by the new fuzzers) fixed.

### Security
- **SAST in CI** — `golangci-lint` (govet, staticcheck, errcheck, gosec,
  ineffassign, misspell, unconvert) and GitHub **CodeQL** (`security-extended`).
- **Secret scanning** — `gitleaks` over full history on every push/PR.
- **Scheduled vuln scan** — `govulncheck` now also runs weekly, catching newly
  disclosed CVEs in unchanged dependencies.
- **Dependabot** — weekly grouped updates for Go modules and GitHub Actions.
- **Supply chain on releases** — SHA-256 `SHA256SUMS`, an SPDX **SBOM**, Sigstore
  (**cosign**) keyless signatures, and **SLSA build provenance**. Least-privilege
  `GITHUB_TOKEN` permissions across all workflows.
- **OpenSSF Scorecard** workflow and badge.

### Fixed
- **`ParseLine` accepted an empty host** (e.g. `:1` produced a hostless proxy);
  now rejected. Found by fuzzing.
- **`ParsePorts` could allocate unbounded memory** on a crafted spec (many
  overlapping ranges); expansion is now capped. Found by fuzzing.
- Corrected a `break` inside a `select` that did not actually stop the CLI's
  target loop on interrupt.

### Added
- **Fuzz tests** for the untrusted-input parsers (proxy lines, port specs,
  egress-IP extraction, banner sanitisation), with the crash inputs kept as
  regression seeds.
- **`rofk version`** reports version, platform, and Go toolchain. Release builds
  stamp the tag via `-ldflags -X main.version`.
- Test suite now runs under the **race detector** in CI with a coverage summary.
- **Governance** — `SECURITY.md`, `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md`,
  issue/PR templates, `CODEOWNERS`, and a `docs/THREAT_MODEL.md`.

---

## [v1.4.2] — 2026-05-31

### Security
- **Patched two DoS vulnerabilities** in `golang.org/x/image`'s TIFF decoder
  (GO-2026-5032, GO-2026-4815), pulled in transitively by the GUI's image
  rendering. Bumped `golang.org/x/image` v0.24.0 → v0.41.0. Found by `govulncheck`.
- **CI now runs `govulncheck`** on every push and pull request, so reachable
  vulnerabilities in dependencies are caught automatically.

### Added
- **Proxy burn protection** (off by default) — an optional per-proxy minimum
  reuse interval on the Scanner tab. When enabled, a proxy used within the gap is
  skipped for that round, so a free SOCKS pool isn't hammered into rate-limits or
  bans mid-scan. This protects your own proxy infrastructure; it is not a
  target-evasion feature.

### Changed
- The per-port quorum decision (open / closed / unconfirmed / unreachable,
  including the "an authoritative refusal overrides a met quorum" rule) was
  extracted from the GUI into a pure, unit-tested `scanner.DecideQuorum` function.
  No behaviour change; it's the same logic, now covered by tests.

---

## [v1.4.1] — 2026-05-31

Maintenance release: dependency and toolchain updates, plus the GUI fixes the
Fyne upgrade required.

### Changed
- **Dependencies updated** — `fyne.io/fyne/v2` v2.4.4 → v2.7.4,
  `golang.org/x/net` v0.24.0 → v0.55.0, and the rest of the module graph brought
  current via `go mod tidy`.
- **Go toolchain** — minimum raised to 1.25 (required by the updated
  `golang.org/x/net` / `x/sys` / `x/text`).
- **CI / release workflows** — bumped actions (`checkout` v6, `setup-go` v6,
  `upload-artifact` v7, `download-artifact` v8, `action-gh-release` v3) and they
  now read the Go version from `go.mod` so it can't drift again. Clears the
  Node 20 deprecation warnings.
- Migrated off the deprecated `theme.DarkTheme()` to a variant-based forced-dark
  theme (same appearance).

### Fixed
- **GUI no longer freezes or crashes on Validate or scan** — Fyne 2.6+ made the
  UI single-threaded; all widget updates from worker goroutines (validation,
  scan log, Hosts refresh, auto-revalidation, the pool-cleanup dialog) now run on
  the main thread via `fyne.Do()`. (Binding updates were already main-thread-safe
  and were left as-is.)

---

## [v1.4.0] — 2026-05-30

### Added
- **Service name labels** — open ports show their common service name
  (`ssh`, `https`, `mysql`, `ms-wbt-server`, …) instead of `unknown`, across the
  GUI log, the Hosts tab, and all CLI output formats.
- **Banner grabbing** — after a successful connect the scanner reads up to 256
  bytes (800 ms) to capture a service banner (SSH version, FTP greeting, etc.),
  shown inline in the log, in the Hosts tab, and exported in txt/csv/xml/json.
- **Scan mode (open-port confirmation)** — a Scanner-page selector controls how
  many proxies must independently agree a port is open before it's reported,
  defeating proxies that fake a successful connection: **Fast** (1), **Confirmed**
  (2, default), **Paranoid** (3). It is the sole authority over proxies-per-port.
  Confirmation dials run in parallel (bounded by Concurrency), so even Paranoid
  finishes in roughly one round-trip, and an authoritative "connection refused"
  from any proxy immediately refutes a false open. Every proxy that agreed is
  listed under the open port.
- **Add common ports** — a checkbox beside the Ports field merges the common-port
  list (deduplicated) directly into what you typed, so the exact ports are visible
  before scanning; unchecking restores your original list.
- **Hosts tab drill-down** — the Hosts view is now three panes
  (Hosts → Open Ports → Validating Proxies). Selecting a port shows every proxy
  that confirmed it, one per line, alongside its service, version, and banner.
- **Auto-revalidation** — a Settings card re-checks the pool on a fixed interval
  and drops proxies that have since died, with a live status line.
- **Dead-proxy retry + prune during scans** — a proxy that fails on its own
  (unreachable, not a SOCKS server, resets/closes mid-handshake, or never replies)
  is skipped, another is tried, and dead proxies are pruned when the scan finishes.
  Proxy-error retries are capped per port so a filtered target can't churn the pool.
- **`-out -` writes to stdout** — the flat CLI streams scan results to stdout for
  piping (e.g. `… -out - -type json | jq`).
- **Skip-validation confirmation** — "Add to Pool (skip validation)" warns about
  the risks (dead proxies, possible IP leakage, no egress data) before adding.
- **Apache License 2.0** — the project now ships under Apache-2.0 (explicit patent
  grant plus warranty/liability disclaimers); see `LICENSE`.

### Changed
- **`-Pn` is now the default for nmap** in every path (CLI scan, flat CLI, GUI),
  since host discovery does not work through SOCKS proxies.
- **Release builds cover five platforms** — `linux/amd64`, `linux/arm64`, macOS
  Apple Silicon (`macos-arm64`) and Intel (`macos-amd64`), and `windows/amd64`.
  Intel Macs now have a native binary (an arm64-only build can't run on them;
  Rosetta 2 only translates x86_64 to arm64).
- **Hosts tab deduplicates ports across rescans** — re-scanning a port no longer
  adds a duplicate row; newly-validating proxies are merged into the existing port
  entry, and the per-host count reflects distinct ports.

### Fixed
- **No false "open" from a single lying proxy** — open results require quorum
  agreement (Scan mode); one proxy faking a CONNECT success can no longer mark a
  closed/filtered port open on its own.
- **Closed/filtered ports no longer churn the pool, and open ports aren't missed
  by flaky proxies** — the retry classifier distinguishes proxy-side failures
  (connection reset, no CONNECT reply, unreachable proxy → retry) from genuine
  target results (`connection refused`, SOCKS4 rejection → reported as closed).
- **Stop button is now responsive** — per-port scan dials race against
  cancellation, so Stop interrupts in-flight connections immediately instead of
  waiting out the dial timeout.

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
