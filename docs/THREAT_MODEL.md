# Threat model

A short, honest description of what Route Fork trusts, what it does not, and the
risks an operator should understand. This is a single-user desktop/CLI tool, not
a networked service, so the model is intentionally small.

## What the tool is

Route Fork validates SOCKS4/5 proxies and runs TCP port scans through a rotating
pool of them. It runs locally, under the control of one operator, against
targets that operator chooses.

## Assets

- The operator's **real IP address** (must not leak to scan targets).
- The operator's **proxy list and credentials** (local files).
- The integrity of **scan results** (open/closed decisions must be honest).

## Trust boundaries and assumptions

- **The operator is trusted.** Command-line flags, file paths, target specs, and
  nmap pass-through arguments are operator-supplied. The tool is not a privilege
  boundary; running it cannot do more than the user already can.
- **Proxies are NOT trusted.** Free SOCKS proxies may be dishonest: they can lie
  about a successful connection, drop traffic, or be honeypots that log activity.
- **Scan targets are NOT trusted.** Their responses (banners, SOCKS replies,
  HTTP echo bodies) are untrusted input and are parsed defensively.

## Threats and mitigations

| Threat | Mitigation |
| --- | --- |
| Real IP leaks to the target | All scan traffic is dialled through a SOCKS proxy in pure Go (no silent direct-connect fallback). Validation fetches and displays each proxy's egress IP; proxies with no verifiable egress are flagged. |
| A lying proxy reports a closed port as open | Scan modes require a quorum (1/2/3) of independent proxies to agree before a port is reported open; an authoritative refusal overrides false "open" votes. |
| Malformed/hostile network responses crash the tool | Response parsers (proxy lines, port specs, SOCKS replies, banners, egress bodies) are fuzz-tested and bounded (e.g. port-spec expansion is capped). |
| Dependency or stdlib vulnerability | `govulncheck` runs on every push/PR and weekly; releases build with the latest patched Go; Dependabot proposes updates. |
| Tampered release binary | Releases ship SHA-256 checksums, Sigstore (cosign) signatures, and SLSA build provenance. |

## Out of scope

- **Anonymity guarantees.** The tool routes through whatever proxies the operator
  supplies; it makes no promise about their trustworthiness or logging.
- **Target-side evasion.** Through a SOCKS proxy there is no packet-level access,
  so IDS/firewall evasion is neither a goal nor possible.
- **Misuse.** Scanning systems without authorisation is the operator's
  responsibility and is explicitly out of scope (see SECURITY.md).
