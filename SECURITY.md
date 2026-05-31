# Security Policy

## Supported versions

Security fixes land on the latest release. Please upgrade to the most recent
tag before reporting an issue.

| Version | Supported |
| ------- | --------- |
| latest  | yes       |
| older   | no        |

## Reporting a vulnerability

**Please do not open a public issue for security problems.**

Report privately through GitHub's
[private vulnerability reporting](https://docs.github.com/en/code-security/security-advisories/guidance-on-reporting-and-writing-information-about-vulnerabilities/privately-reporting-a-security-vulnerability):
go to the repository's **Security** tab and choose **Report a vulnerability**.

Please include:

- a description of the issue and its impact,
- steps to reproduce (a proof of concept if possible),
- affected version / commit,
- any suggested remediation.

### What to expect

- Acknowledgement within a few days.
- An assessment and, if confirmed, a fix on a best-effort timeline (this is a
  community project, not a commercial product with an SLA).
- Credit in the release notes if you would like it.

## Scope and intended use

Route Fork is a tool for **authorised security testing only**. Using it to scan
systems you do not own or have explicit written permission to test may be
illegal. Misuse of the tool is out of scope for this policy and is the sole
responsibility of the operator.

## Project security practices

This repository runs automated security tooling on every change:

- **SAST** — `golangci-lint` (govet, staticcheck, errcheck, gosec, ineffassign)
  and GitHub **CodeQL** (`security-extended`).
- **SCA** — `govulncheck` on every push, PR, and weekly schedule; Dependabot for
  dependency and Action updates.
- **Secret scanning** — `gitleaks` over the full history.
- **Supply chain** — release binaries ship with SHA-256 checksums, an SBOM, and
  Sigstore (cosign) signatures plus SLSA build provenance; the project publishes
  an OpenSSF Scorecard.
