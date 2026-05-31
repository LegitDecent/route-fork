# Contributing to Route Fork

Thanks for your interest in improving Route Fork.

## Ground rules

- Route Fork is for **authorised security testing only**. Contributions that
  exist solely to enable abuse (target evasion, attacks on systems you do not
  own) will not be accepted.
- Be civil. See [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).

## Development setup

Requires [Go 1.25+](https://go.dev/dl/). On Linux the GUI needs OpenGL and X11
headers:

```bash
sudo apt-get install -y gcc libgl1-mesa-dev xorg-dev   # Debian/Ubuntu
```

Common tasks:

```bash
go build ./...        # build everything
go test ./...         # run the test suite
go test -race ./...   # run with the race detector (as CI does)
go vet ./...
```

## Before opening a pull request

Your change must pass everything CI runs:

```bash
go vet ./...
go test -race ./...
go run github.com/golangci/golangci-lint/v2/cmd/golangci-lint@latest run ./...
go run golang.org/x/vuln/cmd/govulncheck@latest ./...
gofmt -l .            # must print nothing
```

- Keep the diff focused; one logical change per PR.
- Add or update tests for behaviour changes. Parser/protocol code should have
  table-driven tests; consider a fuzz target for anything that parses untrusted
  input (see `proxy/fuzz_test.go`, `scanner/fuzz_test.go`).
- Update `CHANGELOG.md` and the README if behaviour or features change.
- Do not commit secrets or real proxy lists; `gitleaks` runs on every PR.

## Reporting security issues

Please follow [SECURITY.md](SECURITY.md) — do not file public issues for
vulnerabilities.
