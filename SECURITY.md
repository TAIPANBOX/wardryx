# Security Policy

wardryx is a Policy Decision Point: it decides `allow`, `deny`, or `hold`
for an agent's actions, so a bug in the decision path can itself become a
security bypass. This document covers how to report a vulnerability.

## Reporting a vulnerability

Please report security issues privately, not in public issues or PRs:

- Open a **GitHub private security advisory**:
  <https://github.com/TAIPANBOX/wardryx/security/advisories/new>

Include the affected version/commit, a description, and a minimal reproduction.
We aim to acknowledge within a few days and to fix high-severity issues before
any public disclosure. There is no bug-bounty program; we credit reporters in
the advisory unless you prefer otherwise.

## Supported versions

wardryx is pre-1.0; only `main` is supported. Fixes land on `main` and are
not backported.

## Verifying a build

Every change must pass the full gate before merge: `gofmt -l .` clean,
`go vet ./...`, `go build ./...`, and `go test -race ./...`. CI also runs the
`integration`-tagged store tests. See [CONTRIBUTING.md](CONTRIBUTING.md).
