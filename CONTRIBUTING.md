# Contributing to wardryx

## Development

```sh
go build ./...   # build
go test -race ./...   # run tests
gofmt -l .        # format check, should print nothing
go vet ./...      # vet
```

Before every commit, this must be clean:

```sh
test -z "$(gofmt -l .)" || (gofmt -l .; exit 1)
go vet ./...
go test -race ./...
go build ./...
```

CI also runs the `integration`-tagged store tests
(`go test -tags integration ./internal/store/`).

## Conventions

- Conventional Commits: `feat:`, `fix:`, `refactor:`, `chore:`, `docs:`, `test:`.
- One logical change per commit.
- `go vet`, `gofmt`, and `go test -race` must pass before a PR.
- Decisions are deterministic: no LLM anywhere in the `allow`/`deny`/`hold`
  path. The same policy set and the same request must always return the
  same answer.

## Security

See [SECURITY.md](SECURITY.md) for how to report vulnerabilities privately.
