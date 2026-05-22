# Contributing to Forager

Thanks for taking the time to contribute. This document explains the local
dev loop, conventions, and how to send a PR.

## Local setup

```bash
git clone https://github.com/nudgebee/forager
cd forager
make build              # → bin/forager
make test               # unit tests with -race, no Docker needed
```

See [docs/configuration.md](docs/configuration.md) for the env-var and
config-file surface, and [docs/architecture.md](docs/architecture.md) for
the runtime model.

## Before you open a PR

```bash
make fmt        # gofmt -w
make lint       # golangci-lint
make test       # go test -race -cover ./...
```

The `make validate` target runs all three.

## Pull request guidelines

- **Branch from `main`.** Keep PRs focused — one concern per PR.
- **Conventional-style commits.** The git log uses `feat:`, `fix:`,
  `feat(<area>):`, `fix(<area>):`, `build(deps):`, `chore:`, `docs:`,
  `refactor:`. The `<area>` is the package or subsystem (`proxy`, `ws`,
  `secrets`, `signing`, ...).
- **Tests.** New behavior needs a unit test next to the code.
- **No new comments stating WHAT.** Well-named functions document
  themselves; comments explain WHY (constraints, workarounds, non-obvious
  invariants).
- **Update docs** when you change the wire shape, config surface, or
  proxy module behavior — see the relevant page under `docs/`.

## DCO sign-off

All commits must be signed off under the [Developer Certificate of
Origin](https://developercertificate.org/). Add a sign-off line to every
commit:

```bash
git commit -s -m "feat(proxy): add new datasource type"
```

This appends a `Signed-off-by: Your Name <you@example.com>` line to the
commit message, confirming you have the right to submit the contribution
under the project's license. Commits without a sign-off will be rejected
by CI.

To configure git to always include your sign-off:

```bash
git config --global format.signOff true
```

## Code conventions

- Errors propagate with `fmt.Errorf("...: %w", err)`.
- Every blocking call takes `context.Context` and honors cancellation.
- No global state beyond the linker-stamped `pkg/version` vars and the
  process-scoped proxy registry built in `cmd/app.go`.
- Tests live next to the code they test.

## Reporting bugs

Use GitHub issues. Include:
- Forager version (`forager --version` or the image tag).
- OS / platform (Linux distro, macOS, Windows, k8s flavor + version).
- Steps to reproduce, expected vs. actual behavior, and any relevant logs
  (with secrets redacted).

## Security

Please don't report security issues via GitHub issues. See
[SECURITY.md](SECURITY.md).

## License

By contributing, you agree your contributions will be licensed under
[Apache-2.0](LICENSE).
