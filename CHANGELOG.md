# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- OpenSSF Scorecard workflow (`scorecard.yml`) publishing results to the
  OpenSSF API, plus a Scorecard badge in the README.
- CodeQL static analysis workflow (`codeql.yml`) for Go.
- `govulncheck` job in CI to flag known vulnerabilities in dependencies.
- Release artifacts now ship a `checksums.txt` with a keyless cosign
  signature (`checksums.txt.sig` / `.pem`) so downloads can be verified.
- Native Go fuzz tests for the signing package: public-key parsing,
  canonical-JSON normalization, and signature envelope verification.

### Changed
- Pinned all GitHub Actions to full commit SHAs (Dependabot keeps the
  `# vX.Y.Z` comments and SHAs current).
- Pinned Dockerfile base images (`golang`, `debian`) by digest and
  `govulncheck` to a tagged version (OpenSSF Scorecard Pinned-Dependencies).
- Scoped workflow `GITHUB_TOKEN` permissions to least privilege: read-only
  at the top level, per-job escalation only where needed.

## [0.1.0] - 2026-05-23

### Added
- Initial public release.
- WebSocket client with auto-reconnect and Ed25519 message-signature
  verification.
- Datasource proxies: PostgreSQL, MySQL, MSSQL, ClickHouse, MongoDB,
  Redis, Kafka, SSH, HTTP, MCP (stdio / HTTP / SSE transports). Oracle
  is supported in the Docker image only (CGO + Oracle Instant Client).
- Secret backends: AWS Secrets Manager, GCP Secret Manager, Azure Key
  Vault, plus a local cloud-push credential store.
- Deployment artifacts: Helm chart, systemd unit, CloudFormation
  template, install scripts for Linux, macOS, and Windows.
- Docker images published to `ghcr.io/nudgebee/forager` (linux/amd64;
  multi-arch tracked as a follow-up once the Dockerfile picks Oracle
  Instant Client by `$TARGETARCH`).

[Unreleased]: https://github.com/nudgebee/forager/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/nudgebee/forager/releases/tag/v0.1.0
