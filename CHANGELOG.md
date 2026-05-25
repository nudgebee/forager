# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.1] - 2026-05-25

### Changed
- Release pipeline now authenticates to AWS via GitHub OIDC instead of
  long-lived access keys (mirror jobs only). The `PROD_AWS_*` repo
  secrets are no longer used.
- AWS account ID, region, and S3 bucket extracted from the workflow
  source into repo variables (`AWS_ACCOUNT_ID`, `AWS_REGION`,
  `MIRROR_S3_BUCKET`, `AWS_ROLE_ARN`).

### Fixed
- Prerelease tags (e.g. `vX.Y.Z-rcN`) are now correctly marked as
  GitHub prereleases instead of shipping as the repo's "latest release."

No functional changes to the agent itself.

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

[Unreleased]: https://github.com/nudgebee/forager/compare/v0.1.1...HEAD
[0.1.1]: https://github.com/nudgebee/forager/releases/tag/v0.1.1
[0.1.0]: https://github.com/nudgebee/forager/releases/tag/v0.1.0
