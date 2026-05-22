# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0] - TBD

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
- Multi-arch Docker images published to `ghcr.io/nudgebee/forager`.

[Unreleased]: https://github.com/nudgebee/forager/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/nudgebee/forager/releases/tag/v0.1.0
