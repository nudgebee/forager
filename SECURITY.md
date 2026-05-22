# Security Policy

## Reporting a vulnerability

Please **do not** open a public GitHub issue for security vulnerabilities.

Report privately via GitHub's [Private Vulnerability Reporting](https://github.com/nudgebee/forager/security/advisories/new)
on this repository, or by email to `security@nudgebee.com`. We'll
acknowledge within 5 business days and aim to provide a fix or mitigation
within 30 days for confirmed, in-scope reports.

## Scope

In scope:
- The `nudgebee-forager` binary built from this repository.
- Public Docker images published at `ghcr.io/nudgebee/forager`.
- The Helm chart at `deploy/helm/forager/`.
- Install scripts under `deploy/` (`install.sh`, `install-macos.sh`,
  `install.ps1`) and the CloudFormation template at
  `deploy/cloudformation/forager-ec2.yaml`.
- Build and CI configuration (`.github/workflows/*`, `Dockerfile`,
  `Makefile`).

Out of scope (please report to the relevant project upstream):
- Bugs in third-party Go dependencies — file with the dependency.
- Bugs in upstream database/SSH/Kafka client libraries — file with
  those projects.
- Bugs in Oracle Instant Client distributed as part of the Docker image.

## Supported versions

We support the latest tagged release and the current `main` branch.

## Disclosure

We follow coordinated disclosure. Once a fix is available we will:
1. Publish a GitHub Security Advisory with the CVE if one was assigned.
2. Release a patched version.
3. Credit the reporter (with their consent).
