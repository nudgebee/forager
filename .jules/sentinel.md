## 2026-08-08 - Atomic Nonce Verification for Replay Prevention
**Vulnerability:** TOCTOU race condition in `pkg/signing/verify.go` allowed concurrent duplicate requests with identical nonces to bypass replay protection because `isReplayedNonce` checked nonces before `recordNonce` was called at the end of message verification.
**Learning:** Checking nonces separately from recording them leaves a race condition window under concurrent load, and checking nonces before signature verification allows unauthenticated requests to pollute or query nonce tracking.
**Prevention:** Perform cryptographic signature verification first, followed by an atomic check-and-record operation for nonces under mutex lock.

## 2026-08-23 - Enforce In-Transit TLS Encryption for Redis Proxy Connections
**Vulnerability:** Redis proxy parsed `tls_enabled` configuration into `Config` but never configured `TLSConfig` on `redis.Options`, causing Redis connections to transmit sensitive queries, data, and authentication credentials in plaintext over unencrypted streams even when TLS was requested.
**Learning:** Parsing security configuration flags into config structs without wiring them into underlying driver/client options creates a false sense of security where in-transit encryption is silently bypassed.
**Prevention:** Ensure parsed security configurations (`TLSEnabled`) explicitly configure secure TLS options (`tls.Config{MinVersion: tls.VersionTLS12, ServerName: host}`) on the client and verify via unit tests.

