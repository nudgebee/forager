## 2026-08-23 - Prevent SSRF and Credential Leakage via HTTP Redirects
**Vulnerability:** In `pkg/proxy/http/proxy.go`, `resolveTargetURL` ensured the initial request was relative to `base_url`, but the unconfigured `http.Client` followed HTTP 3xx redirects automatically to arbitrary destinations, exposing internal cloud metadata endpoints (`169.254.169.254`) and leaking custom authentication headers.
**Learning:** Initial URL resolution guards are completely bypassed when an HTTP client follows redirects, which Go's `net/http` client does up to 10 hops by default without origin boundaries.
**Prevention:** Configure `CheckRedirect` to return `http.ErrUseLastResponse` by default, treating redirects as terminal responses in reverse proxies, and only follow redirects when explicitly opted in via configuration (`follow_redirects: true`).

## 2026-08-15 - Enforce Complete Signature Verification on WebSocket Proxy Actions
**Vulnerability:** An incomplete `signedActions` map in `pkg/ws/handler.go` omitted 21 proxy actions across Kafka (`kafka_consumer_lag`, `kafka_brokers`, etc.), MongoDB (`mongo_list_databases`, `mongo_current_ops`, etc.), and Redis (`redis_slowlog`, `redis_client_list`, etc.). Because verification logic only checked `signedActions[effectiveAction]`, unlisted actions bypassed cryptographic signature verification entirely, allowing unsigned messages to extract database queries, internal topology, and cluster metadata.
**Learning:** Using an opt-in allowlist where unlisted actions default to unverified creates a fail-open hazard whenever new proxy capabilities or actions are added without updating the central map.
**Prevention:** Register all proxy actions explicitly in `signedActions`, enforce fail-secure signature verification for all actions whenever verification is enabled (`h.verifier.Enabled()`), and maintain automated tests that assert every action touching external or internal infrastructure requires cryptographic signatures.

## 2026-08-08 - Atomic Nonce Verification for Replay Prevention
**Vulnerability:** TOCTOU race condition in `pkg/signing/verify.go` allowed concurrent duplicate requests with identical nonces to bypass replay protection because `isReplayedNonce` checked nonces before `recordNonce` was called at the end of message verification.
**Learning:** Checking nonces separately from recording them leaves a race condition window under concurrent load, and checking nonces before signature verification allows unauthenticated requests to pollute or query nonce tracking.
**Prevention:** Perform cryptographic signature verification first, followed by an atomic check-and-record operation for nonces under mutex lock.

## 2026-08-23 - Enforce In-Transit TLS Encryption for Redis Proxy Connections
**Vulnerability:** Redis proxy parsed `tls_enabled` configuration into `Config` but never configured `TLSConfig` on `redis.Options`, causing Redis connections to transmit sensitive queries, data, and authentication credentials in plaintext over unencrypted streams even when TLS was requested.
**Learning:** Parsing security configuration flags into config structs without wiring them into underlying driver/client options creates a false sense of security where in-transit encryption is silently bypassed.
**Prevention:** Ensure parsed security configurations (`TLSEnabled`) explicitly configure secure TLS options (`tls.Config{MinVersion: tls.VersionTLS12, ServerName: host}`) on the client and verify via unit tests.

