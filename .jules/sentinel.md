## 2026-08-23 - Prevent SSRF and Credential Leakage via HTTP Redirects
**Vulnerability:** In `pkg/proxy/http/proxy.go`, `resolveTargetURL` ensured the initial request was relative to `base_url`, but the unconfigured `http.Client` followed HTTP 3xx redirects automatically to arbitrary destinations, exposing internal cloud metadata endpoints (`169.254.169.254`) and leaking custom authentication headers.
**Learning:** Initial URL resolution guards are completely bypassed when an HTTP client follows redirects, which Go's `net/http` client does up to 10 hops by default without origin boundaries.
**Prevention:** Configure `CheckRedirect` to return `http.ErrUseLastResponse` by default, treating redirects as terminal responses in reverse proxies, and only follow redirects when explicitly opted in via configuration (`follow_redirects: true`).

## 2026-08-08 - Atomic Nonce Verification for Replay Prevention
**Vulnerability:** TOCTOU race condition in `pkg/signing/verify.go` allowed concurrent duplicate requests with identical nonces to bypass replay protection because `isReplayedNonce` checked nonces before `recordNonce` was called at the end of message verification.
**Learning:** Checking nonces separately from recording them leaves a race condition window under concurrent load, and checking nonces before signature verification allows unauthenticated requests to pollute or query nonce tracking.
**Prevention:** Perform cryptographic signature verification first, followed by an atomic check-and-record operation for nonces under mutex lock.
