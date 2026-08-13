## 2026-08-08 - Atomic Nonce Verification for Replay Prevention
**Vulnerability:** TOCTOU race condition in `pkg/signing/verify.go` allowed concurrent duplicate requests with identical nonces to bypass replay protection because `isReplayedNonce` checked nonces before `recordNonce` was called at the end of message verification.
**Learning:** Checking nonces separately from recording them leaves a race condition window under concurrent load, and checking nonces before signature verification allows unauthenticated requests to pollute or query nonce tracking.
**Prevention:** Perform cryptographic signature verification first, followed by an atomic check-and-record operation for nonces under mutex lock.

## 2026-08-13 - Fail-Closed Signature Verification for Relay Messages
**Vulnerability:** Newly added proxy actions (e.g. Kafka actions, Mongo status/stats, Redis info/slowlog/client list) were missing from an explicit opt-in `signedActions` map in `pkg/ws/handler.go`, allowing unsigned messages for those actions to silently bypass signature verification even when message signing was enabled.
**Learning:** Opt-in authorization/verification maps are fail-open security antipatterns. When new proxy modules or sub-actions are added, forgetting to register them in an explicit map leaves unauthenticated execution vectors.
**Prevention:** Enforce signature verification uniformly for all incoming control plane messages in `HandleMessage` (fail-closed, secure by default) when signature verification is enabled, eliminating manual opt-in map maintenance.

