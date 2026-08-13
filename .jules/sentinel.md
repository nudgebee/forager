## 2026-08-08 - Atomic Nonce Verification for Replay Prevention
**Vulnerability:** TOCTOU race condition in `pkg/signing/verify.go` allowed concurrent duplicate requests with identical nonces to bypass replay protection because `isReplayedNonce` checked nonces before `recordNonce` was called at the end of message verification.
**Learning:** Checking nonces separately from recording them leaves a race condition window under concurrent load, and checking nonces before signature verification allows unauthenticated requests to pollute or query nonce tracking.
**Prevention:** Perform cryptographic signature verification first, followed by an atomic check-and-record operation for nonces under mutex lock.

## 2026-08-13 - Comprehensive Registration of Actions in `signedActions` Map
**Vulnerability:** Newly added proxy actions (e.g. Kafka, Mongo status/stats, Redis info/slowlog/client list) were missing from the central `signedActions` map in `pkg/ws/handler.go`, allowing unsigned messages for those actions to bypass signature verification even when message signing was enabled.
**Learning:** `signedActions` used an explicit opt-in map rather than a default-signed approach, so adding new proxy packages or actions without updating `signedActions` silently creates unsigned execution paths.
**Prevention:** Always register every action supported by any proxy module in `signedActions` (or add unit tests asserting all proxy actions are present in `signedActions`).

