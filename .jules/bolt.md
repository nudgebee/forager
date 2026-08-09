## 2026-08-09 - Parallel Datasource Health Checks
**Learning:** In proxy registries managing multiple datasources (DB, SSH, HTTP, Kafka, etc.), sequential health checks cause total latency to scale linearly as O(N * timeout), blocking reporting threads when target endpoints time out.
**Action:** Always perform multi-datasource health probes and metadata collection concurrently using goroutines with per-check context timeouts.
