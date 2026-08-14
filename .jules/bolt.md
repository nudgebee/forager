# Bolt's Performance Journal

Critical learnings and performance patterns discovered in this codebase.

## 2026-08-08 - Pre-parse IP Addresses for Comparator Functions
**Learning:** `sort.Slice` calls comparator functions $O(N \log N)$ times. Calling `netip.ParseAddr` or other parsing/conversion functions inside a sort comparator creates severe CPU overhead ($2 \cdot N \log_2 N$ string parses) during large discovery sweeps (up to 65,536 hosts).
**Action:** Always pre-parse IP strings into `netip.Addr` structs once into a temporary slice or wrapper struct before sorting.

## 2026-08-13 - Use Switch Statements for Zero-Allocation Static Lookups
**Learning:** Defining static lookup map literals (such as `map[string]string{...}`) inside helper functions evaluated per-host (e.g., `osFamily` in `parseFacts`) causes Go to allocate and populate a new hash map on the heap on every invocation (~1.2 KB and 3 allocations per call).
**Action:** Prefer switch statements over map literals for fixed static lookups to achieve zero heap allocations, complete immutability, and zero race-condition risk.

## 2026-08-14 - Pre-parse and Cache Guard Expressions at Pack Validation
**Learning:** Re-parsing filter expressions or guard ASTs (such as `when` expressions in content packs) inside per-target evaluation loops (`Select`) during fleet-wide sweeps causes massive repeated string splitting, heap allocations, and CPU overhead ($O(N_{\text{hosts}} \cdot N_{\text{collectors}})$ parses).
**Action:** Parse guard expressions once into compiled AST structs (`*whenExpr`) during pack load/validation (`Pack.validate`), caching the pointer on the collector struct for direct zero-parse evaluations.
