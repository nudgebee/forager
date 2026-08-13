# Bolt's Performance Journal

Critical learnings and performance patterns discovered in this codebase.

## 2026-08-08 - Pre-parse IP Addresses for Comparator Functions
**Learning:** `sort.Slice` calls comparator functions $O(N \log N)$ times. Calling `netip.ParseAddr` or other parsing/conversion functions inside a sort comparator creates severe CPU overhead ($2 \cdot N \log_2 N$ string parses) during large discovery sweeps (up to 65,536 hosts).
**Action:** Always pre-parse IP strings into `netip.Addr` structs once into a temporary slice or wrapper struct before sorting.

## 2026-08-13 - Pre-allocate Static Lookup Maps at Package Scope
**Learning:** Defining static lookup map literals (such as `map[string]string{...}`) inside helper functions evaluated per-host (e.g., `osFamily` in `parseFacts`) causes Go to allocate and populate a new hash map on the heap on every invocation (~1.2 KB and 3 allocations per call).
**Action:** Declare static lookup maps as package-level read-only `var` or `const`-like variables so they are allocated once at package init.
