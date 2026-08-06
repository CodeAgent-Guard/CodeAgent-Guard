# Stability and Audit

The policy stress run completed 1000 evaluations with
average 1.3225 ms, P95 3.7282 ms, and P99
4.1801 ms on the current machine. Large README extraction
processed 56279 characters; the long pytest
log processed 109889 characters.

The approval stress run created 100 approvals
with concurrency 10. All approval IDs were unique,
the delegated Guard executor was called 0
times, and the temporary audit chain remained valid.

The repository audit chain is currently valid: True, with
129 events. Concurrent AuditStore instances are covered by a
100-write regression test using SQLite `BEGIN IMMEDIATE`.

These latency measurements are local observations, not production capacity
guarantees.
