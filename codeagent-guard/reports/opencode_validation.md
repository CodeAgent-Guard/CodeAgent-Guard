# OpenCode Adapter Validation

- Scenarios: 30
- Expected authorizations: 30
- Pending to approved: 1
- Pending to rejected: 1
- Pending to expired: 1
- Guard executor calls: 0
- Traces generated: 30
- P95 policy latency: 62.5743 ms

## Validation Level

OpenCode Hook/Adapter-level simulation. Real OpenCode was not started in this environment. Native execution remains delegated and the Guard executor is asserted unused.

## Scope

Results cover the current OpenCode adapter and Hook contract, not a live OpenCode process or every model behavior. The Hook can resume an approved native call only
while the OpenCode process and Hook wait remain alive.
