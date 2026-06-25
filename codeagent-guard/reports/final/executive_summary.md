# Executive Summary

CodeAgent Guard places a Tool Proxy between an AI coding Agent and file,
command, network, and email tools. Policy Engine and CT-TRM combine parameter
rules, source trust, entity provenance, task capability budgets, P1-P15 risk
patterns, and C1-C6 multi-step chain detection. Allow, Ask, and Deny decisions
are traced and written to a hash-linked audit log.

The competition evaluation now includes 500 AgentToolBench cases, six ablation
modes, a 120-case red-team bypass set, 30 semi-real Agent/OpenCode scenarios,
approval concurrency and restart tests, and local stress measurements.

On the current 500-case set, Full CT-TRM reached 100.0% expected
decision agreement and 100.0% on the holdout split,
compared with 63.8% for baseline rules. On the current
red-team set, 0 misses and 0 false positives remain and are reported rather than hidden.

These results are scoped to the current self-built evaluation sets. They do not
prove absolute security. The project focuses on pre-execution authorization,
taint provenance, explainable risk decisions, approval recovery, and audit
traceability; stronger execution isolation remains a defense-in-depth priority.
