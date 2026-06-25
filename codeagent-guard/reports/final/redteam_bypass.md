# Red-team Bypass Evaluation

- Cases: 120
- Blocked: 110
- Asked: 6
- Missed: 0
- False positives: 0
- Accuracy on this bypass set: 100.0%

Missed cases are retained in `reports/redteam/redteam_failures.md` with a
suggested deterministic remediation direction. The suite covers encoded and
alternate paths, symlink/TOCTOU simulations, private and metadata URL forms,
redirect/DNS mocks, shell substitutions and decoders, email recipient spoofing,
chunked secret representations, and package lifecycle scripts.

This is a current deterministic red-team set. Results cannot be generalized
to unknown techniques outside the evaluated cases.
