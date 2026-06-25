# CT-TRM Ablation Evaluation

## Dataset

- Cases: 120
- Dev/regression/holdout are reported separately in each JSON result.
- Dangerous operations are policy inputs only; no real network, email, secret
  file, or destructive command is executed.

## Ablation Summary

| Mode | Cases | Accuracy | Holdout | FP | FN | Taint | Chain | P95 ms |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| full_ct_trm | 120 | 100.0% | 100.0% | 0 | 0 | 6 | 14 | 3.2009 |

## Full CT-TRM Category Breakdown

| Category | Total | Passed | Allow | Ask | Deny | FP | FN |
|---|---:|---:|---:|---:|---:|---:|---:|
| redteam_bypass | 120 | 120 | 4 | 6 | 110 | 0 | 0 |

## Observable Difference

- Accuracy delta versus baseline rules: 0.0 percentage points.
- False-negative reduction versus baseline rules: 0 cases.
- Full mode taint detections: 6.
- Full mode chain-risk detections: 14.

## Failure Analysis

- False positives: 0
- False negatives: 0
- Detailed cases and suggested fixes are retained in `failures.md` and the
  per-mode JSON files.

## Scope

The reported percentages describe expected-decision agreement on the current
self-built benchmark only. They are not proof of absolute security and cannot
be generalized to all unknown attacks. Container, namespace, seccomp, or VM
isolation remains necessary for defense in depth.
