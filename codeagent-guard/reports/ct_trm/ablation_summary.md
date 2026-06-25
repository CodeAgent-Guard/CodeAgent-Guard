# CT-TRM Ablation Evaluation

## Dataset

- Cases: 500
- Dev/regression/holdout are reported separately in each JSON result.
- Dangerous operations are policy inputs only; no real network, email, secret
  file, or destructive command is executed.

## Ablation Summary

| Mode | Cases | Accuracy | Holdout | FP | FN | Taint | Chain | P95 ms |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| no_guard_mock | 500 | 9.2% | 9.0% | 0 | 390 | 0 | 0 | 0.0003 |
| baseline_rules | 500 | 66.8% | 71.0% | 0 | 132 | 0 | 0 | 0.1163 |
| rules_plus_source | 500 | 66.8% | 72.0% | 6 | 132 | 0 | 0 | 0.6201 |
| rules_plus_taint | 500 | 78.6% | 81.0% | 6 | 83 | 159 | 0 | 0.7546 |
| ct_trm_without_chain | 500 | 85.4% | 86.0% | 0 | 73 | 159 | 0 | 0.8834 |
| full_ct_trm | 500 | 98.0% | 97.0% | 0 | 10 | 159 | 145 | 0.9256 |

## Full CT-TRM Category Breakdown

| Category | Total | Passed | Allow | Ask | Deny | FP | FN |
|---|---:|---:|---:|---:|---:|---:|---:|
| benign | 70 | 70 | 46 | 24 | 0 | 0 | 0 |
| dangerous_shell_and_encoded_payload | 55 | 55 | 0 | 0 | 55 | 0 | 0 |
| indirect_prompt_injection | 50 | 40 | 0 | 10 | 40 | 0 | 10 |
| multi_step_chain | 40 | 40 | 0 | 0 | 40 | 0 | 0 |
| package_script_poisoning | 50 | 50 | 0 | 0 | 50 | 0 | 0 |
| path_traversal_and_symlink | 55 | 55 | 0 | 0 | 55 | 0 | 0 |
| secret_exfiltration | 55 | 55 | 0 | 0 | 55 | 0 | 0 |
| ssrf_and_metadata | 45 | 45 | 0 | 0 | 45 | 0 | 0 |
| task_tool_misalignment | 30 | 30 | 0 | 30 | 0 | 0 | 0 |
| tool_output_poisoning | 50 | 50 | 0 | 10 | 40 | 0 | 0 |

## Observable Difference

- Accuracy delta versus baseline rules: 31.2 percentage points.
- False-negative reduction versus baseline rules: 122 cases.
- Full mode taint detections: 159.
- Full mode chain-risk detections: 145.

## Failure Analysis

- False positives: 0
- False negatives: 10
- Detailed cases and suggested fixes are retained in `failures.md` and the
  per-mode JSON files.

## Scope

The reported percentages describe expected-decision agreement on the current
self-built benchmark only. They are not proof of absolute security and cannot
be generalized to all unknown attacks. Container, namespace, seccomp, or VM
isolation remains necessary for defense in depth.
