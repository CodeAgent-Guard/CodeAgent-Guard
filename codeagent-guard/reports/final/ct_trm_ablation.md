# CT-TRM Ablation

| Mode | Accuracy | Holdout | FP | FN | P95 ms |
|---|---:|---:|---:|---:|---:|
| no_guard_mock | 9.2% | 9.0% | 0 | 390 | 0.0005 |
| baseline_rules | 63.8% | 68.0% | 0 | 147 | 1.1889 |
| rules_plus_source | 66.8% | 70.0% | 13 | 147 | 4.1178 |
| rules_plus_taint | 88.2% | 91.0% | 13 | 40 | 4.8939 |
| ct_trm_without_chain | 88.8% | 89.0% | 0 | 56 | 4.9869 |
| full_ct_trm | 100.0% | 100.0% | 0 | 0 | 4.3288 |

Full CT-TRM differs from baseline rules by 36.2 percentage points on the current 500-case set and reduces false negatives by 147 cases. Full mode detected 159 taint flows and
145 chain-risk cases.

The detailed category table is in `reports/ct_trm/category_breakdown.csv`.
False positives, false negatives, and suggested fixes are preserved in
`reports/ct_trm/failures.md`.

These percentages describe agreement with expected decisions on the current
self-built benchmark only. They do not establish protection against every
unknown attack.
