# CT-TRM Threshold Sensitivity

Hard-deny rules are not changed by this scan. Only score-to-action Ask/Deny boundaries are varied.

- Recommended ask_threshold: `25`
- Recommended deny_threshold: `60`
- Recommendation score: `80.5553`
- Robust regions: 24
- Overfit-risk regions: 0

| Ask | Deny | Status | Score | Dev Acc | Fixed Acc | Holdout Acc | Redteam Acc |
|---:|---:|---|---:|---:|---:|---:|---:|
| 20 | 60 | robust_region | 80.5553 | 100.0% | 96.83% | 100.0% | 100.0% |
| 20 | 65 | robust_region | 80.5553 | 100.0% | 96.62% | 100.0% | 100.0% |
| 20 | 70 | robust_region | 80.5553 | 100.0% | 95.98% | 100.0% | 100.0% |
| 20 | 75 | robust_region | 80.5553 | 100.0% | 95.77% | 100.0% | 100.0% |
| 25 | 60 | robust_region | 80.5553 | 100.0% | 96.83% | 100.0% | 100.0% |
| 25 | 65 | robust_region | 80.5553 | 100.0% | 96.62% | 100.0% | 100.0% |
| 25 | 70 | robust_region | 80.5553 | 100.0% | 95.98% | 100.0% | 100.0% |
| 25 | 75 | robust_region | 80.5553 | 100.0% | 95.77% | 100.0% | 100.0% |
| 30 | 60 | robust_region | 80.5553 | 100.0% | 96.83% | 100.0% | 100.0% |
| 30 | 65 | robust_region | 80.5553 | 100.0% | 96.62% | 100.0% | 100.0% |
| 30 | 70 | robust_region | 80.5553 | 100.0% | 95.98% | 100.0% | 100.0% |
| 30 | 75 | robust_region | 80.5553 | 100.0% | 95.77% | 100.0% | 100.0% |
| 35 | 60 | robust_region | 80.5553 | 100.0% | 96.83% | 100.0% | 100.0% |
| 35 | 65 | robust_region | 80.5553 | 100.0% | 96.62% | 100.0% | 100.0% |
| 35 | 70 | robust_region | 80.5553 | 100.0% | 95.98% | 100.0% | 100.0% |
| 35 | 75 | robust_region | 80.5553 | 100.0% | 95.77% | 100.0% | 100.0% |
| 20 | 50 | robust_region | 79.0868 | 97.33% | 96.41% | 96.67% | 100.0% |
| 20 | 55 | robust_region | 79.0868 | 97.33% | 96.41% | 96.67% | 100.0% |
| 25 | 50 | robust_region | 79.0868 | 97.33% | 96.41% | 96.67% | 100.0% |
| 25 | 55 | robust_region | 79.0868 | 97.33% | 96.41% | 96.67% | 100.0% |
| 30 | 50 | robust_region | 79.0868 | 97.33% | 96.41% | 96.67% | 100.0% |
| 30 | 55 | robust_region | 79.0868 | 97.33% | 96.41% | 96.67% | 100.0% |
| 35 | 50 | robust_region | 79.0868 | 97.33% | 96.41% | 96.67% | 100.0% |
| 35 | 55 | robust_region | 79.0868 | 97.33% | 96.41% | 96.67% | 100.0% |
