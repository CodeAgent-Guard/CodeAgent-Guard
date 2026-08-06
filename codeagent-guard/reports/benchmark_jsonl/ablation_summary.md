# CT-TRM Ablation Evaluation

## Dataset

- Cases: 473
- Dev/regression/holdout are reported separately in each JSON result.
- Dangerous operations are policy inputs only; no real network, email, secret
  file, or destructive command is executed.

## Ablation Summary

| Mode | Cases | Accuracy | Holdout | FP | FN | Taint | Chain | P95 ms |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| full_ct_trm | 473 | 97.04% | 0.0% | 4 | 4 | 86 | 0 | 3.0792 |

## Full CT-TRM Category Breakdown

| Category | Total | Passed | Allow | Ask | Deny | FP | FN |
|---|---:|---:|---:|---:|---:|---:|---:|
| A. 正常任务 (Benign) | 55 | 50 | 50 | 5 | 0 | 4 | 0 |
| B. 单步直接攻击 | 50 | 50 | 0 | 0 | 50 | 0 | 0 |
| C. 多轮诱导攻击 | 30 | 29 | 4 | 6 | 20 | 0 | 0 |
| D. 间接提示注入 | 50 | 50 | 2 | 6 | 42 | 0 | 0 |
| E. 工具输出污染 | 30 | 27 | 0 | 1 | 29 | 0 | 0 |
| F. 路径穿越攻击 | 40 | 39 | 1 | 2 | 37 | 0 | 1 |
| G. 符号链接与特殊文件攻击 | 28 | 24 | 3 | 11 | 14 | 0 | 3 |
| H. 编码与分段 Payload | 30 | 30 | 0 | 0 | 30 | 0 | 0 |
| I. 外部邮箱伪装攻击 | 20 | 20 | 0 | 10 | 10 | 0 | 0 |
| J. SSRF 与云元数据攻击 | 40 | 40 | 0 | 1 | 39 | 0 | 0 |
| K. 危险 Shell 管道与命令注入 | 30 | 30 | 0 | 0 | 30 | 0 | 0 |
| L. Package/Script 投毒攻击 | 30 | 30 | 0 | 16 | 14 | 0 | 0 |
| M. 绕过与边缘案例 | 40 | 40 | 0 | 2 | 38 | 0 | 0 |

## Observable Difference

- Accuracy delta versus baseline rules: 0.0 percentage points.
- False-negative reduction versus baseline rules: 0 cases.
- Full mode taint detections: 86.
- Full mode chain-risk detections: 0.

## Failure Analysis

- False positives: 4
- False negatives: 4
- Detailed cases and suggested fixes are retained in `failures.md` and the
  per-mode JSON files.

## Scope

The reported percentages describe expected-decision agreement on the current
self-built benchmark only. They are not proof of absolute security and cannot
be generalized to all unknown attacks. Container, namespace, seccomp, or VM
isolation remains necessary for defense in depth.
