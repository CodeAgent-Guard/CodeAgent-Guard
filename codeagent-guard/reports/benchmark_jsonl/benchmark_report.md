# benchmark.jsonl Evaluation

## Scope

- Input cases: 473
- Malicious: 352
- Benign/confirmation: 121
- Policy decisions only; no tool is executed.
- Tainted samples register their argument payload as untrusted source context.
- Missing filesystem and prior-turn setup is not inferred from expected labels.

## Core Metrics

| Mode | Exact | Accuracy | Malicious block | Intervention | FPR | FNR | Deny F1 | P95 ms |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| baseline_rules | 329/473 | 69.56% | 75.0% | 91.76% | 23.14% | 25.0% | 81.99% | 1.0009 |
| full_ct_trm | 345/473 | 72.94% | 79.55% | 98.01% | 23.14% | 20.45% | 84.85% | 3.1974 |

## Full CT-TRM Confusion Matrix

| Expected / Actual | Allow | Ask | Deny |
|---|---:|---:|---:|
| allow | 34 | 25 | 0 |
| ask | 3 | 31 | 28 |
| deny | 7 | 65 | 280 |

## Full CT-TRM Category Breakdown

| Category | Exact | Denied | FP | FN |
|---|---:|---:|---:|---:|
| A. 正常任务 (Benign) | 30/55 | 0 | 0 | 0 |
| B. 单步直接攻击 | 26/50 | 26 | 0 | 24 |
| C. 多轮诱导攻击 | 22/30 | 26 | 7 | 0 |
| D. 间接提示注入 | 44/50 | 48 | 6 | 0 |
| E. 工具输出污染 | 26/30 | 30 | 4 | 0 |
| F. 路径穿越攻击 | 32/40 | 30 | 0 | 8 |
| G. 符号链接与特殊文件攻击 | 12/28 | 14 | 7 | 9 |
| H. 编码与分段 Payload | 25/30 | 25 | 0 | 5 |
| I. 外部邮箱伪装攻击 | 12/20 | 10 | 3 | 3 |
| J. SSRF 与云元数据攻击 | 38/40 | 37 | 0 | 2 |
| K. 危险 Shell 管道与命令注入 | 18/30 | 18 | 0 | 12 |
| L. Package/Script 投毒攻击 | 24/30 | 10 | 1 | 5 |
| M. 绕过与边缘案例 | 36/40 | 34 | 0 | 4 |

## Metric Definitions

- Accuracy: exact `allow/ask/deny` agreement.
- Malicious block rate: malicious samples classified `deny`.
- Intervention rate: malicious samples classified `ask` or `deny`.
- FPR: benign/confirmation samples incorrectly classified `deny`.
- FNR: malicious samples not classified `deny`.
- Deny precision/recall/F1: binary metrics with `deny` as the positive class.

The detailed failures are in `full_ct_trm_failures.jsonl`. These results apply
only to the supplied dataset and current deterministic policy implementation.
