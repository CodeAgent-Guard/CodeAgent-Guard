# CT-TRM 消融评测报告

生成时间：2026-06-23T08:29:19.356383+00:00

## 总体指标

| 模式 | 用例 | 准确率 | Allow | Ask | Deny | FP | FN | Taint Flow | Chain Risk | Avg ms | P95 ms |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| `baseline_rules` | 50 | 54.0% | 19 | 10 | 21 | 0 | 17 | 0 | 0 | 0.602 | 2.1732 |
| `rules_plus_source` | 50 | 60.0% | 7 | 22 | 21 | 0 | 17 | 0 | 0 | 1.2135 | 3.6818 |
| `full_ct_trm` | 50 | 100.0% | 5 | 7 | 38 | 0 | 0 | 17 | 12 | 1.6455 | 5.4019 |

## Full CT-TRM 分类结果

| 分类 | 用例 | 通过 | Allow | Ask | Deny |
|---|---:|---:|---:|---:|---:|
| dangerous_shell | 5 | 5 | 0 | 0 | 5 |
| indirect_prompt_injection | 5 | 5 | 0 | 0 | 5 |
| multi_step_chain | 5 | 5 | 0 | 1 | 4 |
| normal_task | 5 | 5 | 5 | 0 | 0 |
| package_script_poisoning | 5 | 5 | 0 | 0 | 5 |
| path_escape | 5 | 5 | 0 | 0 | 5 |
| secret_exfiltration | 5 | 5 | 0 | 0 | 5 |
| ssrf | 5 | 5 | 0 | 0 | 5 |
| task_misalignment | 5 | 5 | 0 | 4 | 1 |
| tool_output_taint | 5 | 5 | 0 | 2 | 3 |

## 可观测差异

- 新增污染传播检测：17
- 新增调用链风险检测：12
- 漏报减少：17
- 准确率变化：46.0 个百分点

## 口径

- `baseline_rules`：仅运行原有参数级规则。
- `rules_plus_source`：加入来源风险评分，不启用传播与序列状态。
- `full_ct_trm`：启用来源、实体、传播、任务预算、风险模式与序列检测。
- 全部样本使用临时 workspace、fake_home、fake_root 和 example.test，不执行工具、不访问网络、不发送邮件。
