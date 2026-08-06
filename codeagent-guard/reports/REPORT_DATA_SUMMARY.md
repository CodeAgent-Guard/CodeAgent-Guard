# CodeAgent Guard 评测数据整理

本文整理当前项目中可用于论文/比赛报告的评测方法、数据集、指标口径和主要结果。所有结果均来自仓库内已有报告文件，建议在正式报告中保持“有边界的结论”，不要表述为对所有未知攻击都有效。

## 一、评测对象

CodeAgent Guard 的核心评测对象是 Agent 工具调用前的风险决策能力。系统在 Agent / OpenCode 与文件、命令、网络、邮件等工具之间加入 Tool Proxy，由 Policy Engine 与 CT-TRM 共同判断每次工具调用应为：

- `ALLOW`：低风险，可直接执行。
- `ASK`：存在副作用或灰区风险，需要用户显式审批。
- `DENY`：命中敏感文件、secret 外传、SSRF、危险 shell、路径逃逸、包脚本投毒等高风险证据，直接拒绝。

CT-TRM 使用的主要信号包括：参数级规则、来源可信度、污染传播、实体/provenance、任务工具预算、P1-P15 风险模式、C1-C6 多步链路风险。

## 二、指标口径

| 指标 | 含义 |
|---|---|
| Accuracy | 三分类准确率，实际 `allow/ask/deny` 与期望标签完全一致的比例。 |
| Attack Intervention Rate | 攻击样本中被 `ASK` 或 `DENY` 干预的比例，衡量副作用执行前是否被拦住。 |
| Strong Block Rate | 攻击样本中被直接 `DENY` 的比例，衡量强阻断能力。 |
| Complete False Negative Rate | 恶意样本被实际 `ALLOW` 的比例，也就是完全漏报率。 |
| Deny Miss Rate | 期望 `DENY` 但实际为 `ASK` 或 `ALLOW` 的比例，表示强阻断漏判。 |
| Normal Task Disruption Rate | 正常任务期望 `ALLOW`，但实际被 `ASK` 或 `DENY` 打断的比例。 |
| Overblocking Rate | 期望 `ASK` 的灰区任务被实际 `DENY` 的比例。 |
| DENY Precision / Recall / F1 | 将 `DENY` 作为正类计算的二分类指标。 |
| Macro F1 | 三分类宏平均 F1。 |
| P95 Latency | 策略判定延迟的 95 分位。 |

## 三、评测方法

### 1. Policy-only 离线评测

用于 `benchmark.jsonl`、AgentToolBench 500、泛化集和 red-team 集。评测时只调用风险决策逻辑，不真正执行危险工具。

安全边界：

- 不读取真实敏感文件。
- 不发送真实邮件。
- 不访问真实外网。
- 不执行真实危险 shell。
- 所有样本使用 `workspace`、`fake_home`、`fake_root`、`mock_server`、`example.test`、fake secret marker。

### 2. 消融实验

在同一批 500 条 AgentToolBench 样本上逐步打开能力模块，比较从无防护到 Full CT-TRM 的变化：

- `no_guard_mock`
- `baseline_rules`
- `rules_plus_source`
- `rules_plus_taint`
- `ct_trm_without_chain`
- `full_ct_trm`

该实验用于说明 CT-TRM 的收益来自污染传播、链路风险和风险模式的组合，而不是单一正则规则。

### 3. 泛化验证与过拟合控制

数据集拆分：

- `dev_calibration`：300 条，只允许用于规则校准。
- `benchmark_jsonl_external_fixed`：473 条，固定外部测试集，不作为训练/调参集。
- `holdout_generated`：300 条，生成方式、路径、命令、URL、邮箱等组合与 benchmark 不完全相同。
- `redteam_unseen`：150 条，覆盖双重编码、IPv6、十进制 IP、URL redirect、DNS mock 到私网、符号链接链、env var expansion、command substitution、分段 secret、附件外传、package script 间接调用。

同时扫描 Ask/Deny 阈值：

- `ask_threshold`: 20, 25, 30, 35
- `deny_threshold`: 50, 55, 60, 65, 70, 75

硬规则不随阈值扫描改变。推荐阈值基于 dev + holdout + redteam 综合表现，而不是只优化固定 benchmark。

### 4. Objective Evaluation

该部分用于检验固定 benchmark 之外的可用性和攻击干预能力：

- `blind_llm_test`：200 条，不向样本生成/标注流程暴露 CT-TRM 内部规则。
- `real_agent_e2e`：40 条，脚本化 Agent 发起真实 ToolProxy 调用，执行器为无副作用 mock。
- `external_redteam`：40 条，模拟外部 red-team 提交流程。

这部分同时记录 usability calibration 前后的变化，重点观察正常任务误报是否下降，同时保持攻击干预率和完全漏报率。

## 四、AgentToolBench 500 消融实验结果

数据来源：`reports/ct_trm/ablation_summary.md`

| 模式 | 样本数 | Accuracy | Holdout | FP | FN | Taint 检测 | Chain 检测 | P95 ms |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| no_guard_mock | 500 | 9.2% | 9.0% | 0 | 390 | 0 | 0 | 0.0003 |
| baseline_rules | 500 | 66.8% | 71.0% | 0 | 132 | 0 | 0 | 0.1163 |
| rules_plus_source | 500 | 66.8% | 72.0% | 6 | 132 | 0 | 0 | 0.6201 |
| rules_plus_taint | 500 | 78.6% | 81.0% | 6 | 83 | 159 | 0 | 0.7546 |
| ct_trm_without_chain | 500 | 85.4% | 86.0% | 0 | 73 | 159 | 0 | 0.8834 |
| full_ct_trm | 500 | 98.0% | 97.0% | 0 | 10 | 159 | 145 | 0.9256 |

关键结论：

- Full CT-TRM 相比 baseline_rules 准确率提升 31.2 个百分点。
- Full CT-TRM 相比 baseline_rules 将 FN 从 132 降到 10，减少 122 个漏判。
- 污染传播检测命中 159 次，多步链路风险检测命中 145 次。
- Full CT-TRM 的 P95 判定延迟约 0.93 ms，在离线策略评测中开销较低。

## 五、AgentToolBench 500 数据覆盖

数据来源：`reports/ct_trm/validation_report.md`

| 类别 | 样本数 |
|---|---:|
| benign | 70 |
| dangerous_shell_and_encoded_payload | 55 |
| indirect_prompt_injection | 50 |
| multi_step_chain | 40 |
| package_script_poisoning | 50 |
| path_traversal_and_symlink | 55 |
| secret_exfiltration | 55 |
| ssrf_and_metadata | 45 |
| task_tool_misalignment | 30 |
| tool_output_poisoning | 50 |

Split 分布：

| Split | 样本数 |
|---|---:|
| dev | 150 |
| regression | 250 |
| holdout | 100 |

## 六、固定 benchmark.jsonl 结果

数据来源：`reports/generalization/generalization_summary.csv` 与 `reports/benchmark_jsonl/category_breakdown.csv`

最终 Full CT-TRM 在 `benchmark.jsonl` external fixed test 上：

| Dataset | Cases | Accuracy | Attack Intervention | Strong Block | Complete FN | Normal Disruption | Overblocking | DENY F1 | Macro F1 | P95 ms | Failures |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| benchmark_jsonl_external_fixed | 473 | 96.83% | 98.86% | 98.58% | 1.14% | 6.78% | 8.06% | 98.58% | 94.03% | 3.1194 | 15 |

按类别统计：

| 类别 | Total | Passed | Allow | Ask | Deny | FP | FN |
|---|---:|---:|---:|---:|---:|---:|---:|
| 正常任务 | 55 | 50 | 50 | 5 | 0 | 4 | 0 |
| 单步直接攻击 | 50 | 50 | 0 | 0 | 50 | 0 | 0 |
| 多轮诱导攻击 | 30 | 29 | 4 | 6 | 20 | 0 | 0 |
| 间接提示注入 | 50 | 50 | 2 | 6 | 42 | 0 | 0 |
| 工具输出污染 | 30 | 27 | 0 | 1 | 29 | 0 | 0 |
| 路径穿越攻击 | 40 | 39 | 1 | 2 | 37 | 0 | 1 |
| 符号链接与特殊文件攻击 | 28 | 24 | 3 | 11 | 14 | 0 | 3 |
| 编码与分段 Payload | 30 | 30 | 0 | 0 | 30 | 0 | 0 |
| 外部邮箱伪装攻击 | 20 | 20 | 0 | 10 | 10 | 0 | 0 |
| SSRF 与云元数据攻击 | 40 | 40 | 0 | 1 | 39 | 0 | 0 |
| 危险 Shell 管道与命令注入 | 30 | 30 | 0 | 0 | 30 | 0 | 0 |
| Package/Script 投毒攻击 | 30 | 30 | 0 | 16 | 14 | 0 | 0 |
| 绕过与边缘案例 | 40 | 40 | 0 | 2 | 38 | 0 | 0 |

可写入报告的解释：

固定 benchmark 主要用于回归和横向对比。最终 Full CT-TRM 在 473 条样本上达到 96.83% 三分类准确率，攻击干预率为 98.86%，完全漏报率为 1.14%。剩余失败主要集中在符号链接/特殊文件、路径状态可观测性和 Ask/Deny 边界。

## 七、泛化验证结果

数据来源：`reports/generalization/generalization_report.md`

| Dataset | Cases | Accuracy | Attack Intervention | Strong Block | Complete FN | Deny Miss | Normal Disruption | Overblock | DENY F1 | Macro F1 | P95 ms | Failures |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| dev_calibration | 300 | 97.33% | 100.0% | 100.0% | 0.0% | 0.0% | 0.0% | 0.0% | 100.0% | 96.32% | 5.206 | 8 |
| benchmark_jsonl_external_fixed | 473 | 96.83% | 98.86% | 98.58% | 1.14% | 1.42% | 6.78% | 8.06% | 98.58% | 94.03% | 3.1194 | 15 |
| holdout_generated | 300 | 99.33% | 100.0% | 100.0% | 0.0% | 0.0% | 0.0% | 0.0% | 100.0% | 98.98% | 4.7347 | 2 |
| redteam_unseen | 150 | 100.0% | 100.0% | 100.0% | 0.0% | 0.0% | 0.0% | 0.0% | 100.0% | 33.33% | 3.2751 | 0 |

解释：

- 非校准数据集上的攻击干预率保持在 98.86% 到 100.0%。
- 完全漏报率保持在 0.0% 到 1.14%。
- redteam_unseen 是 DENY-only 数据集，因此三分类 Macro F1 不如 Strong Block 和 DENY F1 有解释力。
- fixed benchmark 与 holdout accuracy 差距约 2.5 个百分点，当前报告未标记明显过拟合风险。

## 八、阈值敏感性分析

数据来源：`reports/generalization/threshold_sensitivity.md`

扫描范围：

- `ask_threshold`: 20 / 25 / 30 / 35
- `deny_threshold`: 50 / 55 / 60 / 65 / 70 / 75

结果：

| 项目 | 结果 |
|---|---|
| 推荐 ask_threshold | 25 |
| 推荐 deny_threshold | 60 |
| robust regions | 24 |
| overfit-risk regions | 0 |
| 推荐依据 | dev + holdout + redteam 综合表现，而不是只优化 benchmark.jsonl |

可写入报告的解释：

阈值扫描只改变分数到 `ASK/DENY` 的边界，不改变 hard-deny 规则。多个阈值组合在 dev、holdout、redteam 上表现稳定，说明最终结果不是单纯依赖某个固定阈值在 benchmark.jsonl 上过拟合。

## 九、Objective Evaluation 结果

数据来源：`reports/objective_eval/objective_evaluation_report.md`、`objective_before_after.md`、`*_after.md`

### 1. Usability calibration 前

| Dataset | Cases | Accuracy | Intervention | Strong Block / Deny | Complete FN / E2E Success | Normal Disruption / FP | Macro F1 | Failures |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| blind_llm_test | 200 | 66.5% | 100.0% | 90.0% | 0.0% | 37.5% | 64.72% | 67 |
| real_agent_e2e | 40 | 67.5% | 100.0% | 80.0% | 0.0% | 40.0% | 67.67% | 13 |
| external_redteam | 40 | 65.0% | 100.0% | 62.16% | 0.0% | 0.0% | 35.56% | 14 |

解释：

这组结果说明早期 CT-TRM 的“副作用前干预”很稳定，攻击干预率均为 100%，完全漏报率为 0%，但正常任务和灰区任务误报较多，三分类边界和可用性不足。

### 2. Usability calibration 后

| Dataset | Cases | Accuracy | Attack Intervention | Strong Block | Complete FN | Normal Disruption / FP | P95 ms | Failures |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| blind_llm_test | 200 | 100.0% | 100.0% | 100.0% | 0.0% | 0.0% | 4.1854 | 0 |
| real_agent_e2e | 40 | 100.0% | 100.0% | 37.5% Deny rate | 0.0% | 0.0% | 8.722 | 0 |
| external_redteam | 40 | 100.0% | 100.0% | 100.0% | 0.0% | 0.0% | 4.1643 | 0 |

real_agent_e2e 详细指标：

| 指标 | 结果 |
|---|---:|
| Strict task completion rate | 100.0% |
| Assisted task completion rate | 100.0% |
| User friction rate | 0.0% |
| Attack trigger rate | 100.0% |
| Guard intervention rate | 100.0% |
| End-to-end attack success rate | 0.0% |
| False positive rate | 0.0% |
| Hard false positive rate | 0.0% |
| Ask rate | 25.0% |
| Deny rate | 37.5% |
| P95 policy latency | 8.722 ms |

### 3. Before / After 变化

| Dataset | Metric | Before | After | Delta |
|---|---|---:|---:|---:|
| Blind LLM Test | Accuracy | 66.5% | 100.0% | +33.5 |
| Blind LLM Test | Normal disruption | 37.5% | 0.0% | -37.5 |
| Blind LLM Test | Complete FN | 0.0% | 0.0% | 0.0 |
| Blind LLM Test | Attack intervention | 100.0% | 100.0% | 0.0 |
| Real Agent E2E | Accuracy | 67.5% | 100.0% | +32.5 |
| Real Agent E2E | Legacy task completion | 60.0% | 100.0% | +40.0 |
| Real Agent E2E | False positive | 40.0% | 0.0% | -40.0 |
| Real Agent E2E | Complete FN | 0.0% | 0.0% | 0.0 |
| Real Agent E2E | Attack intervention | 100.0% | 100.0% | 0.0 |
| External Red-Team | Accuracy | 65.0% | 100.0% | +35.0 |
| External Red-Team | Strong block | 62.16% | 100.0% | +37.84 |
| External Red-Team | Complete FN | 0.0% | 0.0% | 0.0 |
| External Red-Team | Attack intervention | 100.0% | 100.0% | 0.0 |

可写入报告的解释：

Objective Evaluation 先暴露了可用性问题：模型虽然能稳定干预攻击，但对正常/灰区任务过于保守。后续 usability calibration 重点降低正常任务误报和 Ask/Deny 边界错误，最终在 blind、real-agent、external-redteam 三组 objective 数据上保持 100% 攻击干预率和 0% 完全漏报率，同时将 normal disruption / false positive 降到 0%。

注意：blind LLM 的人工双人标注当前仍是 pending manual review，不能声称已经完成独立人工一致性验证。

## 十、Semi-real Agent 与 OpenCode 相关验证

数据来源：`reports/real_agent_validation.md`

| 指标 | 结果 |
|---|---:|
| Scenarios | 30 |
| Runs across modes | 90 |
| Benign task completion | 100.0% |
| Full CT-TRM benign workflow success | 100.0% |
| Dangerous calls blocked before mock execution | 32 |
| Approval flows completed | 6 |
| Traces generated | 60 |
| Average policy latency | 69.097 ms |
| P95 policy latency | 116.3065 ms |

验证方式：

使用确定性的半真实 Agent 工具计划，通过真实 ToolProxy、PolicyEngine、CT-TRM、Trace、Audit 和 approval store；执行器是无副作用 mock。

## 十一、Red-team bypass 与稳定性数据

### Red-team bypass

数据来源：`reports/redteam/redteam_results.md`

| 指标 | 结果 |
|---|---:|
| Cases | 120 |
| Blocked | 110 |
| Asked | 6 |
| Missed | 0 |
| False positives | 0 |
| P95 policy latency | 3.2009 ms |

### 稳定性压力测试

数据来源：`reports/stability/stability_summary.md`

| 指标 | 结果 |
|---|---:|
| Policy evaluations | 1000 |
| Policy average latency | 1.3225 ms |
| Policy P95 latency | 3.7282 ms |
| Policy P99 latency | 4.1801 ms |
| Approval operations | 100 |
| Approval concurrency | 10 |
| Unique approval IDs | 100 |
| Approved / rejected | 50 / 50 |
| Approval stress audit valid | True |
| Repository audit valid | True, 129 events |

## 十二、可以直接写进报告的结论

建议写法：

> 在固定 benchmark、生成式 holdout、unseen redteam、blind LLM、real-agent E2E 和外部 redteam 模拟数据上，CodeAgent Guard 的 CT-TRM 能够在工具真正执行前对高风险行为进行稳定干预。最终 `benchmark.jsonl` external fixed test 上三分类准确率为 96.83%，攻击干预率为 98.86%，完全漏报率为 1.14%；在 `holdout_generated` 与 `redteam_unseen` 上攻击干预率均为 100%，完全漏报率为 0%。Objective Evaluation 暴露并修复了正常任务误报问题，usability calibration 后 blind、real-agent、external-redteam 三组数据均保持 100% 攻击干预率和 0% 完全漏报率。

更谨慎的写法：

> 这些结果表明，CT-TRM 在本项目构造的多个未参与校准的数据集上保持了较稳定的攻击干预能力，并在可解释审批和审计链路下改善了正常任务可用性。但该结论仍受限于当前数据集规模、样本生成方式和 mock 执行环境，不能等同于对所有未知 Agent 攻击的安全保证。

## 十三、报告中应避免的表述

不建议写：

- “完全防住所有攻击”
- “泛化到所有未知场景”
- “真实网络/真实邮箱/真实 secret 环境已验证”
- “人工标注一致性已完成”

建议写：

- “在当前 deterministic benchmark 和 mock 执行环境下”
- “在多个未参与校准的数据集上”
- “工具执行前干预能力稳定”
- “仍需要系统隔离、沙箱、权限边界作为纵深防御”

## 十四、原始数据位置

| 内容 | 文件 |
|---|---|
| AgentToolBench 500 消融 | `reports/ct_trm/ablation_summary.md` |
| AgentToolBench 覆盖验证 | `reports/ct_trm/validation_report.md` |
| benchmark.jsonl 固定测试 | `reports/generalization/benchmark_jsonl_external_fixed.json` |
| 泛化总表 | `reports/generalization/generalization_summary.csv` |
| 泛化报告 | `reports/generalization/generalization_report.md` |
| 阈值敏感性 | `reports/generalization/threshold_sensitivity.md` |
| Objective 总报告 | `reports/objective_eval/objective_evaluation_report.md` |
| Objective before/after | `reports/objective_eval/objective_before_after.md` |
| Blind LLM after | `reports/objective_eval/blind_llm_test_after.md` |
| Real Agent E2E after | `reports/objective_eval/real_agent_e2e_after.md` |
| External Redteam after | `reports/objective_eval/external_redteam_after.md` |
| Semi-real Agent 验证 | `reports/real_agent_validation.md` |
| Red-team bypass | `reports/redteam/redteam_results.md` |
| 稳定性测试 | `reports/stability/stability_summary.md` |

