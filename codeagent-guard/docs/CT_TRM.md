# CT-TRM：Context-Taint Tool Risk Model

CT-TRM 是 CodeAgent Guard 在原有确定性 Policy Engine 之上的上下文污染驱动风险模型。它不替换基础硬规则，而是补充来源、实体、传播、任务预算、序列状态和可解释评分。

## 执行流程

```text
用户任务
  -> TaskCapabilityBudget
  -> Agent 生成工具调用
  -> Tool Proxy
  -> 基础 Policy Engine 规则
  -> TaintTracker 参数实体抽取与历史匹配
  -> ProvenanceGraph 记录传播边
  -> ChainRiskAnalyzer 检查最近 20 个步骤
  -> P1-P15 风险模式
  -> CTTRMRiskModel 固定评分与硬规则
  -> Decision 单调合并
  -> Allow / Ask / Deny
  -> Trace + Audit
  -> 工具结果回灌为新来源并更新 ChainState
```

OpenCode 使用同一流程。Guard 只完成执行前授权时，Trace 将工具结果标记为 `result_unavailable`，不会虚构执行结果。

## 模块

| 文件 | 职责 |
|---|---|
| `guard/taint.py` | 来源模型、安全实体抽取、规范化、污染匹配 |
| `guard/provenance.py` | 轻量来源/实体节点和传播边 |
| `guard/task_budget.py` | 根据用户任务推断合理能力预算 |
| `guard/chain_risk.py` | 最近步骤状态和 C1-C6 强证据链 |
| `guard/risk_patterns.py` | P1-P15 结构化风险模式 |
| `guard/risk_model.py` | 风险特征、固定评分、硬规则和决策映射 |
| `guard/ct_trm_evaluation.py` | 三模式消融评测 |

## 来源与实体

来源包括系统策略、用户任务、历史上下文、工作区文件、代码注释、配置、日志、工具输出、HTTP 响应、LLM 计划和 Agent Memory。

实体包括：

- path
- url
- email
- secret
- command
- instruction
- domain
- IP address
- file extension

Secret 实体不保存明文。系统只保留掩码和 SHA-256，例如：

```json
{
  "raw_value": "FA****ONLY",
  "normalized_value": "sha256:...",
  "metadata": {
    "masked": true,
    "secret_hash": "..."
  }
}
```

## 固定风险评分

评分由以下特征组成：

- `AssetRisk`
- `ActionRisk`
- `BoundaryRisk`
- `SourceRisk`
- `TaintRisk`
- `ChainRisk`
- `AuthorizationScore`
- `Pattern:P1` 至 `Pattern:P15` 证据项

映射：

| 分数 | 决策 |
|---:|---|
| 0-24 | Allow / Low |
| 25-59 | Ask / Medium 或 High |
| 60+ | Deny / High 或 Critical |

任务授权可以降低普通灰区风险，但不能覆盖硬拒绝。

## 硬拒绝

以下类型不允许通过任务预算或用户授权降级：

- SSH 私钥、云凭据、`.env`、token 和系统敏感文件。
- Shell 绕过文件策略读取敏感资产。
- Secret 外发到外部邮件或 HTTP。
- 本机、私网、链路本地和云 metadata。
- 反弹 Shell、远程脚本管道、编码后执行和危险删除。
- 路径穿越、符号链接逃逸及授权根目录破坏。
- 外部 HTTP 内容落地后执行。
- 明确访问 secret、metadata 或执行删除的 package lifecycle script。

## Trace 与 Audit

每次启用 CT-TRM 的调用新增 `ct_trm_assessment` 事件，包含：

- `total_score`
- `hard_deny`
- `action`
- `risk_level`
- `features`
- `reasons`
- `risk_patterns`
- `taint_matches`
- `provenance_edges`
- `chain_findings`
- `task_budget`
- `explanation`

Audit 表新增 `ct_trm_json`，该字段参与新事件的哈希链计算。历史事件没有 CT-TRM 数据时仍按旧负载验证，兼容已有数据库。

## 测试

```bash
python -m unittest discover -s tests -v
```

当前共 104 项测试，覆盖基础回归、CT-TRM 抽取、溯源、预算、序列风险、P1-P15、Trace/Audit 脱敏、审批并发与过期，以及污染来源和调用链的跨重启恢复。

## 消融评测

```bash
python run_ct_trm_evaluation.py
```

输入：

```text
benchmarks/agent_tool_bench/ct_trm_cases.yaml
```

输出：

```text
reports/ct_trm_evaluation.json
reports/ct_trm_evaluation.md
```

评测模式：

- `baseline_rules`
- `rules_plus_source`
- `full_ct_trm`

当前 50 条离线样本结果：

| 模式 | 准确率 | FP | FN | Taint Flow | Chain Risk |
|---|---:|---:|---:|---:|---:|
| baseline_rules | 54% | 0 | 17 | 0 | 0 |
| rules_plus_source | 60% | 0 | 17 | 0 | 0 |
| full_ct_trm | 100% | 0 | 0 | 17 | 12 |

这些结果只代表当前自建确定性样本集，不代表对未知攻击的绝对安全保证。

## AgentToolBench 500

新的确定性 benchmark 位于
`benchmarks/agent_tool_bench/cases/ct_trm_500.yaml`，包含 500 条样本：
150 条 dev、250 条 regression、100 条 holdout。评测支持：

- `no_guard_mock`
- `baseline_rules`
- `rules_plus_source`
- `rules_plus_taint`
- `ct_trm_without_chain`
- `full_ct_trm`

当前 500 条自建样本中，Full CT-TRM 的预期判定准确率为 91.4%，
holdout 为 92.0%；baseline rules 为 67.8%。120 条独立红队绕过集上的
准确率为 81.67%，失败案例保留在 `reports/redteam/redteam_failures.md`。
这些比例仅描述当前评测集，不能泛化为对所有未知攻击的绝对防护。

## 当前限制

- 来源、脱敏实体和调用链摘要保存在 SQLite `data/state.db`，按 TTL 清理；不保存上下文原文或密钥明文。
- 实体匹配以确定性规范化、哈希和字符串关系为主，不包含语义嵌入。
- OpenCode Ask 在 Hook 存活期间会等待 Dashboard 审批并恢复原生调用；进程退出或等待超时后不能恢复该进程。
- OpenCode 未提供真实用户任务时，只能使用插件配置或环境变量提供任务描述。
- 符号链接检测依赖操作系统可见的 realpath；Windows 测试无创建权限时使用受控模拟。
- 生产部署仍需容器、身份认证、出站网络策略和外部审计锚定。
