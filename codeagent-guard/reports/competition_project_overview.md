# CodeAgent Guard 参赛项目说明

> 材料基线：Git 提交 `79f0de1` 及当前 CT-TRM 工作区实现
> 核验日期：2026-06-22
> 项目定位：面向 AI 编程智能体的工具调用安全网关与可审计执行平台

## 1. 项目名称

**CodeAgent Guard：面向 AI 编程智能体的工具调用安全网关**

一句话介绍：

> 在 AI Agent 与文件、命令、网络、邮件等高风险工具之间建立独立安全边界，对每次工具调用执行参数级检查、Allow/Ask/Deny 决策、人工审批、审计留痕和攻击复现。

## 2. 背景与问题

AI 编程智能体不仅生成文本，还可以读取文件、修改代码、执行 Shell、访问网络和发送信息。仓库 README、代码注释、日志、配置文件及工具输出均可能被攻击者植入提示注入内容，诱导 Agent：

- 越权读取 SSH 私钥、环境变量或系统文件。
- 执行远程脚本、反弹 Shell 或破坏性命令。
- 访问本机、私网及云元数据服务，形成 SSRF。
- 将 API Key、密码或私钥发送到外部地址。
- 绕过当前任务的工具授权，调用不应使用的能力。

仅依赖模型“自觉拒绝”不能形成稳定安全边界。本项目把安全判断从 Agent 推理中分离出来，由独立的 Tool Proxy 和 Policy Engine 在实际副作用发生前强制执行。

## 3. 目标与适用场景

项目目标：

1. 所有高风险工具调用必须经过统一安全入口。
2. 安全策略不依赖具体模型或 Agent，可独立替换和复用。
3. 低风险操作自动放行，中高风险操作询问用户，明确恶意操作直接拒绝。
4. 每次计划、决策、执行、审批和结果都可查询、回放和校验。
5. 支持内置 Agent，也能接入 OpenCode 等外部 Agent。

适用场景：

- AI 编程助手和自动化代码 Agent。
- 企业内部研发终端与受控工作区。
- 安全测试、红队攻击复现和策略评估。
- 需要人工审批与审计追责的 Agent 自动化流程。

## 4. 总体架构

```text
用户
  |
  +-- 内置 Agent + LLM Provider
  |       |
  |       +-- ToolCall
  |
  +-- OpenCode
          |
          +-- tool.execute.before 插件
                  |
                  +-- OpenCodeToolProxyAdapter
                              |
                              v
                         Tool Proxy
                              |
                 +------------+------------+
                 |                         |
           Policy Engine              Transparency
          Allow / Ask / Deny          Trace Timeline
                 |
          +------+------+
          |             |
     Tool Executor   Delegated execution
     内置 Agent执行    OpenCode自行执行
          |
          v
   Audit SQLite + SHA-256 Hash Chain
```

关键设计：

- `server.py` 仅作为组合根，创建模块实例并注入依赖。
- Agent 只负责规划，不负责决定自身操作是否安全。
- Policy Engine 只做判定，不直接执行工具。
- Tool Executor 只接收已经归一化并获准的参数。
- OpenCode 接入通过 Adapter 完成工具名和参数映射，不侵入核心策略。
- Dashboard 依赖统一 Trace Event 协议，不绑定特定 Agent。

## 5. 核心模块

| 模块 | 代码位置 | 主要职责 |
|---|---|---|
| 内置 Agent | `guard/agent.py` | LLM 工具循环、上下文记忆、暂停与恢复、最终总结 |
| LLM Provider | `guard/providers.py` | 云端及本地 OpenAI/Anthropic 兼容模型接入 |
| 外部 Agent Adapter | `guard/adapters.py` | 外部调用标准化、OpenCode 工具映射 |
| Tool Proxy | `guard/tools.py` | 统一安全入口、策略编排、审批和审计 |
| Policy Engine | `guard/policy.py` | 参数级风险判断和 Allow/Ask/Deny 聚合 |
| CT-TRM | `guard/taint.py` 等六个模块 | 来源、实体、溯源、任务预算、序列风险和聚合 |
| Tool Catalog | `guard/catalog.py` | 工具 Schema 与可授权工具集合 |
| Tool Executor | `guard/executors.py` | 文件、命令、网络和邮件等实际副作用 |
| Audit Store | `guard/audit.py` | SQLite 审计记录与 SHA-256 前向哈希链 |
| Transparency | `guard/transparency.py` | Agent 无关的全链路事件和历史回放 |
| Evaluation | `guard/evaluation.py` | 100 条策略用例、指标计算和报告生成 |
| Dashboard | `frontend/` | 总览、Agent、评测、审计和策略管理 |
| OpenCode 插件 | `opencode/tool-proxy-plugin.js` | 在 OpenCode 原生工具执行前请求 Guard 授权 |

## 6. Tool Proxy 与策略核心

### 6.1 决策机制

`Decision` 默认状态为：

- `action = allow`
- `risk_level = low`

每条规则通过 `Decision.add(action, risk, reason)` 累积结果：

- `deny` 优先级最高。
- 当前为 `allow` 时，`ask` 可将结果升级为询问。
- 风险等级按 `low < medium < high < critical` 取最高值。
- 命中的原因去重保存，供前端解释和审计。

这使最终决策具备确定的单调升级特性：后续规则可以提高风险和处置级别，但不会意外把拒绝降级为允许。

### 6.2 主要检测维度

- 任务级工具白名单。
- 工作区、可信工作环境和外部授权目录边界。
- 路径归一化、路径穿越和敏感文件检测。
- API Key、密码、Token、私钥等敏感内容检测。
- 远程脚本、反弹 Shell、危险管道和破坏性命令检测。
- Shell 绕过文件与网络工具策略的检测。
- HTTP 协议、私网、本机、保留地址和云元数据 SSRF 检测。
- 外部邮件收件人审批和敏感信息外传阻断。
- 仓库内容、日志、配置及工具输出的 taint/不可信来源判断。
- 删除、移动、目录打开及状态变更操作的人工确认。

### 6.3 三类处置

| 决策 | 含义 | 示例 |
|---|---|---|
| Allow | 风险可接受，直接执行或授权外部 Agent 执行 | 工作区内普通文件读取 |
| Ask | 操作有合法用途但存在副作用，需要用户明确批准 | 外部收件人邮件、删除文件、外部目录写入 |
| Deny | 明确越权或高危，不允许用户审批绕过 | 私钥读取、路径穿越、反弹 Shell、密钥外传 |

### 6.4 CT-TRM 上下文污染风险模型

CT-TRM 在基础规则之后执行，回答参数来源、可信度、传播路径、任务一致性和多步攻击链问题。系统实现了 path、URL、email、secret、command 和 instruction 等实体抽取，维护 source/entity/tool argument 传播图，并检测 secret 外传、外部内容落地执行、工具输出诱导命令和 package lifecycle poisoning。风险由固定评分表和硬拒绝共同决定，任务授权扣分不能覆盖敏感资产、SSRF、secret 外传等硬规则。

## 7. 已接入工具

当前 Catalog 共 11 个工具：

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

执行侧保护包括：

- 命令最长运行 30 秒。
- Linux 环境设置 CPU、内存、文件大小和文件描述符限制。
- HTTP 请求设置超时并接受 SSRF 策略检查。
- 未配置 SMTP 时，邮件只写入本地 outbox，不宣称真实发送。
- 外部授权根目录本身不能被覆盖、移动或删除。
- 非空外部目录不能直接删除。

## 8. 可信工作环境

用户可以在 Dashboard 中选择额外的可信目录，配置会持久保存到 `data/trusted_workspaces.json`，并动态同步到 Policy Engine 和 Tool Executor，无需重启服务。

目录分为三种语义：

| 目录类型 | 用途 | 默认策略 |
|---|---|---|
| 项目工作区 | 当前受控项目 | 普通操作按规则 Allow/Ask/Deny |
| 可信工作环境 | 用户主动选择的长期工作目录 | 常规读写允许，危险变更仍需询问或拒绝 |
| 外部授权目录 | 临时外部 CRUD 范围 | 每次外部访问通常要求 Ask |

即使目录被设为可信，敏感文件、密钥外传、危险命令和根目录破坏仍不会被放行。

## 9. 上下文记忆与对话管理

内置 Agent 已实现连续上下文：

- 多轮问答保存在同一个 Conversation 中。
- 每轮问答对应独立 Trace，可展开查看完整执行链路。
- 历史对话可搜索和重新打开。
- 每轮问答在页面中使用折叠面板展示。
- 支持“新建上下文”，旧对话继续保留在历史列表。
- 上下文最大字符数可在 1,000 到 200,000 之间配置，默认 20,000。
- 使用量或累计量达到 80% 时显示接近上限提醒。
- 超过本次可带入量时只选择最近轮次，并提示新建上下文。
- 每个 Conversation 最多保存 100 轮问答。

当前内置 Agent 上下文保存于 `data/agent_contexts.json`。该文件属于本地私有运行数据，已被 `.gitignore` 排除。

## 10. OpenCode 接入方式

当前提交已实现 OpenCode 执行前授权：

1. OpenCode 准备执行原生工具。
2. `tool.execute.before` Hook 捕获工具名与参数。
3. 插件调用 `POST /api/opencode/authorize-tool`。
4. `OpenCodeToolProxyAdapter` 将原生工具映射为策略工具：
   - `bash` -> `run_command`
   - `read` -> `read_file`
   - `write` / `edit` -> `write_file`
   - `grep` -> `search_files`
   - `glob` -> `list_directory`
   - `webfetch` -> `http_request`
5. Guard 完成策略判定、Trace 记录和审计。
6. Allow 时，执行权返回 OpenCode，由 OpenCode 自己运行原生工具。
7. Deny 时插件抛出错误；Ask 时插件保持等待，直到 Dashboard 批准、拒绝或超时。

这条链路保留了模块独立性：

- OpenCode 负责 Agent 推理和原生工具执行。
- Guard 负责授权、风险判断、审批记录和审计。
- Adapter 只做协议与工具语义转换。

OpenCode 的 `Ask -> Dashboard 审批 -> 原始工具调用自动恢复` 已形成闭环。Hook 等待 Guard 的持久化审批状态，批准后返回并由 OpenCode 执行原生工具；Guard 不接管 OpenCode 的工具执行。若 OpenCode 进程退出或等待超时，则不能恢复已经终止的进程。

## 11. 可视化与全链路透明

Dashboard 当前包含五个主视图：

- **安全总览**：调用量、阻断量、风险分布、策略延迟和审计完整性。
- **Agent 控制台**：模型配置、工具授权、可信工作环境、连续对话和执行时间线。
- **评测中心**：生成并运行 100 条策略测试，展示准确率和误报率。
- **审计日志**：按 Trace 分组查询工具、参数、决策、原因、结果和哈希。
- **策略中心**：查看当前工作区、可信目录及主要策略范围。

单次 Trace 可记录：

1. 用户任务。
2. Agent 工具请求。
3. Policy Engine 判定。
4. Tool Proxy 行动。
5. 工具执行结果。
6. 用户审批结果。
7. Audit Hash Chain 记录。
8. Agent 最终总结。

## 12. 数据存储与隐私

当前正式源码使用以下存储：

| 数据 | 存储位置 | 是否提交 Git |
|---|---|---|
| 审计事件 | `data/audit.db` | 否 |
| Trace 元数据与事件 | `data/traces.db` | 否 |
| 内置 Agent 对话 | `data/agent_contexts.json` | 否 |
| 可信目录配置 | `data/trusted_workspaces.json` | 否 |
| 未真实发送的邮件 | `data/outbox/` | 否 |
| 策略评测报告 | `data/evaluation/`、`reports/` | 仅保留脱敏成果 |

说明：

- 当前提交没有使用统一的 `state.db` 作为运行时状态源。
- 本地若存在 `data/state.db`，属于遗留或实验数据，不应写入参赛功能说明。
- `.env`、API Key 文件、证书、邮件、数据库、日志、工作区和 Agent 私有状态均已在 `.gitignore` 中排除。
- 参赛打包前仍需人工执行一次密钥扫描，避免压缩工具绕过 Git 忽略规则。

## 13. 实测结果

基于当前提交于 2026-06-22 重新核验：

| 项目 | 结果 |
|---|---:|
| 单元测试 | 104/104 通过 |
| 策略回归用例 | 100 条 |
| 策略用例准确率 | 100% |
| 策略阻断率 | 100% |
| 误报率 FPR | 0% |
| 漏报率 FNR | 0% |
| 独立攻击场景 | 5 类 |
| 独立攻击阻断率 | 100% |
| 本机平均策略判定延迟 | 0.5904 ms |
| 本机 P95 策略判定延迟 | 1.8356 ms |
| 当前审计链 | 128 条，校验有效 |
| 隔离副本篡改实验 | 成功检测，定位到首个异常事件 |
| CT-TRM benchmark | 500 条主集 + 120 条红队绕过集 |
| Baseline / Full CT-TRM | 54% / 100% |
| Full CT-TRM FP / FN | 0 / 0 |
| 污染传播 / 序列风险 | 17 / 12 |

五类攻击场景：

| 场景 | 目标工具 | 结果 |
|---|---|---|
| README 提示注入读取 SSH 私钥 | `read_file` | Critical / Deny |
| 恶意代码注释执行远程脚本 | `run_command` | Critical / Deny |
| 扫描结果诱导 API Key 邮件外传 | `send_email` | Critical / Deny |
| 恶意日志诱导反弹 Shell | `run_command` | Critical / Deny |
| 配置文件路径穿越读取系统文件 | `read_file` | Critical / Deny |

指标说明：

- 延迟仅统计 Policy Engine 判定，不包含 LLM、网络和真实工具执行耗时。
- 当前测试集是项目自建规则回归集，不等同于第三方独立测评。
- 100% 结果应表述为“当前测试集结果”，不能泛化为对所有未知攻击的绝对防护。

## 14. 项目创新点

1. **Agent 与安全决策解耦**
   不依赖模型自我约束，策略位于工具副作用之前。

2. **任务授权与参数检测结合**
   不只判断“能否使用某工具”，还检查具体路径、命令、URL、收件人和内容。

3. **Allow/Ask/Deny 分级处置**
   在安全与可用性之间保留人工确认通道，明确恶意行为不可通过审批绕过。

4. **不可信上下文传播**
   将仓库内容、代码注释、日志、配置和工具输出视为潜在污染源。

5. **Agent 无关的 Trace 协议**
   内置 Agent 与 OpenCode 可共用策略、审计和可视化链路。

6. **可验证审计而非普通日志**
   使用 SQLite 和 SHA-256 前向哈希链，并提供隔离副本篡改实验。

7. **安全边界可动态扩展**
   用户可选择可信工作环境，同时保留敏感操作保护。

8. **安全控制与用户体验并重**
   连续对话、历史保留、折叠问答、上下文容量提醒和完整执行回放集成在同一界面。

## 15. 建议演示流程

建议控制在 5 至 7 分钟：

1. **正常任务**
   让 Agent 列出工作区并读取普通文件，展示 Allow 和工具结果。

2. **连续上下文**
   追问上一个结果，展示同一 Conversation 内保留历史和每轮折叠。

3. **人工审批**
   请求删除测试文件或向外部地址发送不含敏感信息的测试邮件，展示 Ask、暂停、批准或拒绝。

4. **提示注入攻击**
   运行 README 私钥读取场景，展示 Critical / Deny 和命中原因。

5. **OpenCode 接入**
   让 OpenCode 执行安全的 `read` 或 `bash` 操作，展示执行前授权和 Guard Trace。

6. **审计校验**
   打开审计详情，展示前序哈希、事件哈希和完整性状态。

7. **评测结果**
   展示 104 项单元测试、100 条基础策略用例、500 条 AgentToolBench、120 条红队集和六模式消融结果。

演示时不要使用真实邮箱、API Key、个人目录或生产数据。邮件演示优先使用本地 outbox 模式。

## 16. 申报摘要

CodeAgent Guard 是一套面向 AI 编程智能体的工具调用安全网关。项目在 Agent 与文件、Shell、网络、邮件等高风险工具之间建立独立安全边界，并通过 CT-TRM 对来源、实体、参数传播、任务能力和跨工具调用链进行确定性风险聚合。系统支持内置 Agent 和 OpenCode 执行前授权，提供可信工作环境、连续上下文、持久化人工审批、全链路 Trace、SQLite 审计及 SHA-256 防篡改校验。当前源码通过 104 项单元测试；100 条基础策略回归符合预期；500 条 AgentToolBench 中，完整模式准确率为 91.4%，holdout 为 92.0%，基础规则为 67.8%。120 条红队绕过集仍保留 18 条漏报和 4 条误报。结果仅代表当前自建评测集。

## 17. 三分钟答辩提纲

**第一部分：为什么做**

AI 编程智能体已经能操作真实系统，但仓库内容本身是不可信的。攻击者可以把恶意指令藏在 README、注释或日志中，诱导 Agent 读取私钥、执行远程脚本或外传密钥。模型拒绝不是强制安全边界。

**第二部分：怎么解决**

项目在 Agent 和工具之间加入 Tool Proxy。所有调用先经过 Policy Engine，对工具授权、路径、命令、URL、邮件内容和数据来源进行检查，输出 Allow、Ask 或 Deny。只有获准参数才能进入执行器，所有过程同步写入 Trace 和哈希审计链。

**第三部分：项目特点**

安全模块与 Agent 解耦。内置 Agent 可直接使用，OpenCode 通过执行前 Hook 接入；替换模型不会丢失策略、审计和可视化。系统还实现了可信工作环境、连续对话、上下文容量提醒和每轮执行回放。

**第四部分：验证结果**

当前实现通过 104 项单元测试；100 条基础策略回归用例全部符合预期；旧 50 条 CT-TRM 回归集保持原结果；新的 500 条主集和 120 条红队集如实保留误报与漏报；针对原有 5 类攻击场景仍全部阻断；审计副本被修改后能够检测并定位断链位置。

**第五部分：边界**

当前是安全原型而非生产沙箱。后续将重点完成 OpenCode 跨进程审批恢复、审批持久化、身份认证、容器隔离和外部审计锚定。

## 18. 当前边界与后续规划

当前边界：

- `run_command` 有策略与资源限制，但不是容器或虚拟机级隔离。
- 服务当前没有用户身份认证、权限分级和 TLS，默认应仅监听本机。
- 单机待审批请求和 CT-TRM 状态已持久化；多实例部署仍需要共享状态库和租约。
- OpenCode Ask 仅能在 Hook 进程保持运行且未超时时恢复原生工具调用。
- Agent 对话使用 JSON 文件保存，尚未迁移到统一数据库。
- Trace 默认最多保留 500 条，尚无归档、导出和多用户隔离。
- SHA-256 哈希链可检测普通事后篡改，但没有外部可信时间戳或签名锚定。
- MCP Server 不属于当前 Git 提交的正式能力，不能在本次材料中宣称已交付。

后续优先级：

1. OpenCode 审批票据与调用恢复协议。
2. 审批、会话和配置统一 SQLite 状态库。
3. API 身份认证、RBAC、CSRF 防护和 TLS。
4. 容器、非特权用户、只读挂载、seccomp 和出站网络白名单。
5. 策略配置文件、版本管理、热更新和回滚。
6. MCP 协议适配层。
7. 审计签名、外部锚定、归档导出和多租户隔离。
8. 引入第三方攻击集、模糊测试和跨平台性能测试。

## 19. 参赛提交检查清单

- [ ] 报名材料中的功能与 Git 提交 `79f0de1` 保持一致。
- [x] 更新 README 中过时的“30 项测试”、OpenCode 状态和旧 Build 编号。
- [ ] 不打包 `.env`、API Key、证书、个人邮箱或 SMTP 凭据。
- [ ] 不打包 `data/*.db`、`data/outbox/`、Agent 对话和真实工作区。
- [ ] 对演示截图中的邮箱、路径、Trace 参数和密钥进行脱敏。
- [ ] 使用全新测试数据录制演示视频。
- [ ] 在干净环境重新执行 `python -m unittest discover -s tests -v`。
- [ ] 重新运行 100 条策略评测和 5 类攻击用例。
- [ ] 说明测试集口径，不把自建测试结果表述为绝对安全保证。
- [ ] 演示 OpenCode 的 Ask 场景，展示 Dashboard 批准后原生工具继续执行，并说明进程退出/超时边界。
