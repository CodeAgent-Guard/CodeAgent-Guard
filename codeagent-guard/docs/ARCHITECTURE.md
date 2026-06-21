# CodeAgent Guard 模块化架构

## 三个可替换模块块

当前代码按以下三块组织，并由 `server.py` 作为组合根创建实例和注入依赖：

```text
┌─────────────────────────┐
│ 1. Agent / Adapter      │
│ agent.py                │
│ adapters.py             │
│ providers.py            │
└────────────┬────────────┘
             │ ToolCall / Tool Gateway
             ▼
┌─────────────────────────┐
│ 2. Security Boundary    │
│ tools.py (Tool Proxy)   │
│ policy.py               │
│ executors.py            │
│ catalog.py              │
└────────────┬────────────┘
             │ AuditPort / Trace events
             ▼
┌─────────────────────────┐
│ 3. Audit & Trace        │
│ audit.py                │
│ transparency.py         │
│ audit.db / traces.db    │
└─────────────────────────┘
```

替换关系：

- 将自研 Agent 换成 OpenCode：保留第二、三块，通过 HTTP、MCP 或
  `ExternalAgentAdapter` 把 OpenCode 工具调用转换为 `ToolCall`。
- 重写 Tool Proxy 或 Policy Engine：实现 `ToolGatewayPort` 或
  `PolicyPort`，在 `server.py` 更换注入实例。
- 重写审计：实现 `AuditPort.append()`，在 `server.py` 更换审计实例。
- 前端依赖稳定的 Trace Event JSON 协议，不依赖具体 Agent 模型实现。

当前模块化已经支持上述替换，但并非完全插件化：

- 内置 `BuiltinAgentAdapter` 的类型标注仍直接使用 `ToolProxy`，属于源码级依赖；
  外部 Agent 路径已经使用 `ToolGatewayPort`。
- 内置攻击演示会通过 Tool Proxy 查询审计链校验结果，这是演示功能的直接依赖。
- 模块实例仍由 `server.py` 写死创建，尚无动态插件发现或配置化工厂。
- 前端依赖现有事件字段；如果重写 Trace 服务，需要保持事件协议兼容。

因此当前状态可定义为“职责分离、依赖可注入、支持替换”，但还不是“任意模块
无需改组合代码即可热插拔”。

## 目标架构

```text
用户
  ↓
Agent Adapter
  ├── BuiltinAgentAdapter
  ├── ExternalAgentAdapter
  └── 后续 OpenCode / MCP Adapter
  ↓
Tool Proxy（统一安全边界）
  ├── 生成 Agent 工具请求事件
  ├── 调用 Policy Engine
  ├── 调度 Tool Executor
  ├── 写入 Audit Hash Chain
  └── 生成透明执行事件
  ↓
Policy Engine
  ├── 工具授权
  ├── 路径边界
  ├── 命令风险
  ├── SSRF
  ├── 敏感信息
  └── Allow / Ask / Deny
  ↓
Tool Executor Registry
  ├── read_file
  ├── write_file
  ├── run_command
  ├── http_request
  ├── send_email
  └── 其他扩展工具
  ↓
Audit & Dashboard
  ├── SQLite 调用日志
  ├── SHA-256 哈希链
  ├── TransparencyService
  └── Dashboard 时间线
```

## 模块边界

| 模块 | 文件 | 职责 |
|---|---|---|
| 数据协议 | `guard/contracts.py` | `ToolCall` 与各模块 Port |
| 自研 Agent | `guard/agent.py` | LLM 循环，不实现安全策略或工具 |
| 外部 Agent 适配 | `guard/adapters.py` | OpenCode/MCP 等外部 Agent 的统一入口 |
| Tool Proxy | `guard/tools.py` | 唯一工具安全网关与流程编排 |
| Tool Executor | `guard/executors.py` | 工具的实际副作用实现 |
| Policy Engine | `guard/policy.py` | 参数级安全判定 |
| Audit | `guard/audit.py` | 防篡改调用审计 |
| 透明事件 | `guard/transparency.py` | 与 Agent 无关的执行链路事件 |
| 组合根 | `server.py` | 创建实例并注入依赖 |

完整 Trace 历史保存在 `data/traces.db`，包括用户任务、Agent 工具请求、策略判定、
Tool Proxy 行动、工具结果、审批、审计事件和最终回答。前端历史列表通过
`GET /api/traces` 查询，点击后通过 `GET /api/traces/{trace_id}` 回放。

## ASK 暂停与恢复

内置 Agent 遇到 `ask` 时不会把“等待审批”当成普通工具结果继续生成最终回答：

```text
Agent Tool Call
    ↓
Policy Engine: ASK
    ↓
Tool Proxy 保存待审批调用并写入 ASK 审计事件
    ↓
AgentSession 暂停（awaiting_approval）
    ↓
用户批准 / 拒绝
    ↓
批准：重新判定并执行工具
拒绝：不执行工具并记录 user_rejected
    ↓
审批结果作为 tool result 回到原 AgentSession
    ↓
Agent 恢复并生成最终回答
```

`Audit & Hash Chain` 在审批前记录 ASK 是正常行为，它证明工具调用曾被暂停，
不代表工具已经执行。批准或拒绝后还会产生新的审批和审计事件。

当前暂停会话和 Tool Proxy 待审批调用保存在进程内存中，不会自动批准，也不会
在服务重启后恢复。

等待审批响应不包含最终回答，Trace 中也不会产生 `final_answer`。审批后所有
退出路径统一经过最终化流程；模型总结失败、返回空内容或达到最大工具步数时，
控制器使用真实执行摘要生成兜底自然语言，保证链路以 `final_answer` 收口。

## 最终执行总结

当内置 Agent 不再请求工具时，控制器不会直接采用模型的简短草稿，而是执行一次
禁用 Tool Calling 的结果归纳请求：

```text
全部工具结果
  + Policy 决策
  + 用户审批
  + Audit 状态
  + 用户原始任务
          ↓
Agent Synthesis（tools=false）
          ↓
自然语言执行总结
          ↓
关键状态事实校验
          ↓
Final Answer
```

总结要求覆盖用户目标、实际操作、工具和关键参数、安全判定、审批情况及最终结果。
关键副作用状态以执行器返回值为准。例如邮件返回 `delivered=false` 且
`queued=true` 时，系统会确保最终回答说明邮件只进入本地 outbox，而非真实发送。

该归纳只适用于内置 Agent。OpenCode 等外部 Agent 可以读取完整 Trace 后自行总结，
或通过 Trace API 上报自己的最终回答。

## 替换 OpenCode 时不会丢失的事件

以下事件由 Tool Proxy 自动生成，与 Agent 实现无关：

1. `AI Agent 工具请求`
2. `Policy Engine`
3. `Tool Proxy 行动`
4. `工具执行结果`
5. `Audit & Hash Chain`

OpenCode 只需通过 HTTP、后续 MCP Server 或 `ExternalAgentAdapter` 调用
Tool Proxy。用户任务、规划摘要和最终回答可以通过 Trace API 补充：

```text
POST /api/traces/start
POST /api/traces/event
POST /api/tools/execute
GET  /api/traces/{trace_id}
```

即使 OpenCode 不主动上报规划摘要，安全边界的五类事件仍然完整存在。

## 扩展原则

- 替换 Agent：新增 Adapter，不修改 Tool Proxy 和 Policy Engine。
- 新增工具：在 `catalog.py` 声明 schema，在 `executors.py` 注册执行器，在
  `policy.py` 增加对应判定函数。
- 替换策略：实现 `PolicyPort.evaluate()` 后在 `server.py` 注入。
- 替换审计：实现 `AuditPort.append()` 后在 `server.py` 注入。
- 接入 MCP：MCP Server 只负责协议转换，最终必须调用 `ToolProxy.invoke()`。
