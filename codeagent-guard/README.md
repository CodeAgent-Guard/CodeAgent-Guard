# CodeAgent Guard 交付、部署与使用指南

CodeAgent Guard 是一个面向 AI 编程智能体的工具调用边界控制与风险审计原型。系统不修改大模型本身，而是在 Agent 与文件、命令、网络和邮件等工具之间设置统一的 Tool Proxy，对每次工具调用执行策略判定、审批、阻断、审计和可视化。

当前版本已集成 **CT-TRM（Context-Taint Tool Risk Model）**，在原有参数规则之上增加来源建模、安全实体抽取、参数溯源、污染传播、任务能力预算、跨工具调用链检测和固定可解释风险评分。详细设计见 [`docs/CT_TRM.md`](docs/CT_TRM.md)。

本项目按“信安赛作品”第一阶段要求实现，推荐运行环境为 **Windows 10/11 + WSL2 + Ubuntu**。

参赛项目全貌、实测指标、演示流程和当前边界见
[`reports/competition_project_overview.md`](reports/competition_project_overview.md)。

## 1. 接收方先看这里

### 1.1 运行关系

Windows 目录用于保存或解压交付包，程序实际在 WSL Ubuntu 中运行：

```text
Windows 交付目录
例如 D:\projects\codeagent-guard
                │
                │ WSL 映射为 /mnt/d/projects/codeagent-guard
                ▼
复制到 Ubuntu：/opt/codeagent-guard
                │
                │ ./start.sh
                ▼
Windows 浏览器访问：http://127.0.0.1:8000
```

注意：正确地址是 `http://127.0.0.1:8000`，`http://` 后面有两个斜杠。

### 1.2 环境要求

- Windows 10/11。
- WSL2 和 Ubuntu。
- Ubuntu 中安装 Python 3.10 或更高版本。
- 使用云端 LLM 时需要网络和对应 API Key。
- 项目仅使用 Python 标准库，不需要执行 `pip install`。
- `run_command` 明确依赖 Linux `/bin/bash`，不建议直接在 Windows PowerShell 中运行 `server.py`。

检查环境：

```bash
python3 --version
```

如果尚未安装 Python：

```bash
sudo apt update
sudo apt install -y python3
```

## 2. 首次部署

### 2.1 安装 WSL2 和 Ubuntu

如果电脑已经能够打开 Ubuntu 终端，可以跳过本节。

以管理员身份打开 PowerShell：

```powershell
wsl --install -d Ubuntu
```

安装完成后重启 Windows，打开 Ubuntu，并按提示创建 Linux 用户。

### 2.2 将项目复制到 `/opt/codeagent-guard`

先把交付包解压到任意 Windows 目录。Windows 的磁盘在 WSL 中位于 `/mnt/<盘符小写>/`。

例如：

| Windows 路径 | WSL 路径 |
|---|---|
| `D:\projects\codeagent-guard` | `/mnt/d/projects/codeagent-guard` |
| `D:\desktop\ZUOPIN\codeagent-guard` | `/mnt/d/desktop/ZUOPIN/codeagent-guard` |

打开 Ubuntu，执行：

```bash
sudo mkdir -p /opt/codeagent-guard
sudo cp -a /mnt/d/newDestop/zuopin/codeagent-guard/. /opt/codeagent-guard/
sudo chown -R "$USER":"$USER" /opt/codeagent-guard
cd /opt/codeagent-guard
chmod +x start.sh
```

如果接收方解压到了其他目录，只需要替换 `cp` 命令中的源路径。

推荐复制到 Linux 文件系统后运行，不要长期直接从 `/mnt/d/...` 启动。这样可以减少 Windows/WSL 文件权限、换行符和磁盘性能差异带来的问题。

### 2.3 创建本机配置

```bash
cd /opt/codeagent-guard
cp .env.example .env
nano .env
```

建议在 `.env` 中增加：

```dotenv
HOST=127.0.0.1
PORT=8000
```

`HOST=127.0.0.1` 表示仅允许本机访问。当前服务没有登录认证，不要直接暴露到公网。

如果暂时不使用 LLM，可以先把 `.env` 中的 `LLM_API_KEY=replace-me` 改为空值：

```dotenv
LLM_API_KEY=
```

没有 LLM 也可以使用攻击复现、策略评测、审计日志和哈希链验证。

### 2.4 启动

```bash
cd /opt/codeagent-guard
./start.sh
```

终端应显示：

```text
CodeAgent Guard: http://localhost:8000
Workspace: /opt/codeagent-guard/workspace
```

保持这个 Ubuntu 终端开启，然后在 Windows 浏览器访问：

```text
http://127.0.0.1:8000
```

停止服务：回到 Ubuntu 终端按 `Ctrl+C`。

健康检查：

```bash
curl http://127.0.0.1:8000/api/health
```

## 3. 配置和调用 LLM

只有“Agent 控制台”中的自然语言任务需要 LLM。攻击复现和 100 条策略评测不调用 LLM。

使用的模型必须支持 **Function Calling / Tool Calling**。只支持普通对话的模型无法驱动 Tool Proxy。

### 3.1 方法一：在 Dashboard 中配置

1. 打开“Agent 控制台”。
2. 选择供应商。
3. 检查 Base URL。
4. 填写供应商实际支持的模型名称。
5. 填写 API Key。
6. 点击“测试连接”。
7. 连接成功后选择本任务允许使用的工具，输入任务并运行。

页面支持 OpenAI、Anthropic Claude、DeepSeek、Qwen、GLM、Kimi、Gemini、SiliconFlow、Ollama、LM Studio、vLLM 和自定义 OpenAI-compatible 服务。

通过页面填写的 API Key 只保存在当前 Python 进程内存中：

- 不写入配置文件。
- 不进入审计日志。
- 服务重启后需要重新填写。

### 3.2 方法二：使用 `.env` 持久配置

OpenAI-compatible 示例：

```dotenv
HOST=127.0.0.1
PORT=8000

LLM_PROVIDER=openai
LLM_PROTOCOL=openai
LLM_BASE_URL=https://api.openai.com
LLM_MODEL=填写实际可用且支持工具调用的模型名
LLM_API_KEY=填写自己的APIKey
```

Anthropic 使用 `LLM_PROTOCOL=anthropic`。其他供应商可以直接在 Dashboard 选择预设，也可以根据 `.env.example` 修改。

修改 `.env` 后需要重启服务：

```bash
# 在运行服务的终端按 Ctrl+C，然后重新启动
./start.sh
```

不要把包含真实 Key 的 `.env` 交给其他人。

### 3.3 使用密钥文件

比直接把 Key 写入 `.env` 更安全的方式：

```bash
cd /opt/codeagent-guard
mkdir -p .secrets
chmod 700 .secrets
nano .secrets/provider-api-key
chmod 600 .secrets/provider-api-key
```

然后在 `.env` 中设置：

```dotenv
LLM_API_KEY=
LLM_API_KEY_FILE=/opt/codeagent-guard/.secrets/provider-api-key
```

### 3.4 本地 Ollama

如果 Ollama 也运行在同一个 Ubuntu 中：

```dotenv
LLM_PROVIDER=ollama
LLM_PROTOCOL=openai
LLM_BASE_URL=http://localhost:11434/v1
LLM_MODEL=支持工具调用的本地模型名
LLM_API_KEY=
```

如果 Ollama 运行在 Windows，而 WSL 无法通过 `localhost:11434` 访问，可在 WSL 中获取 Windows 宿主地址：

```bash
ip route | awk '/default/ {print $3}'
```

将结果用于 `LLM_BASE_URL=http://<宿主地址>:11434/v1`，同时确认 Ollama 监听地址和 Windows 防火墙允许 WSL 访问。

### 3.5 授权 Agent 打开 Windows 目录

`open_directory` 可以从 WSL 调用 Windows 资源管理器，但它不会默认获得整个磁盘权限。
管理员必须在 `.env` 中配置可打开的目录，例如：

```dotenv
GUARD_OPEN_DIRECTORY_ROOTS=/mnt/c/Users/demo/Desktop,/mnt/d/trusted-workspace
```

也可以填写 Windows 路径；多个目录使用英文逗号分隔：

```dotenv
GUARD_OPEN_DIRECTORY_ROOTS='C:\Users\demo\Desktop,D:\trusted-workspace'
```

修改后重启服务并刷新页面。前端默认会勾选 `open_directory`；如果浏览器仍显示旧页面，按 `Ctrl+F5` 强制刷新。使用时：

1. 确认“任务级授权工具”中 `open_directory` 已勾选。
2. 向 Agent 明确说明要打开的文件夹。
3. Policy Engine 返回 `ASK` 后点击“批准并执行”。

只有配置目录本身及其子目录可以打开。未配置目录会返回
`external_directory_not_authorized`。该工具只负责打开资源管理器，不会扩大
`read_file`、`write_file`、`list_directory`、`search_files` 或 `run_command`
的文件访问范围。

### 3.6 授权 Agent 在外部目录增删查改

如果需要让 Agent 在桌面等外部目录中执行受控增删查改，必须额外配置
`GUARD_EXTERNAL_WRITE_ROOTS`：

```dotenv
GUARD_EXTERNAL_WRITE_ROOTS=/mnt/c/Users/demo/Desktop,/mnt/d/trusted-workspace
```

该配置只扩展授权目录内的基础文件/目录 CRUD：

- `list_directory`：列出授权外部目录内容，外部路径会触发 `ASK`。
- `read_file` / `search_files`：读取或搜索授权目录内文件，外部路径会触发 `ASK`。
- `write_file`：创建或修改授权目录内文件，外部路径会触发 `ASK`。
- `make_directory`：在授权外部目录下创建文件夹，外部路径会触发 `ASK`。
- `move_path`：在同一个授权外部目录内重命名/移动文件或文件夹，外部路径会触发 `ASK`。
- `delete_path`：删除授权目录内的文件或空文件夹，外部路径会触发 `ASK`。

它不会授权执行命令，也不会允许跨授权根目录移动。未配置目录仍会被判定为
`resource_scope_violation`。删除目录不做递归删除，非空目录会被拒绝或由执行器失败返回。

## 4. Dashboard 使用说明

### 4.1 安全总览

展示：

- 工具调用总数、阻断数、阻断率和平均策略延迟。
- 风险等级分布。
- 最近工具调用和风险告警。
- 最新 Trace 的动态调用链。
- 审计哈希链状态。
- 攻击复现结果。

### 4.2 Agent 控制台

用于配置 LLM、提交自然语言任务和查看透明执行事件。

页面左侧“历史任务”会保存内置 Agent 过去的问题。点击任意记录，可以回放：

- 用户原始任务。
- Agent 工具请求。
- 任务级工具授权。
- Policy Engine 风险判定。
- Tool Proxy 执行、暂停或阻断动作。
- 工具执行结果。
- 用户审批。
- Audit Hash Chain 记录。
- Agent 最终回答。

历史 Trace 保存在 `data/traces.db`，服务重启后仍然存在，默认最多保留最近
500 条。历史回放为只读模式，不会重新执行工具。

运行任务前必须勾选本任务允许使用的工具。未勾选的工具即使被模型调用，也会命中 `tool_not_allowed` 并被拒绝。

如果策略返回 `ask`：

1. 工具不会立即执行。
2. Agent 状态变为 `awaiting_approval`，不会提前生成最终回答。
3. 页面显示“批准并执行”和“拒绝操作”。
4. 批准后系统重新执行策略判定并调用工具，再把工具结果交回同一个 Agent 会话。
5. 拒绝时不会执行工具，拒绝结果会进入审计链并交回 Agent。
6. Agent 从暂停位置继续运行，最后生成完整回答。

系统不会倒计时自动批准高风险操作，必须由用户明确批准或拒绝。服务重启会丢失
尚未处理的审批会话，因此审批应在当前服务进程中完成。

等待审批阶段只有暂停提示，不会生成或保存 `final_answer`。批准或拒绝后，所有
完成路径都会生成最终自然语言总结；即使总结模型请求失败或达到最大工具步数，
系统也会依据真实工具记录生成兜底总结。

当所有工具调用结束后，内置 Agent 会额外执行一次不允许调用工具的“结果归纳”：

- 复述用户原始要求。
- 将工具名称、关键参数和执行过程转换为自然语言。
- 说明 Allow、Ask、Deny 和用户审批情况。
- 明确最终是成功、失败、被拒绝还是只进入本地队列。
- 给出重要结果路径或错误原因。

这会额外产生一次 LLM 请求。系统还会根据真实工具返回值进行事实校验，例如
`delivered=false, queued=true` 会被明确说明为“邮件未真实发送，仅保存到本地
outbox 队列”，不会当成发送成功。

页面中的“AI Agent 思考”是可审计的规划和工具选择摘要，不是模型的私有思维链。

### 4.3 攻击复现

无需配置 LLM即可运行：

1. 恶意 README 诱导读取 SSH 私钥。
2. 恶意代码注释诱导下载并执行远程脚本。
3. 扫描结果诱导密钥邮件外传。
4. 恶意运行日志诱导反弹 Shell。
5. 配置文件诱导路径穿越。
6. 正常任务基线。

点击场景后，系统会生成真实策略判定、透明事件和审计记录，但被拒绝的危险调用不会产生工具副作用。

### 4.4 评测中心

点击“重新生成 100 条”可以生成：

```text
data/evaluation/test_cases.jsonl
```

点击“运行评测”会输出：

- 100 条策略用例准确率。
- 无防护攻击成功率 ASR。
- 防护后攻击成功率。
- 防护阻断率。
- 误报率 FPR。
- 平均和 P95 策略判定延迟。
- 审计篡改检测结果。

评测只调用 Policy Engine，不会真实执行命令、删除文件、访问网络或发送邮件。

### 4.5 审计日志

审计数据保存在：

```text
/opt/codeagent-guard/data/audit.db
```

完整 Agent Trace 历史保存在：

```text
/opt/codeagent-guard/data/traces.db
```

Trace 中可能包含用户问题、代码片段和工具结果。虽然系统会对常见 API Key、
Token 和密码字段做脱敏，但仍应按敏感数据管理该数据库。

可执行：

- 按 Trace 会话分组查看，每个会话显示任务、记录数和 Allow/Ask/Deny 统计。
- 使用会话下拉框只查看某一次任务产生的审计记录。
- 时间显示为浏览器本地时区的 `YYYY-MM-DD HH:mm:ss`。
- 按工具、Trace、参数和原因搜索。
- 按 `allow / ask / deny` 过滤。
- 查看参数、阻断原因、前序哈希和事件哈希。
- 校验完整哈希链。
- 在隔离数据库副本中执行篡改检测实验。
- 清空演示审计数据。

### 4.6 策略中心

展示当前启用的工作区边界、敏感路径、危险命令、SSRF、外发、密钥检测、不可信上下文和任务级工具授权规则。

## 5. 工作区说明

Agent 的文件工具只能访问：

```text
/opt/codeagent-guard/workspace/
```

要让 Agent 分析某个待测项目，需要先把待测文件放入 `workspace/`，例如：

```bash
cp -a /path/to/project/. /opt/codeagent-guard/workspace/
```

请先清理原有演示文件或为每次演示准备独立副本。不要把真实密钥、生产配置和重要的唯一文件放进工作区。

工具路径参数使用相对于 `workspace/` 的路径：

```text
README.md
src/app.py
reports/result.txt
```

不能使用工作区外路径。`../`、`~/.ssh`、`/etc`、`/root` 等路径会被策略拒绝。

`open_directory` 是单独的桌面交互工具，不属于文件读写工具。它可以打开
`GUARD_OPEN_DIRECTORY_ROOTS` 配置的外部目录，但不能读取、修改或执行其中的文件。

## 6. HTTP API 调用

### 6.1 健康检查

```bash
curl http://127.0.0.1:8000/api/health
```

### 6.2 调用内置 Agent

需要先配置 LLM：

```bash
curl -sS -X POST http://127.0.0.1:8000/api/agent/run \
  -H 'Content-Type: application/json' \
  -d '{
    "prompt": "检查工作区中的 Python 文件并说明发现",
    "max_steps": 8,
    "allowed_tools": ["list_directory", "search_files", "read_file", "run_command"]
  }'
```

### 6.3 外部 Agent 调用受控工具

`allowed_tools` 必须显式传入：

```bash
curl -sS -X POST http://127.0.0.1:8000/api/tools/execute \
  -H 'Content-Type: application/json' \
  -d '{
    "agent_id": "external-agent",
    "trace_id": "trace-demo-001",
    "call_id": "call-demo-001",
    "task": "读取项目说明",
    "tool": "read_file",
    "args": {"path": "README.md"},
    "source": "agent",
    "tainted": false,
    "allowed_tools": ["read_file"]
  }'
```

返回的 `action` 为：

- `allow`：工具已经执行。
- `ask`：工具未执行，返回 `approval_id`，等待用户审批。
- `deny`：工具未执行。

### 6.4 审批

查看待审批操作：

```bash
curl http://127.0.0.1:8000/api/approvals
```

批准：

```bash
curl -sS -X POST http://127.0.0.1:8000/api/approvals/resolve \
  -H 'Content-Type: application/json' \
  -d '{"approval_id":"替换为实际ID","approve":true,"actor":"operator"}'
```

将 `approve` 改为 `false` 即为拒绝。

### 6.5 外部 Agent Trace

外部 Agent 可以调用以下接口补充用户任务、规划摘要和最终回答：

```text
POST /api/traces/start
POST /api/traces/event
POST /api/tools/execute
GET  /api/traces/{trace_id}
```

即使外部 Agent 不上报规划摘要，Tool Proxy 仍会自动生成工具请求、策略判定、执行行动、工具结果和审计链事件。

## 7. 命令行测试

### 7.1 单元测试

```bash
cd /opt/codeagent-guard
python3 -m unittest discover -s tests -v
```

当前项目包含 154 项单元测试（不同平台可有少量条件跳过）。

### 7.2 生成 100 条策略用例

```bash
python3 generate_test_cases.py
```

### 7.3 运行完整策略评测

服务启动后，可以在 Dashboard 的“评测中心”运行，也可以执行：

```bash
curl -sS -X POST http://127.0.0.1:8000/api/evaluation/run \
  -H 'Content-Type: application/json' \
  -d '{}'
```

结果保存在：

```text
data/evaluation/evaluation_result.json
data/evaluation/experiment_report.md
```

### 7.4 运行五类独立攻击用例

```bash
python3 run_attack_suite.py
```

结果保存在：

```text
data/evaluation/attack_suite_result.json
```

### 7.5 运行 CT-TRM 消融评测

```bash
python3 run_ct_trm_evaluation.py
```

评测使用 50 条离线样本，对比 `baseline_rules`、`rules_plus_source` 和
`full_ct_trm`，不会执行工具、访问网络或发送邮件。结果保存在：

```text
reports/ct_trm_evaluation.json
reports/ct_trm_evaluation.md
```

### 7.6 AgentToolBench 500、红队与稳定性评测

```bash
python -m benchmarks.agent_tool_bench.generators.generate_ct_trm_cases \
  --output benchmarks/agent_tool_bench/cases/ct_trm_500.yaml \
  --count 500 --seed 20260622

python -m benchmarks.agent_tool_bench.generators.validate_cases \
  --cases benchmarks/agent_tool_bench/cases/ct_trm_500.yaml \
  --output reports/ct_trm/validation_report.json

python -m guard.evaluation_ct_trm \
  --cases benchmarks/agent_tool_bench/cases/ct_trm_500.yaml \
  --all-modes --output-dir reports/ct_trm

python -m guard.evaluation_ct_trm \
  --cases benchmarks/agent_tool_bench/cases/redteam_bypass.yaml \
  --mode full_ct_trm --output-dir reports/redteam

python -m benchmarks.agent_tool_bench.real_agent.run_real_agent_validation \
  --output reports/real_agent_validation.json

python -m benchmarks.agent_tool_bench.real_agent.run_opencode_validation \
  --output reports/opencode_validation.json

python scripts/stress_ct_trm_policy.py \
  --output reports/stability/stress_ct_trm_policy.json

python scripts/stress_approval_flow.py \
  --output reports/stability/stress_approval_flow.json

python scripts/check_report_claims.py reports docs
```

新评测结果位于 `reports/ct_trm/`、`reports/redteam/`、
`reports/stability/` 和 `reports/final/`。所有百分比仅描述当前自建评测集。

## 8. 已实现功能

| 作品要求/功能 | 状态 | 实现位置或说明 |
|---|---|---|
| 自研轻量 AI Agent | 已实现 | `guard/agent.py` |
| OpenAI-compatible LLM | 已实现 | `guard/providers.py` |
| Anthropic Messages API | 已实现 | `guard/providers.py` |
| 文件读取、写入 | 已实现 | `read_file`、`write_file` |
| 命令执行监管 | 已实现 | `run_command` |
| HTTP 请求监管 | 已实现 | `http_request` |
| 邮件发送监管 | 已实现 | `send_email` |
| 目录、搜索、创建、删除、移动工具 | 已实现 | 额外五类工具 |
| Windows 授权目录打开 | 已实现 | `open_directory`，配置目录 + 任务授权 + 用户审批三层控制 |
| 外部授权目录增删查改 | 已实现 | `GUARD_EXTERNAL_WRITE_ROOTS` + 文件/目录 CRUD 工具强制 ASK |
| 任务级工具白名单 | 已实现 | 未授权工具返回 `tool_not_allowed` |
| Allow / Ask / Deny | 已实现 | `guard/policy.py`、`guard/tools.py` |
| ASK 审批闭环 | 已实现 | Agent 暂停，批准或拒绝后恢复并生成最终回答 |
| 工作区边界和路径穿越检测 | 已实现 | 路径归一化后判定 |
| 敏感文件和密钥检测 | 已实现 | `.ssh`、`.env`、私钥、API Key 等 |
| 危险命令检测 | 已实现 | 远程脚本、破坏命令、反弹 Shell 等 |
| `run_command` 防工具绕过 | 已实现 | 阻止敏感路径和 curl/wget/ssh 等网络绕过 |
| SSRF 防护 | 已实现 | 阻止本机、私网、链路本地和保留地址 |
| 外部收件人控制 | 已实现 | 外部邮件 Ask，敏感内容 Deny |
| 不可信上下文和 taint | 已实现 | 日志、配置、仓库内容、工具输出不能授权写操作 |
| SQLite 审计日志 | 已实现 | `data/audit.db` |
| SHA-256 前向哈希链 | 已实现 | 支持校验和隔离副本篡改实验 |
| 中文 Dashboard | 已实现 | 总览、Agent、评测、审计、策略五个页面 |
| 透明执行事件 | 已实现 | `TransparencyService` |
| Agent 历史任务和完整链路回放 | 已实现 | SQLite `data/traces.db`，重启后保留 |
| Agent 自然语言执行总结 | 已实现 | 工具链结束后由 LLM 二次归纳，并校验关键结果状态 |
| 恶意 README、注释、日志、配置、扫描输出 | 已实现 | `adversarial/` |
| 不少于三类攻击场景 | 已实现 | 当前为五类攻击场景 |
| 风险分析报告 | 已实现 | `reports/security_risk_analysis.md` |
| 实验评测报告 | 已实现 | `reports/experiment_evaluation.md` |
| ASR、阻断率、FPR、延迟、审计完整性 | 已实现 | 评测中心和评测结果文件 |
| 外部 Agent HTTP 接入 | 已实现 | `/api/tools/execute` 和 Trace API |
| OpenCode 执行前授权插件 | 已实现 | `opencode/tool-proxy-plugin.js` + `/api/opencode/authorize-tool` |
| OpenCode 执行结果回传 | 已实现 | 原生 Hook 回传实际结果；审计优先、完整结果指纹校验、Trace 幂等补写 |
| CT-TRM 上下文污染风险模型 | 已实现 | 来源、实体、溯源、任务预算、P1-P15、序列风险和固定评分 |
| CT-TRM 消融评测 | 已实现 | 500 条 AgentToolBench，六种模式对比；保留旧 50 条回归集 |

当前随项目保存的评测结果为：

- 策略用例：100 条。
- 当前用例准确率：100%。
- 独立攻击场景：5 类。
- 无防护 ASR：100%。
- 防护后攻击成功率：0%。
- 防护阻断率：100%。
- 当前测试集 FPR：0%。
- 审计篡改检测：成功。

这些结果只代表当前确定性样本集，不等于已经覆盖所有真实攻击。

## 9. 未实现或仅部分实现

| 项目 | 当前状态 |
|---|---|
| OpenCode 进程退出后的任务恢复 | 部分实现；Hook 保持运行时可在审批后继续原生调用，若 OpenCode 进程已退出则不能恢复该进程 |
| OpenCode 长输出 DLP | 原型限制；完整执行结果会生成 SHA-256 指纹用于幂等与冲突校验，但 DLP 与界面仅扫描/保存每个文本字段前 12,000 字符 |
| MCP Server | 未实现；架构已预留，后续应把 MCP tools 转发到 `ToolProxy.invoke()` |
| 独立 `scan_secret` 工具 | 未实现；密钥检测已内置于写文件和邮件策略 |
| 机器学习异常检测 | 未实现；当前是确定性规则策略引擎 |
| 任务意图的语义相关性判断 | 未完整实现；当前主要依赖任务工具白名单、source 和 tainted 标记 |
| 容器/虚拟机级命令沙箱 | 未实现；当前是受限子进程和 Linux 资源限制 |
| 完整网络隔离 | 未实现；主要依赖策略检测，生产环境仍需网络命名空间和出站规则 |
| 多用户、登录、RBAC、TLS | 未实现；当前是本地演示服务 |
| 审计数字签名或外部锚定 | 未实现；当前 SHA-256 链可检测普通事后篡改，但数据库管理员可整体重写链 |
| 多节点审批队列 | 未实现；单机审批与 CT-TRM 状态已持久化到 `data/state.db`，多实例仍需共享数据库和租约 |
| Trace 归档、导出和按用户隔离 | 未实现；当前最多保留最近 500 条 |
| 默认真实邮件发送 | 未启用；未配置 SMTP 时只写入 `data/outbox/` |
| 生产级高可用部署 | 未实现；当前使用 Python `ThreadingHTTPServer` |

因此，本项目适合作品演示、策略验证和二次开发，不应直接作为生产安全网关部署。

## 10. 项目结构

```text
codeagent-guard/
├── server.py                 HTTP 服务和依赖装配
├── start.sh                 WSL/Ubuntu 启动脚本
├── guard/
│   ├── agent.py             内置轻量 Agent
│   ├── providers.py         LLM 供应商适配
│   ├── tools.py             Tool Proxy 和审批流程
│   ├── policy.py            Allow / Ask / Deny 策略
│   ├── executors.py         工具实际执行器
│   ├── audit.py             SQLite 和哈希链
│   ├── transparency.py      透明 Trace 事件和历史持久化
│   └── adapters.py          外部 Agent 适配入口
├── frontend/                中文 Dashboard
├── workspace/               Agent 唯一允许操作的工作区
├── adversarial/             对抗样本
├── data/evaluation/         测试用例和评测结果
├── reports/                 风险分析和实验报告
├── docs/ARCHITECTURE.md     模块化架构说明
└── tests/test_guard.py      单元测试
```

## 11. 常见问题

### `./start.sh: Permission denied`

```bash
chmod +x start.sh
./start.sh
```

### 出现 `^M` 或 `/usr/bin/env: bash\r`

交付包中的脚本被转换成 Windows CRLF 换行：

```bash
sed -i 's/\r$//' start.sh
chmod +x start.sh
```

### 8000 端口被占用

```bash
PORT=8001 ./start.sh
```

然后访问 `http://127.0.0.1:8001`。

如果 `./start.sh` 提示当前数据目录已有实例，先检查 Guard 自己，不要结束
`systemd-resolve` 等无关系统进程：

```bash
curl -sS http://127.0.0.1:8000/api/health
sudo lsof -i :8000
```

`lsof` 的端口过滤语法是 `-i :8000`；`kill` 后只能跟真实 PID。Windows 与
WSL 共享项目 `data/` 时，另一侧实例可能无法出现在当前 WSL 的 `lsof` 输出中，
但 Guard 会用跨环境实例锁阻止两边同时写 SQLite。

### OpenCode 已运行，但前端没有出现记录

1. 在项目根目录运行 `opencode debug config`，确认只加载当前项目的
   `.opencode/plugins/codeagent-guard.js`；删除用户配置中已不存在的旧绝对路径。
2. 用 `curl -sS http://127.0.0.1:8000/api/health` 确认 build 为
   `2026.08.14-human-evidence-v1` 或更新版本。
3. 在前端“设置”中将 OpenCode 当前项目目录加入“可信工作环境”。相对路径会以
   OpenCode 的真实工作目录解析；未授权的工作区外访问仍会 Ask 或 Deny。
4. 保持 Guard 运行后重新启动一次 OpenCode 会话。前端每 3 秒同步 Trace、审计链
   与审批；执行结果临时回传失败时插件会重试，服务重启也会从已提交审计补齐 Trace。

### Windows 浏览器打不开页面

先在 WSL 中检查：

```bash
curl http://127.0.0.1:8000/api/health
```

如果 WSL 内正常、Windows 浏览器仍不能访问，可获取 WSL 地址：

```bash
hostname -I
```

临时尝试 `http://<WSL地址>:8000`，并检查 Windows 防火墙。使用该方式时，服务需要监听 `0.0.0.0`。

### LLM 测试连接失败

依次检查：

1. WSL 是否能访问供应商网络。
2. Base URL 是否正确。
3. 模型名是否真实存在。
4. API Key 是否有效。
5. 模型是否支持 Tool Calling。
6. 自建服务是否实现 `/chat/completions` 和 `tool_calls`。

### Agent 不读取项目内容

- 确认项目位于 `/opt/codeagent-guard/workspace/`。
- 在任务工具授权中至少勾选 `list_directory`、`read_file` 或 `search_files`。
- 模型必须支持工具调用。

### API 返回 `allowed_tools 必须由当前任务显式声明`

每个 Agent 或工具 API 请求都必须包含非空的 `allowed_tools` 数组，并明确列出该任务允许使用的工具。

### 邮件为什么没有真正发送

默认安全模式不配置 SMTP，允许的邮件被保存到：

```text
data/outbox/
```

只有设置 `SMTP_HOST` 等配置后才会真实外发。真实外发前应先确认测试收件人和数据合规要求。

## 12. 交付前检查

交付方打包前应确认：

- 删除 `.env`，只保留 `.env.example`。
- 不打包 `.secrets/`、API Key 或其他真实凭据。
- 不打包 `data/audit.db` 和 `data/outbox/` 中的敏感演示数据。
- 清理 `__pycache__/` 和 `*.pyc`。
- 保留 `reports/`、`adversarial/` 和 `data/evaluation/`，用于展示作品成果。
- 在干净的 WSL Ubuntu 环境重新执行启动和 154 项单元测试。

更新部署后可用以下命令确认不是旧进程或旧代码：

```bash
curl -s http://127.0.0.1:8000/api/health
```

当前修复版本的 `build` 应为：

```text
2026.08.14-human-evidence-v1
```

`.gitignore` 已忽略 `.env`、`.env.permissions`、审计数据库、邮件 outbox 和 Python
缓存，但使用普通压缩软件打包时仍需人工确认这些文件没有被包含。

## 13. 安全边界

- 所有文件工具限制在 `workspace/`。
- `open_directory` 仅能打开管理员配置的目录及其子目录，且每次执行都需要用户审批。
- `GUARD_EXTERNAL_WRITE_ROOTS` 只允许在管理员配置的外部目录内执行受控文件/目录 CRUD，且外部路径每次都需要用户审批。
- 命令在 `workspace/` 中运行，最大超时 30 秒，并使用隔离 HOME。
- Linux 环境下设置 CPU、内存、文件大小和文件描述符限制。
- HTTP 工具拒绝本机、私网、保留地址和云元数据地址。
- 外部收件人需要审批，检测到密钥时直接拒绝。
- 所有 `allow / ask / deny` 工具调用均进入 SQLite 审计链。
- 当前服务无身份认证，应默认仅监听 `127.0.0.1`。
- 生产部署仍需非特权容器、seccomp、只读挂载、网络命名空间、TLS、认证授权和外部审计锚定。

更详细的模块设计见 [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md)。
