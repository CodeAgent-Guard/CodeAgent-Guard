from __future__ import annotations

import re
import uuid
from dataclasses import asdict, dataclass, field
from enum import Enum


class SideEffectLevel(str, Enum):
    READ_ONLY = "read_only"
    WORKSPACE_WRITE = "workspace_write"
    COMMAND_EXECUTION = "command_execution"
    NETWORK_ACCESS = "network_access"
    EXTERNAL_COMMUNICATION = "external_communication"
    DESTRUCTIVE = "destructive"


SIDE_EFFECT_ORDER = {
    SideEffectLevel.READ_ONLY: 0,
    SideEffectLevel.WORKSPACE_WRITE: 1,
    SideEffectLevel.COMMAND_EXECUTION: 2,
    SideEffectLevel.NETWORK_ACCESS: 3,
    SideEffectLevel.EXTERNAL_COMMUNICATION: 4,
    SideEffectLevel.DESTRUCTIVE: 5,
}


TOOL_SIDE_EFFECT = {
    "read_file": SideEffectLevel.READ_ONLY,
    "list_directory": SideEffectLevel.READ_ONLY,
    "search_files": SideEffectLevel.READ_ONLY,
    "open_directory": SideEffectLevel.READ_ONLY,
    "write_file": SideEffectLevel.WORKSPACE_WRITE,
    "make_directory": SideEffectLevel.WORKSPACE_WRITE,
    "run_command": SideEffectLevel.COMMAND_EXECUTION,
    "http_request": SideEffectLevel.NETWORK_ACCESS,
    "send_email": SideEffectLevel.EXTERNAL_COMMUNICATION,
    "delete_path": SideEffectLevel.DESTRUCTIVE,
    "move_path": SideEffectLevel.DESTRUCTIVE,
}


@dataclass
class TaskCapabilityBudget:
    task_id: str
    user_task: str
    max_side_effect: SideEffectLevel
    likely_tools: set[str] = field(default_factory=set)
    unlikely_tools: set[str] = field(default_factory=set)
    allowed_path_hints: list[str] = field(default_factory=list)
    allowed_command_hints: list[str] = field(default_factory=list)
    denied_tool_hints: set[str] = field(default_factory=set)
    confidence: float = 0.5
    reasons: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        value = asdict(self)
        value["user_task"] = _redact_task(self.user_task)
        value["max_side_effect"] = self.max_side_effect.value
        value["likely_tools"] = sorted(self.likely_tools)
        value["unlikely_tools"] = sorted(self.unlikely_tools)
        value["denied_tool_hints"] = sorted(self.denied_tool_hints)
        return value


READ_TOOLS = {"read_file", "list_directory", "search_files"}
MUTATING_TOOLS = {
    "write_file", "make_directory", "run_command", "http_request",
    "send_email", "delete_path", "move_path",
}


def infer_task_budget(user_task: str) -> TaskCapabilityBudget:
    task = str(user_task or "").strip()
    lowered = task.lower()
    task_id = f"task-{uuid.uuid5(uuid.NAMESPACE_URL, task).hex[:12]}"

    if _contains(lowered, (
        "删除", "清理", "移除文件", "移动", "重命名",
        "delete", "remove file", "cleanup", "move ", "rename",
    )):
        likely = {"delete_path", "move_path", "list_directory", "read_file"}
        return TaskCapabilityBudget(
            task_id, task, SideEffectLevel.DESTRUCTIVE,
            likely_tools=likely,
            unlikely_tools={"send_email", "http_request"},
            confidence=0.9,
            reasons=["task_requests_destructive_file_operation"],
        )

    if (
        "内部" in lowered
        and _contains(
            lowered,
            ("通知", "报告", "周报", "任务更新", "错误报告"),
        )
    ):
        return TaskCapabilityBudget(
            task_id,
            task,
            SideEffectLevel.EXTERNAL_COMMUNICATION,
            likely_tools={"send_email", "read_file"},
            unlikely_tools={"delete_path", "move_path"},
            confidence=0.9,
            reasons=["task_requests_internal_communication"],
        )

    if re.search(
        r"(?i)\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,63}\b",
        task,
    ) or _contains(lowered, (
        "发送邮件", "发邮件", "通知", "发送报告", "发送", "发给",
        "send email", "email ", " email", "notify", "mail ",
    )):
        return TaskCapabilityBudget(
            task_id, task, SideEffectLevel.EXTERNAL_COMMUNICATION,
            likely_tools={"send_email", "read_file"},
            unlikely_tools={"delete_path", "move_path"},
            confidence=0.95,
            reasons=["task_requests_external_communication"],
        )

    if _contains(lowered, (
        "http", "请求接口", "访问网址", "下载", "fetch", "download",
        "request api", "web",
    )):
        return TaskCapabilityBudget(
            task_id, task, SideEffectLevel.NETWORK_ACCESS,
            likely_tools={"http_request", "read_file", "write_file"},
            unlikely_tools={"send_email", "delete_path", "move_path"},
            confidence=0.85,
            reasons=["task_requests_network_access"],
        )

    if _contains(lowered, (
        "安装依赖", "npm install", "pnpm install", "yarn install",
        "pip install", "apt install", "install dependencies",
    )):
        return TaskCapabilityBudget(
            task_id, task, SideEffectLevel.COMMAND_EXECUTION,
            likely_tools={"run_command", "read_file", "list_directory"},
            unlikely_tools={"send_email", "delete_path", "move_path"},
            allowed_command_hints=[
                "npm install", "pnpm install", "yarn install", "pip install",
            ],
            confidence=0.95,
            reasons=["task_requests_dependency_installation"],
        )

    if _contains(lowered, (
        "运行测试", "执行测试", "pytest", "npm test", "make test",
        "修复失败", "run tests", "test failure", "build",
        "unit test", "unit tests", "go test",
    )) or re.search(
        r"\b(?:run|execute)\b.{0,40}\b(?:package\s+)?tests?\b",
        lowered,
    ):
        likely = {"read_file", "search_files", "run_command", "write_file"}
        return TaskCapabilityBudget(
            task_id, task, SideEffectLevel.COMMAND_EXECUTION,
            likely_tools=likely,
            unlikely_tools={"send_email", "delete_path", "move_path"},
            allowed_command_hints=[
                "pytest", "python -m pytest", "npm test", "make test",
                "python -m unittest", "go test",
            ],
            confidence=0.95,
            reasons=["task_requests_test_or_build_execution"],
        )

    if _contains(lowered, (
        "命令", "版本", "语法检查", "目录列表", "目录结构", "列出当前目录",
        "简单文件查找", "git 状态", "git 日志", "行数统计",
        "环境变量", "查看进程", "网络连接", "ssh agent",
        "打开的文件", "挂载点", "shell", "command", "version",
        "syntax check", "git status", "git log", "line count",
        "environment variable", "process list", "network connection",
    )):
        return TaskCapabilityBudget(
            task_id,
            task,
            SideEffectLevel.COMMAND_EXECUTION,
            likely_tools={
                "run_command",
                "read_file",
                "list_directory",
                "search_files",
            },
            unlikely_tools={"send_email", "delete_path", "move_path"},
            allowed_command_hints=[
                "pytest",
                "python -m pytest",
                "npm test",
                "make test",
                "go test",
            ],
            confidence=0.85,
            reasons=["task_requests_command_inspection"],
        )

    if _contains(lowered, (
        "修复", "修改", "实现", "创建文件", "写入", "更新代码",
        "fix", "edit", "implement", "create file", "write", "update code",
    )):
        return TaskCapabilityBudget(
            task_id, task, SideEffectLevel.WORKSPACE_WRITE,
            likely_tools={
                "read_file", "search_files", "list_directory",
                "write_file", "make_directory",
            },
            unlikely_tools={"send_email", "delete_path", "http_request"},
            confidence=0.85,
            reasons=["task_requests_workspace_modification"],
        )

    if _contains(lowered, (
        "总结", "解释", "查看", "读取", "查找", "搜索", "todo",
        "review", "summarize", "explain", "inspect", "find", "search",
        "readme", "代码审查",
    )):
        return TaskCapabilityBudget(
            task_id, task, SideEffectLevel.READ_ONLY,
            likely_tools=set(READ_TOOLS),
            unlikely_tools=set(MUTATING_TOOLS),
            denied_tool_hints=set(),
            confidence=0.9,
            reasons=["task_is_read_only"],
        )

    command_hint = bool(re.search(r"(?i)\b(?:bash|shell|command|命令)\b", task))
    return TaskCapabilityBudget(
        task_id,
        task,
        (
            SideEffectLevel.COMMAND_EXECUTION
            if command_hint else SideEffectLevel.WORKSPACE_WRITE
        ),
        likely_tools=(
            {"run_command", "read_file"}
            if command_hint
            else {"read_file", "list_directory", "search_files", "write_file"}
        ),
        unlikely_tools={"send_email", "delete_path", "move_path"},
        confidence=0.4,
        reasons=["task_intent_uncertain"],
    )


def tool_alignment(
    budget: TaskCapabilityBudget,
    tool_name: str,
    args: dict,
) -> tuple[int, str]:
    if tool_name in budget.likely_tools:
        if _explicit_argument_match(budget, tool_name, args):
            return -25, "explicitly_requested_low_risk_capability"
        return -15, "tool_directly_related_to_task"
    if tool_name in budget.unlikely_tools:
        requested = TOOL_SIDE_EFFECT.get(tool_name, SideEffectLevel.DESTRUCTIVE)
        if (
            SIDE_EFFECT_ORDER[requested]
            > SIDE_EFFECT_ORDER[budget.max_side_effect]
        ):
            return 20, "task_tool_misalignment"
        return 0, "tool_not_expected_for_task"
    return -5, "tool_weakly_related_to_task"


def _explicit_argument_match(
    budget: TaskCapabilityBudget,
    tool_name: str,
    args: dict,
) -> bool:
    if tool_name == "run_command":
        command = str(args.get("cmd") or args.get("command") or "").lower()
        return any(hint in command for hint in budget.allowed_command_hints)
    return budget.confidence >= 0.9


def _contains(text: str, values: tuple[str, ...]) -> bool:
    return any(value in text for value in values)


def _redact_task(task: str) -> str:
    value = str(task)
    value = re.sub(r"\bsk-[A-Za-z0-9_-]{8,}\b", "sk-[REDACTED]", value)
    value = re.sub(
        r"(?i)((?:api[_-]?key|token|password|secret)\s*[:=]\s*)\S+",
        r"\1[REDACTED]",
        value,
    )
    return value[:1000]
