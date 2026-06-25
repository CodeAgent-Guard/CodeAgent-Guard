from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from typing import Any, Protocol


@dataclass
class ToolCall:
    tool: str
    args: dict[str, Any]
    trace_id: str
    task: str = "工具调用"
    source: str = "agent"
    tainted: bool = False
    approved: bool = False
    agent_id: str = "external-agent"
    allowed_tools: tuple[str, ...] | None = None
    conversation_id: str | None = None
    call_id: str = field(default_factory=lambda: f"call-{uuid.uuid4().hex[:12]}")


class PolicyPort(Protocol):
    def evaluate(self, tool: str, args: dict, *, source: str = "user",
                 tainted: bool = False, approved: bool = False,
                 task_allowed_tools: set[str] | None = None,
                 trace_id: str | None = None, task: str | None = None,
                 conversation_id: str | None = None,
                 ct_trm_mode: str = "full_ct_trm"): ...


class ToolExecutorPort(Protocol):
    def execute(self, tool: str, args: dict) -> dict: ...


class AuditPort(Protocol):
    def append(self, **values) -> dict: ...


class ToolGatewayPort(Protocol):
    def invoke(self, call: ToolCall) -> dict: ...

    def authorize(self, call: ToolCall) -> dict: ...


class AgentAdapterPort(Protocol):
    def status(self) -> dict: ...

    def run(self, prompt: str, max_steps: int = 8,
            allowed_tools: list[str] | None = None) -> dict: ...
