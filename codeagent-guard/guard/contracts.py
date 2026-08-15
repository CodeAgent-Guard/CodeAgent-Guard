from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from typing import Any, Literal, Protocol, TypedDict


FusionAction = Literal["allow", "ask", "deny"]
ApprovalStatus = Literal[
    "not_required", "pending", "approved", "rejected", "expired"
]
ExecutionStatus = Literal[
    "not_executed", "success", "failed", "unknown_side_effects"
]


class TaskScope(TypedDict):
    allowed_tools: list[str]
    max_calls: int
    argument_constraints: dict[str, Any]


class ToolOutcome(TypedDict, total=False):
    trace_id: str
    call_id: str
    fusion_action: FusionAction
    action: FusionAction
    approval_status: ApprovalStatus
    execution_authorized: bool
    execution_attempted: bool
    execution_status: ExecutionStatus
    execution_error: str
    execution_delegated: bool
    risk_level: str
    reasons: list[str]
    result: dict[str, Any]
    approval_id: str | None


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
    metadata: dict[str, Any] = field(default_factory=dict)
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
    def invoke(self, call: ToolCall) -> ToolOutcome: ...

    def authorize(self, call: ToolCall) -> ToolOutcome: ...


class AgentAdapterPort(Protocol):
    def status(self) -> dict: ...

    def run(self, prompt: str, max_steps: int = 8,
            allowed_tools: list[str] | None = None,
            task_scope: TaskScope | None = None) -> dict: ...
