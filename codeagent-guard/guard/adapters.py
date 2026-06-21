from __future__ import annotations

import uuid

from .contracts import ToolCall, ToolGatewayPort
from .transparency import TransparencyService


class ExternalAgentAdapter:
    """Adapter surface for OpenCode, MCP hosts, or other coding agents."""

    def __init__(
        self,
        gateway: ToolGatewayPort,
        transparency: TransparencyService,
        agent_id: str,
    ) -> None:
        self.gateway = gateway
        self.transparency = transparency
        self.agent_id = agent_id

    def start_task(
        self,
        task: str,
        *,
        trace_id: str | None = None,
        metadata: dict | None = None,
    ) -> str:
        trace_id = trace_id or f"trace-{uuid.uuid4().hex[:12]}"
        self.transparency.begin(
            trace_id,
            task=task,
            agent_id=self.agent_id,
            metadata=metadata or {},
        )
        self.transparency.emit(
            trace_id,
            phase="user_task",
            actor="user",
            label="用户任务",
            status="submitted",
            title=f"任务已提交给 {self.agent_id}",
            summary=task,
            details={"prompt": task},
        )
        return trace_id

    def invoke_tool(
        self,
        trace_id: str,
        task: str,
        tool: str,
        args: dict,
        *,
        source: str = "agent",
        tainted: bool = False,
        call_id: str | None = None,
        allowed_tools: list[str] | tuple[str, ...] | None = None,
    ) -> dict:
        return self.gateway.invoke(ToolCall(
            tool=tool,
            args=args,
            trace_id=trace_id,
            task=task,
            source=source,
            tainted=tainted,
            approved=False,
            agent_id=self.agent_id,
            allowed_tools=(
                tuple(allowed_tools) if allowed_tools is not None else None
            ),
            call_id=call_id or f"call-{uuid.uuid4().hex[:12]}",
        ))

    def report(
        self,
        trace_id: str,
        *,
        phase: str,
        title: str,
        summary: str,
        status: str = "reported",
        details: dict | None = None,
    ) -> dict:
        return self.transparency.emit(
            trace_id,
            phase=phase,
            actor=self.agent_id,
            label=f"{self.agent_id} 事件",
            status=status,
            title=title,
            summary=summary,
            details=details or {},
        )

    def finish(self, trace_id: str, answer: str) -> dict:
        self.transparency.emit(
            trace_id,
            phase="final_answer",
            actor=self.agent_id,
            label=f"{self.agent_id} 最终回答",
            status="completed",
            title="任务处理完成",
            summary=answer,
            details={"answer": answer},
        )
        return self.transparency.snapshot(trace_id)
