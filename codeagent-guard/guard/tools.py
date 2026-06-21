from __future__ import annotations

import json
import threading
import time
import uuid
from dataclasses import replace
from pathlib import Path

from .contracts import AuditPort, PolicyPort, ToolCall, ToolExecutorPort
from .executors import ToolExecutorRegistry
from .transparency import TransparencyService


class ToolProxy:
    """Unified security gateway between any Agent and external tools."""

    def __init__(
        self,
        workspace: Path,
        audit: AuditPort,
        policy: PolicyPort,
        outbox: Path,
        *,
        executor: ToolExecutorPort | None = None,
        transparency: TransparencyService | None = None,
    ) -> None:
        self.workspace = workspace.resolve()
        self.audit = audit
        self.policy = policy
        self.executor = executor or ToolExecutorRegistry(
            self.workspace,
            outbox,
            open_directory_roots=getattr(
                policy, "open_directory_roots", ()
            ),
            external_write_roots=getattr(
                policy, "external_write_roots", ()
            ),
            trusted_workspace_roots=getattr(
                policy, "trusted_workspace_roots", ()
            ),
        )
        self.transparency = transparency or TransparencyService()
        self._pending_approvals: dict[str, ToolCall] = {}
        self._approval_lock = threading.RLock()

    def invoke(self, call: ToolCall) -> dict:
        self.transparency.begin(
            call.trace_id,
            task=call.task,
            agent_id=call.agent_id,
            metadata={"source": call.source},
        )
        self.transparency.emit(
            call.trace_id,
            phase="agent_plan",
            actor=call.agent_id,
            label="AI Agent 工具请求",
            status="planned",
            title=f"请求调用工具 {call.tool}",
            summary=f"{call.agent_id} 将 {call.tool} 调用提交给 Tool Proxy。",
            details={
                "call_id": call.call_id,
                "tool": call.tool,
                "arguments": call.args,
                "source": call.source,
                "tainted": call.tainted,
            },
        )

        started = time.perf_counter()
        decision = self.policy.evaluate(
            call.tool,
            call.args,
            source=call.source,
            tainted=call.tainted,
            approved=call.approved,
            task_allowed_tools=(
                set(call.allowed_tools) if call.allowed_tools is not None else None
            ),
        )
        policy_latency_ms = (time.perf_counter() - started) * 1000
        self.transparency.emit(
            call.trace_id,
            phase="policy_decision",
            actor="policy_engine",
            label="Policy Engine",
            status=decision.action,
            title=f"策略判定：{decision.action.upper()}",
            summary=self._policy_summary(
                decision.action, decision.risk_level, decision.reasons
            ),
            details={
                "call_id": call.call_id,
                "tool": call.tool,
                "decision": decision.action,
                "risk_level": decision.risk_level,
                "matched_rules": decision.reasons or ["policy_passed"],
                "normalized_arguments": decision.normalized_args,
                "latency_ms": round(policy_latency_ms, 3),
            },
        )

        result: dict = {}
        summary = "Policy blocked execution"
        action = decision.action
        if action == "allow":
            self.transparency.emit(
                call.trace_id,
                phase="tool_action",
                actor="tool_proxy",
                label="Tool Proxy 行动",
                status="executed",
                title=f"执行 {call.tool}",
                summary=f"Tool Proxy 将批准后的参数交给 {call.tool} 执行器。",
                details={
                    "call_id": call.call_id,
                    "tool": call.tool,
                    "executed": True,
                    "arguments": decision.normalized_args,
                },
            )
            try:
                result = self.executor.execute(call.tool, decision.normalized_args)
                summary = self._summarize(result)
            except Exception as exc:
                action = "deny"
                decision.action = "deny"
                decision.risk_level = "medium"
                if "tool_execution_failed" not in decision.reasons:
                    decision.reasons.append("tool_execution_failed")
                result = {"error": str(exc)}
                summary = f"Execution failed: {exc}"
            self.transparency.emit(
                call.trace_id,
                phase="tool_result",
                actor="tool_executor",
                label="工具执行结果",
                status="success" if not result.get("error") else "error",
                title=f"{call.tool} 返回结果",
                summary=TransparencyService.result_summary(result),
                details={"call_id": call.call_id, "tool": call.tool, "result": result},
            )
        else:
            approval_id = None
            if action == "ask":
                approval_id = f"approval-{uuid.uuid4().hex[:12]}"
                with self._approval_lock:
                    self._pending_approvals[approval_id] = replace(
                        call, approved=True
                    )
                summary = "Waiting for explicit user confirmation"
                result = {
                    "approval_required": True,
                    "approval_id": approval_id,
                }
            self.transparency.emit(
                call.trace_id,
                phase="tool_action",
                actor="tool_proxy",
                label="Tool Proxy 行动",
                status=action,
                title=f"{'暂停' if action == 'ask' else '阻断'} {call.tool}",
                summary=(
                    f"Tool Proxy 未执行 {call.tool}，等待显式批准。"
                    if action == "ask"
                    else f"Tool Proxy 未执行 {call.tool}，不存在工具副作用。"
                ),
                details={
                    "call_id": call.call_id,
                    "tool": call.tool,
                    "executed": False,
                    "arguments": decision.normalized_args,
                    "approval_id": approval_id,
                },
            )

        total_latency_ms = (time.perf_counter() - started) * 1000
        audit_event = self.audit.append(
            trace_id=call.trace_id,
            task=call.task,
            tool=call.tool,
            args=decision.normalized_args,
            decision=action,
            risk_level=decision.risk_level,
            reasons=decision.reasons,
            source=call.source,
            tainted=call.tainted,
            result_summary=summary,
            latency_ms=policy_latency_ms,
        )
        self.transparency.emit(
            call.trace_id,
            phase="audit_record",
            actor="audit",
            label="Audit & Hash Chain",
            status="recorded",
            title="调用已写入防篡改审计链",
            summary=f"审计事件 #{audit_event['seq']} 已记录并连接到前序哈希。",
            details={
                "call_id": call.call_id,
                "audit_seq": audit_event["seq"],
                "prev_hash": audit_event["prev_hash"],
                "hash": audit_event["hash"],
                "policy_latency_ms": round(policy_latency_ms, 3),
                "total_latency_ms": round(total_latency_ms, 3),
            },
        )
        return {
            "trace_id": call.trace_id,
            "call_id": call.call_id,
            "action": action,
            "risk_level": decision.risk_level,
            "reasons": decision.reasons,
            "result": result,
            "audit": audit_event,
            "latency_ms": round(policy_latency_ms, 3),
            "total_latency_ms": round(total_latency_ms, 3),
            "approval_id": result.get("approval_id"),
            "events": self.transparency.snapshot(call.trace_id)["events"],
        }

    def execute(self, tool: str, args: dict, *, trace_id: str | None = None,
                task: str = "手动工具调用", source: str = "user",
                tainted: bool = False, approved: bool = False,
                agent_id: str = "external-agent", call_id: str | None = None,
                allowed_tools: list[str] | tuple[str, ...] | None = None) -> dict:
        """Compatibility facade for the built-in Agent and HTTP API."""
        return self.invoke(ToolCall(
            tool=tool,
            args=args,
            trace_id=trace_id or f"trace-{uuid.uuid4().hex[:12]}",
            task=task,
            source=source,
            tainted=tainted,
            approved=approved,
            agent_id=agent_id,
            allowed_tools=(
                tuple(allowed_tools) if allowed_tools is not None else None
            ),
            call_id=call_id or f"call-{uuid.uuid4().hex[:12]}",
        ))

    def list_approvals(self) -> list[dict]:
        with self._approval_lock:
            return [
                {
                    "approval_id": approval_id,
                    "trace_id": call.trace_id,
                    "call_id": call.call_id,
                    "agent_id": call.agent_id,
                    "task": call.task,
                    "tool": call.tool,
                    "args": TransparencyService.redact(call.args),
                }
                for approval_id, call in self._pending_approvals.items()
            ]

    def get_approval(self, approval_id: str) -> dict | None:
        """Return redacted approval metadata without consuming the request."""
        with self._approval_lock:
            call = self._pending_approvals.get(approval_id)
            if call is None:
                return None
            return {
                "approval_id": approval_id,
                "trace_id": call.trace_id,
                "call_id": call.call_id,
                "agent_id": call.agent_id,
                "task": call.task,
                "tool": call.tool,
                "args": TransparencyService.redact(call.args),
            }

    def resolve_approval(self, approval_id: str, *, approve: bool,
                         actor: str = "user") -> dict:
        with self._approval_lock:
            call = self._pending_approvals.pop(approval_id, None)
        if call is None:
            raise ValueError("审批请求不存在、已处理或服务已重启")
        self.transparency.emit(
            call.trace_id,
            phase="approval_decision",
            actor=actor,
            label="用户审批",
            status="approved" if approve else "rejected",
            title="用户批准高风险操作" if approve else "用户拒绝高风险操作",
            summary=(
                f"用户批准继续执行 {call.tool}。"
                if approve else f"用户拒绝执行 {call.tool}，工具不会产生副作用。"
            ),
            details={
                "approval_id": approval_id,
                "call_id": call.call_id,
                "tool": call.tool,
                "approved": approve,
            },
        )
        if approve:
            return self.invoke(call)

        audit_event = self.audit.append(
            trace_id=call.trace_id,
            task=call.task,
            tool=call.tool,
            args=call.args,
            decision="deny",
            risk_level="medium",
            reasons=["user_rejected"],
            source=call.source,
            tainted=call.tainted,
            result_summary="User rejected pending operation",
            latency_ms=0,
        )
        self.transparency.emit(
            call.trace_id,
            phase="audit_record",
            actor="audit",
            label="Audit & Hash Chain",
            status="recorded",
            title="审批拒绝已写入防篡改审计链",
            summary=f"审计事件 #{audit_event['seq']} 已记录。",
            details={
                "approval_id": approval_id,
                "audit_seq": audit_event["seq"],
                "prev_hash": audit_event["prev_hash"],
                "hash": audit_event["hash"],
            },
        )
        return {
            "trace_id": call.trace_id,
            "call_id": call.call_id,
            "action": "deny",
            "risk_level": "medium",
            "reasons": ["user_rejected"],
            "result": {"approved": False},
            "audit": audit_event,
            "latency_ms": 0,
            "approval_id": approval_id,
            "events": self.transparency.snapshot(call.trace_id)["events"],
        }

    @staticmethod
    def _policy_summary(action: str, risk: str, reasons: list[str]) -> str:
        if action == "allow":
            return f"风险等级 {risk.upper()}，未命中阻断规则，允许工具执行。"
        reason_text = "、".join(reasons) if reasons else "需要用户确认"
        if action == "ask":
            return f"风险等级 {risk.upper()}，命中 {reason_text}，暂停执行并等待用户确认。"
        return f"风险等级 {risk.upper()}，命中 {reason_text}，工具调用已阻断。"

    @staticmethod
    def _summarize(result: dict) -> str:
        return json.dumps(result, ensure_ascii=False)[:2000]
