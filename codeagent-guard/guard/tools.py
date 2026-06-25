from __future__ import annotations

import copy
import json
import threading
import time
import uuid
from dataclasses import replace
from pathlib import Path

from .contracts import AuditPort, PolicyPort, ToolCall, ToolExecutorPort
from .executors import ToolExecutorRegistry
from .state import RuntimeStateStore
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
        state_store: RuntimeStateStore | None = None,
        approval_ttl_seconds: int = 900,
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
        self.state_store = state_store
        self.approval_ttl_seconds = approval_ttl_seconds
        self._pending_approvals: dict[str, tuple[ToolCall, bool]] = {}
        self._approval_lock = threading.RLock()
        self._restore_pending_approvals()

    def invoke(self, call: ToolCall) -> dict:
        return self._handle(call, execute=True)

    def authorize(self, call: ToolCall) -> dict:
        """Run policy/audit for an external tool that will execute elsewhere."""
        return self._handle(call, execute=False)

    def _handle(self, call: ToolCall, *, execute: bool) -> dict:
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
            trace_id=call.trace_id,
            task=call.task,
            conversation_id=call.conversation_id,
        )
        policy_latency_ms = (time.perf_counter() - started) * 1000
        if decision.assessment:
            self.transparency.emit(
                call.trace_id,
                phase="ct_trm_assessment",
                actor="ct_trm",
                label="CT-TRM 风险模型",
                status=decision.assessment.get("action", decision.action),
                title=(
                    "上下文污染与工具风险评估："
                    f"{decision.assessment.get('action', decision.action).upper()}"
                ),
                summary=decision.assessment.get(
                    "explanation",
                    "CT-TRM 已完成风险聚合。",
                ),
                details={
                    "call_id": call.call_id,
                    "tool": call.tool,
                    **decision.assessment,
                },
            )
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
            title = f"执行 {call.tool}" if execute else f"批准 {call.tool}"
            summary_text = (
                f"Tool Proxy 将批准后的参数交给 {call.tool} 执行器。"
                if execute
                else (
                    "Tool Proxy 已完成策略审批，实际执行权返回给外部 Agent。"
                )
            )
            self.transparency.emit(
                call.trace_id,
                phase="tool_action",
                actor="tool_proxy",
                label="Tool Proxy 行动",
                status="executed" if execute else "approved",
                title=title,
                summary=summary_text,
                details={
                    "call_id": call.call_id,
                    "tool": call.tool,
                    "executed": execute,
                    "execution_delegated": not execute,
                    "arguments": decision.normalized_args,
                },
            )
            if execute:
                try:
                    result = self.executor.execute(
                        call.tool, decision.normalized_args
                    )
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
                    details={
                        "call_id": call.call_id,
                        "tool": call.tool,
                        "result": result,
                    },
                )
                observer = getattr(self.policy, "observe_tool_result", None)
                if observer is not None:
                    observer(
                        call.tool,
                        decision.normalized_args,
                        result,
                        action,
                        trace_id=call.trace_id,
                        call_id=call.call_id,
                        conversation_id=call.conversation_id,
                        taint_matches=decision.taint_matches,
                    )
            else:
                result = {
                    "approved": True,
                    "execution_delegated": True,
                    "normalized_args": decision.normalized_args,
                    "result_unavailable": True,
                }
                summary = "Policy approved delegated external execution"
                self.transparency.emit(
                    call.trace_id,
                    phase="tool_result",
                    actor="external_agent",
                    label="外部工具执行结果",
                    status="unavailable",
                    title=f"{call.tool} 结果由外部 Agent 持有",
                    summary=(
                        "Guard 仅完成执行前授权，当前未收到外部工具结果。"
                    ),
                    details={
                        "call_id": call.call_id,
                        "tool": call.tool,
                        "execution_delegated": True,
                        "result_unavailable": True,
                    },
                )
        else:
            approval_id = None
            if action == "ask":
                approval_id = f"approval-{uuid.uuid4().hex[:12]}"
                with self._approval_lock:
                    approved_call = replace(
                        call,
                        args=copy.deepcopy(call.args),
                        approved=True,
                    )
                    self._pending_approvals[approval_id] = (
                        approved_call,
                        execute,
                    )
                    if self.state_store is not None:
                        self.state_store.save_approval(
                            approval_id,
                            self._call_dict(approved_call),
                            execute=execute,
                            ttl_seconds=self.approval_ttl_seconds,
                        )
                summary = "Waiting for explicit user confirmation"
                result = {
                    "approval_required": True,
                    "approval_id": approval_id,
                    "execution_delegated": not execute,
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
            args=TransparencyService.redact(decision.normalized_args),
            decision=action,
            risk_level=decision.risk_level,
            reasons=decision.reasons,
            source=call.source,
            tainted=call.tainted,
            result_summary=str(TransparencyService.redact(summary)),
            latency_ms=policy_latency_ms,
            ct_trm=TransparencyService.redact(decision.assessment),
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
            "execution_delegated": bool(result.get("execution_delegated")),
            "ct_trm": decision.assessment,
            "events": self.transparency.snapshot(call.trace_id)["events"],
        }

    def execute(self, tool: str, args: dict, *, trace_id: str | None = None,
                task: str = "手动工具调用", source: str = "user",
                tainted: bool = False, approved: bool = False,
                agent_id: str = "external-agent", call_id: str | None = None,
                allowed_tools: list[str] | tuple[str, ...] | None = None,
                conversation_id: str | None = None) -> dict:
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
            conversation_id=conversation_id,
            call_id=call_id or f"call-{uuid.uuid4().hex[:12]}",
        ))

    def list_approvals(self) -> list[dict]:
        if self.state_store is not None:
            return [
                self._public_approval(item)
                for item in self.state_store.list_pending_approvals()
            ]
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
                    "execution_delegated": not execute,
                }
                for approval_id, (call, execute) in self._pending_approvals.items()
            ]

    def get_approval(self, approval_id: str) -> dict | None:
        """Return redacted approval metadata without consuming the request."""
        if self.state_store is not None:
            item = self.state_store.get_approval(approval_id)
            if item is None or item["status"] != "pending":
                return None
            self._restore_pending_item(item)
            return self._public_approval(item)
        with self._approval_lock:
            pending = self._pending_approvals.get(approval_id)
            if pending is None:
                return None
            call, execute = pending
            return {
                "approval_id": approval_id,
                "trace_id": call.trace_id,
                "call_id": call.call_id,
                "agent_id": call.agent_id,
                "task": call.task,
                "tool": call.tool,
                "args": TransparencyService.redact(call.args),
                "execution_delegated": not execute,
            }

    def get_approval_status(self, approval_id: str) -> dict | None:
        if self.state_store is not None:
            item = self.state_store.get_approval(approval_id)
            if item is None:
                return None
            return {
                **self._public_approval(item),
                "status": item["status"],
                "resolved_at": item["resolved_at"],
                "resolution": TransparencyService.redact(
                    item.get("resolution") or {}
                ),
            }
        approval = self.get_approval(approval_id)
        if approval is None:
            return None
        return {**approval, "status": "pending", "resolution": {}}

    def resolve_approval(self, approval_id: str, *, approve: bool,
                         actor: str = "user") -> dict:
        persisted = None
        if self.state_store is not None:
            persisted = self.state_store.get_approval(approval_id)
            if persisted is None or persisted["status"] != "pending":
                with self._approval_lock:
                    self._pending_approvals.pop(approval_id, None)
                raise ValueError(
                    "Approval does not exist, has expired, or was already resolved"
                )
        with self._approval_lock:
            pending = self._pending_approvals.pop(approval_id, None)
            if pending is None and persisted is not None:
                pending = self._pending_from_item(persisted)
        if pending is None:
            raise ValueError("审批请求不存在、已处理或服务已重启")
        call, execute = pending
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
            outcome = self._handle(call, execute=execute)
            self._store_resolution(
                approval_id,
                status="approved",
                outcome=outcome,
            )
            return outcome

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
        outcome = {
            "trace_id": call.trace_id,
            "call_id": call.call_id,
            "action": "deny",
            "risk_level": "medium",
            "reasons": ["user_rejected"],
            "result": {"approved": False},
            "audit": audit_event,
            "latency_ms": 0,
            "approval_id": approval_id,
            "execution_delegated": not execute,
            "events": self.transparency.snapshot(call.trace_id)["events"],
        }
        self._store_resolution(
            approval_id,
            status="rejected",
            outcome=outcome,
        )
        return outcome

    def _restore_pending_approvals(self) -> None:
        if self.state_store is None:
            return
        for item in self.state_store.list_pending_approvals():
            self._restore_pending_item(item)

    def _restore_pending_item(self, item: dict) -> None:
        with self._approval_lock:
            self._pending_approvals.setdefault(
                item["approval_id"],
                self._pending_from_item(item),
            )

    @staticmethod
    def _pending_from_item(item: dict) -> tuple[ToolCall, bool]:
        allowed_tools = item.get("allowed_tools")
        return (
            ToolCall(
                tool=item["tool"],
                args=item.get("args") or {},
                trace_id=item["trace_id"],
                task=item.get("task") or "Tool call",
                source=item.get("source") or "agent",
                tainted=bool(item.get("tainted")),
                approved=True,
                agent_id=item.get("agent_id") or "external-agent",
                allowed_tools=(
                    tuple(allowed_tools)
                    if allowed_tools is not None
                    else None
                ),
                conversation_id=item.get("conversation_id"),
                call_id=item["call_id"],
            ),
            bool(item.get("execute", True)),
        )

    @staticmethod
    def _call_dict(call: ToolCall) -> dict:
        return {
            "tool": call.tool,
            "args": call.args,
            "trace_id": call.trace_id,
            "task": call.task,
            "source": call.source,
            "tainted": call.tainted,
            "agent_id": call.agent_id,
            "allowed_tools": (
                list(call.allowed_tools)
                if call.allowed_tools is not None
                else None
            ),
            "conversation_id": call.conversation_id,
            "call_id": call.call_id,
        }

    @staticmethod
    def _public_approval(item: dict) -> dict:
        return {
            "approval_id": item["approval_id"],
            "trace_id": item["trace_id"],
            "call_id": item["call_id"],
            "agent_id": item["agent_id"],
            "task": item["task"],
            "tool": item["tool"],
            "args": TransparencyService.redact(item.get("args") or {}),
            "execution_delegated": not bool(item.get("execute", True)),
            "created_at": item.get("created_at"),
            "expires_at": item.get("expires_at"),
            "status": item.get("status", "pending"),
            "source": item.get("source"),
            "tainted": bool(item.get("tainted", False)),
            "allowed_tools": item.get("allowed_tools"),
            "conversation_id": item.get("conversation_id"),
        }

    def _store_resolution(
        self,
        approval_id: str,
        *,
        status: str,
        outcome: dict,
    ) -> None:
        if self.state_store is None:
            return
        resolution = {
            "trace_id": outcome.get("trace_id"),
            "call_id": outcome.get("call_id"),
            "action": outcome.get("action"),
            "risk_level": outcome.get("risk_level"),
            "reasons": outcome.get("reasons") or [],
            "result": outcome.get("result") or {},
            "execution_delegated": bool(
                outcome.get("execution_delegated")
            ),
        }
        self.state_store.resolve_approval(
            approval_id,
            status=status,
            resolution=TransparencyService.redact(resolution),
            retention_seconds=self.approval_ttl_seconds,
        )

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
