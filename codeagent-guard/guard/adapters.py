from __future__ import annotations

import copy
import hashlib
import json
import os
from pathlib import Path
import re
import threading
import uuid
from typing import Any

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


class OpenCodeToolProxyAdapter(ExternalAgentAdapter):
    """Policy adapter for OpenCode's native tool names."""

    DEFAULT_ALLOWED_POLICY_TOOLS = (
        "read_file",
        "write_file",
        "run_command",
        "http_request",
        "list_directory",
        "search_files",
        "make_directory",
        "delete_path",
        "move_path",
    )

    INTERNAL_TOOLS = {
        "invalid",
        "question",
        "task",
        "todowrite",
        "skill",
    }

    def __init__(
        self,
        gateway: ToolGatewayPort,
        transparency: TransparencyService,
        agent_id: str = "opencode",
    ) -> None:
        super().__init__(gateway, transparency, agent_id)
        workspace = getattr(gateway, "workspace", None)
        self.workspace = Path(workspace).resolve() if workspace else None
        self._request_lock = threading.RLock()
        self._authorization_cache: dict[tuple[str, str], dict] = {}
        self._authorized_calls: dict[tuple[str, str], dict] = {}

    def reconcile_external_results(self, limit: int = 500) -> int:
        """Repair keyed Trace events from committed external-result audits."""
        audit_store = getattr(self.gateway, "audit", None)
        if audit_store is None:
            return 0
        repaired = 0
        for event in audit_store.list_events(limit):
            if event.get("event_type") != "external_execution_result":
                continue
            call_id = str(event.get("call_id") or "")
            evidence = event.get("result_evidence") or {}
            if not call_id or not evidence or not event.get("result_fingerprint"):
                continue
            authorization = self._recover_authorization(
                str(event.get("trace_id") or ""),
                call_id,
            )
            if authorization is None or not self._execution_is_authorized(
                authorization
            ):
                continue
            result_key = f"opencode:{call_id}:external-result"
            audit_key = f"opencode:{call_id}:external-result-audit"
            before = (
                self.transparency.find_event(event["trace_id"], result_key),
                self.transparency.find_event(event["trace_id"], audit_key),
            )
            self._ensure_external_result_trace(
                trace_id=event["trace_id"],
                call_id=call_id,
                authorization=authorization,
                result_audit=event,
                result_evidence=evidence,
            )
            after = (
                self.transparency.find_event(event["trace_id"], result_key),
                self.transparency.find_event(event["trace_id"], audit_key),
            )
            repaired += sum(
                1 for old, new in zip(before, after) if old is None and new is not None
            )
        return repaired

    def authorize_tool(
        self,
        *,
        trace_id: str,
        task: str,
        tool: str,
        args: dict,
        source: str = "agent",
        tainted: bool = False,
        call_id: str | None = None,
        allowed_tools: list[str] | tuple[str, ...] | None = None,
        metadata: dict | None = None,
    ) -> dict:
        metadata = metadata or {}
        actual_call_id = call_id or f"call-{uuid.uuid4().hex[:12]}"
        cache_key = (trace_id, actual_call_id)
        request_fingerprint = self._request_fingerprint(tool, args, metadata)
        authorization_fingerprint = self._authorization_fingerprint(
            tool=tool,
            args=args,
            task=task,
            source=source,
            tainted=tainted,
            allowed_tools=allowed_tools,
            metadata=metadata,
        )
        with self._request_lock:
            authorization = (
                self._authorized_calls.get(cache_key)
                or self._recover_authorization(trace_id, actual_call_id)
            )
            if authorization is not None:
                authorization = self._refresh_final_authorization(
                    trace_id,
                    actual_call_id,
                    authorization,
                )
                self._assert_authorization_matches(
                    authorization,
                    authorization_fingerprint,
                    trace_id,
                    actual_call_id,
                )
                self._authorized_calls[cache_key] = authorization
                cached = self._authorization_cache.get(cache_key)
                if (
                    cached is not None
                    and self._authorization_state(cached)
                    == self._authorization_state(authorization)
                ):
                    return copy.deepcopy(cached)
                return self._authorization_response(authorization)
            result = self._authorize_uncached(
                trace_id=trace_id,
                task=task,
                tool=tool,
                args=args,
                source=source,
                tainted=tainted,
                call_id=actual_call_id,
                allowed_tools=allowed_tools,
                metadata=metadata,
                request_fingerprint=request_fingerprint,
                authorization_fingerprint=authorization_fingerprint,
            )
            if len(self._authorization_cache) >= 1000:
                self._authorization_cache.pop(next(iter(self._authorization_cache)))
            self._authorization_cache[cache_key] = copy.deepcopy(result)
            self._authorized_calls[cache_key] = {
                "trace_id": trace_id,
                "call_id": actual_call_id,
                "fingerprint": request_fingerprint,
                "authorization_fingerprint": authorization_fingerprint,
                "raw_tool": tool,
                "raw_args": copy.deepcopy(args),
                "mapped_tool": result["opencode"]["policy_tool"],
                "mapped_args": copy.deepcopy(
                    result["opencode"]["policy_args"]
                ),
                "task": task,
                "source": source,
                "tainted": bool(tainted),
                "conversation_id": str(
                    metadata.get("session_id") or trace_id
                ),
                "fusion_action": (
                    result.get("fusion_action") or result.get("action")
                ),
                "action": (
                    result.get("fusion_action") or result.get("action")
                ),
                "approval_status": result.get("approval_status"),
                "execution_authorized": result.get("execution_authorized"),
                "execution_attempted": result.get("execution_attempted"),
                "execution_status": result.get("execution_status"),
                "execution_error": result.get("execution_error"),
                "risk_level": result.get("risk_level"),
                "reasons": list(result.get("reasons") or []),
                "audit": copy.deepcopy(result.get("audit") or {}),
                "approval_id": result.get("approval_id"),
                "ct_trm": copy.deepcopy(result.get("ct_trm") or {}),
            }
            if len(self._authorized_calls) >= 1000:
                self._authorized_calls.pop(next(iter(self._authorized_calls)))
            return result

    def _authorize_uncached(
        self,
        *,
        trace_id: str,
        task: str,
        tool: str,
        args: dict,
        source: str,
        tainted: bool,
        call_id: str,
        allowed_tools: list[str] | tuple[str, ...] | None,
        metadata: dict,
        request_fingerprint: str,
        authorization_fingerprint: str,
    ) -> dict:
        mapped_tool, mapped_args = self._map_tool(tool, args, metadata)
        execution_context = self._execution_context(args, metadata)
        result = self.gateway.authorize(ToolCall(
            tool=mapped_tool,
            args=mapped_args,
            trace_id=trace_id,
            task=task,
            source=source,
            tainted=tainted,
            approved=False,
            agent_id=self.agent_id,
            allowed_tools=(
                tuple(allowed_tools)
                if allowed_tools is not None
                else self.DEFAULT_ALLOWED_POLICY_TOOLS
            ),
            conversation_id=str(
                metadata.get("session_id") or trace_id
            ),
            metadata={
                "integration": "opencode",
                "raw_tool": tool,
                "raw_arguments": args,
                "execution_context": execution_context,
                "request_fingerprint": request_fingerprint,
                "authorization_fingerprint": authorization_fingerprint,
            },
            call_id=call_id,
        ))
        result["opencode"] = {
            "tool": tool,
            "policy_tool": mapped_tool,
            "policy_args": mapped_args,
        }
        return result

    def record_tool_result(
        self,
        *,
        trace_id: str,
        task: str,
        tool: str,
        args: dict,
        result: Any,
        call_id: str | None = None,
        metadata: dict | None = None,
    ) -> dict:
        metadata = metadata or {}
        if not call_id:
            raise ValueError("OpenCode tool result requires call_id")
        actual_call_id = str(call_id)
        cache_key = (trace_id, actual_call_id)
        request_fingerprint = self._request_fingerprint(tool, args, metadata)
        with self._request_lock:
            authorization = (
                self._authorized_calls.get(cache_key)
                or self._recover_authorization(trace_id, actual_call_id)
            )
            if authorization is None:
                raise ValueError(
                    "OpenCode tool result has no matching authorization"
                )
            self._assert_request_matches(
                authorization,
                request_fingerprint,
                trace_id,
                actual_call_id,
            )
            authorization = self._refresh_final_authorization(
                trace_id,
                actual_call_id,
                authorization,
            )
            if not self._execution_is_authorized(authorization):
                raise ValueError(
                    "OpenCode tool result is not backed by execution authorization"
                )
            self._authorized_calls[cache_key] = authorization
            return self._record_tool_result_uncached(
                trace_id=trace_id,
                authorization=authorization,
                result=result,
                call_id=actual_call_id,
            )

    def _record_tool_result_uncached(
        self,
        *,
        trace_id: str,
        authorization: dict,
        result: Any,
        call_id: str,
    ) -> dict:
        mapped_tool = str(authorization["mapped_tool"])
        mapped_args = copy.deepcopy(authorization["mapped_args"])
        raw_tool = str(authorization["raw_tool"])
        result_fingerprint = self._external_result_fingerprint(result)
        result_payload = self._normalize_external_result(
            mapped_tool,
            mapped_args,
            result,
        )
        sanitized_result = result_payload
        output_scan: dict = {}
        policy = getattr(self.gateway, "policy", None)
        result_scanner = getattr(policy, "scan_tool_result", None)
        if result_scanner is not None:
            sanitized_result, output_scan = result_scanner(
                mapped_tool,
                result_payload,
            )
        result_error = self._external_result_error(sanitized_result)
        result_status = "failed" if result_error else "success"
        fusion_action = str(
            authorization.get("fusion_action")
            or authorization.get("action")
            or ""
        )
        approval_status = str(
            authorization.get("approval_status") or "not_required"
        )
        result_evidence = {
            "tool": mapped_tool,
            "external_tool": raw_tool,
            "result": TransparencyService.redact(sanitized_result),
            "dlp_scan": TransparencyService.redact(output_scan),
            "fusion_action": fusion_action,
            "approval_status": approval_status,
            "execution_authorized": True,
            "execution_attempted": True,
            "execution_status": result_status,
            "execution_error": TransparencyService.redact(result_error),
        }
        audit_store = getattr(self.gateway, "audit", None)
        if audit_store is None:
            raise RuntimeError("OpenCode result recording requires an audit store")
        existing = self._existing_result_audit(trace_id, call_id)
        if existing is not None:
            if existing.get("result_fingerprint") != result_fingerprint:
                raise ValueError(
                    "conflicting external execution result for "
                    f"{trace_id}/{call_id}"
                )
            return self._ensure_external_result_trace(
                trace_id=trace_id,
                call_id=call_id,
                authorization=authorization,
                result_audit=existing,
                result_evidence=existing.get("result_evidence") or result_evidence,
            )

        observer = getattr(policy, "observe_tool_result", None)
        if observer is not None:
            observer(
                mapped_tool,
                mapped_args,
                sanitized_result,
                # This path is reached only after execution authorization.
                # Keep the persisted lifecycle Fusion action (including ASK)
                # separate from the ALLOW fact needed by chain-risk state.
                "allow",
                trace_id=trace_id,
                call_id=call_id,
                conversation_id=str(
                    authorization.get("conversation_id") or trace_id
                ),
                result_fingerprint=result_fingerprint,
            )
        result_audit = audit_store.append(
            trace_id=trace_id,
            task=str(authorization.get("task") or "OpenCode tool call"),
            tool=mapped_tool,
            args=TransparencyService.redact(mapped_args),
            decision=fusion_action,
            risk_level=str(authorization.get("risk_level") or "low"),
            reasons=list(authorization.get("reasons") or []),
            source=str(authorization.get("source") or "agent"),
            tainted=bool(authorization.get("tainted", False)),
            result_summary=TransparencyService.result_summary(sanitized_result),
            latency_ms=0,
            event_type="external_execution_result",
            call_id=call_id,
            execution_status=result_status,
            execution_attempted=True,
            approval_status=approval_status,
            execution_error=str(
                TransparencyService.redact(result_error)
            ),
            result_fingerprint=result_fingerprint,
            result_evidence=result_evidence,
        )
        return self._ensure_external_result_trace(
            trace_id=trace_id,
            call_id=call_id,
            authorization=authorization,
            result_audit=result_audit,
            result_evidence=result_evidence,
        )

    def _ensure_external_result_trace(
        self,
        *,
        trace_id: str,
        call_id: str,
        authorization: dict,
        result_audit: dict,
        result_evidence: dict,
    ) -> dict:
        mapped_tool = str(result_evidence.get("tool") or authorization["mapped_tool"])
        raw_tool = str(
            result_evidence.get("external_tool") or authorization["raw_tool"]
        )
        sanitized_result = result_evidence.get("result") or {}
        output_scan = result_evidence.get("dlp_scan") or {}
        result_status = str(
            result_evidence.get("execution_status")
            or result_audit.get("execution_status")
            or "success"
        )
        # Historical external-result rows used ``error``.  Keep those audit
        # hashes untouched while exposing the current execution vocabulary.
        if result_status == "error":
            result_status = "failed"
        fusion_action = str(
            result_evidence.get("fusion_action")
            or authorization.get("fusion_action")
            or authorization.get("action")
            or result_audit.get("decision")
            or ""
        )
        approval_status = str(
            result_evidence.get("approval_status")
            or authorization.get("approval_status")
            or result_audit.get("approval_status")
            or "not_required"
        )
        execution_error = str(
            result_evidence.get("execution_error")
            or result_audit.get("execution_error")
            or ""
        )
        if output_scan.get("finding_count"):
            output_evidence = dict(output_scan)
            output_evidence.pop("action", None)
            self.transparency.emit(
                trace_id,
                phase="dlp_scan",
                actor="dlp",
                label="DLP 输出脱敏",
                status="redacted",
                title="DLP 输出扫描：REDACTED",
                summary="OpenCode 工具结果包含敏感数据，已生成脱敏摘要和 HMAC 指纹。",
                details={
                    "call_id": call_id,
                    "tool": mapped_tool,
                    **output_evidence,
                    "evidence_only": True,
                },
                event_key=f"opencode:{call_id}:external-result-dlp",
            )
        self.transparency.emit(
            trace_id,
            phase="tool_result",
            actor=self.agent_id,
            label="OpenCode 工具执行结果",
            status=result_status,
            title=f"{mapped_tool} 返回结果",
            summary=TransparencyService.result_summary(sanitized_result),
            details={
                "call_id": call_id,
                "tool": mapped_tool,
                "external_tool": raw_tool,
                "result": sanitized_result,
                "execution_delegated": True,
                "fusion_action": fusion_action,
                "approval_status": approval_status,
                "execution_authorized": True,
                "execution_attempted": True,
                "execution_status": result_status,
                "execution_error": execution_error,
            },
            event_key=f"opencode:{call_id}:external-result",
        )
        self.transparency.emit(
            trace_id,
            phase="audit_record",
            actor="audit",
            label="Audit & Hash Chain",
            status="recorded",
            title="OpenCode 执行结果已写入防篡改审计链",
            summary=(
                f"审计事件 #{result_audit['seq']} 记录了外部工具的"
                "实际执行结果，并连接到前序哈希。"
            ),
            details={
                "call_id": call_id,
                "audit_seq": result_audit["seq"],
                "audit_type": "external_execution_result",
                "authorization_audit_seq": (
                    authorization.get("audit") or {}
                ).get("seq"),
                "prev_hash": result_audit["prev_hash"],
                "hash": result_audit["hash"],
                "fusion_action": fusion_action,
                "approval_status": approval_status,
                "execution_authorized": True,
                "execution_attempted": True,
                "execution_status": result_status,
                "execution_error": execution_error,
            },
            event_key=f"opencode:{call_id}:external-result-audit",
        )
        return self.transparency.snapshot(trace_id)

    @staticmethod
    def _external_result_error(result: Any) -> str:
        if not isinstance(result, dict):
            return ""
        if result.get("error"):
            return str(result["error"])
        try:
            raw_exit_code = result.get("exit_code")
            exit_code = 0 if raw_exit_code in (None, "") else int(raw_exit_code)
        except (TypeError, ValueError):
            return "external tool returned an invalid exit code"
        return (
            str(result.get("stderr") or f"process exited with code {exit_code}")
            if exit_code
            else ""
        )

    @staticmethod
    def _request_fingerprint(tool: str, args: dict, metadata: dict) -> str:
        payload = {
            "tool": str(tool).strip().lower(),
            "args": args,
            "directory": OpenCodeToolProxyAdapter._working_directory(
                args,
                metadata,
            ),
            "home": OpenCodeToolProxyAdapter._normalize_host_path(
                str(metadata.get("home") or "")
            ),
            "session_id": str(metadata.get("session_id") or ""),
        }
        return OpenCodeToolProxyAdapter._json_fingerprint(payload)

    @classmethod
    def _authorization_fingerprint(
        cls,
        *,
        tool: str,
        args: dict,
        task: str,
        source: str,
        tainted: bool,
        allowed_tools: list[str] | tuple[str, ...] | None,
        metadata: dict,
    ) -> str:
        effective_allowed = (
            tuple(allowed_tools)
            if allowed_tools is not None
            else cls.DEFAULT_ALLOWED_POLICY_TOOLS
        )
        return cls._json_fingerprint({
            "request_fingerprint": cls._request_fingerprint(tool, args, metadata),
            "task": str(task),
            "source": str(source),
            "tainted": bool(tainted),
            "allowed_tools": sorted(str(item) for item in effective_allowed),
            "project": cls._normalize_host_path(str(metadata.get("project") or "")),
            "worktree": cls._normalize_host_path(str(metadata.get("worktree") or "")),
        })

    @staticmethod
    def _json_fingerprint(value: Any) -> str:
        canonical = json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            default=str,
        )
        return hashlib.sha256(canonical.encode()).hexdigest()

    @classmethod
    def _external_result_fingerprint(cls, result: Any) -> str:
        if not isinstance(result, dict):
            return cls._json_fingerprint(result)
        payload = copy.deepcopy(result)
        reported = str(payload.pop("_guard_result_fingerprint", ""))
        if re.fullmatch(r"[0-9a-fA-F]{64}", reported):
            return cls._json_fingerprint({
                "reported_full_result_sha256": reported.lower(),
                "received_result": payload,
            })
        return cls._json_fingerprint(payload)

    @staticmethod
    def _assert_request_matches(
        authorization: dict,
        fingerprint: str,
        trace_id: str,
        call_id: str,
    ) -> None:
        authorized = str(authorization.get("fingerprint") or "")
        if not authorized or authorized != fingerprint:
            raise ValueError(
                "OpenCode call_id was reused with a different tool, "
                f"arguments, or working directory: {trace_id}/{call_id}"
            )

    @staticmethod
    def _assert_authorization_matches(
        authorization: dict,
        fingerprint: str,
        trace_id: str,
        call_id: str,
    ) -> None:
        authorized = str(
            authorization.get("authorization_fingerprint") or ""
        )
        if not authorized or authorized != fingerprint:
            raise ValueError(
                "OpenCode call_id was reused with a different authorization "
                f"context: {trace_id}/{call_id}"
            )

    @staticmethod
    def _authorization_response(authorization: dict) -> dict:
        fusion_action = str(
            authorization.get("fusion_action")
            or authorization.get("action")
            or ""
        )
        return {
            "trace_id": authorization.get("trace_id"),
            "call_id": authorization.get("call_id"),
            "fusion_action": fusion_action,
            # Backward-compatible alias; never represents execution outcome.
            "action": fusion_action,
            "approval_status": (
                authorization.get("approval_status") or "not_required"
            ),
            "execution_authorized": bool(
                authorization.get("execution_authorized")
            ),
            "execution_attempted": bool(
                authorization.get("execution_attempted")
            ),
            "execution_status": (
                authorization.get("execution_status") or "not_executed"
            ),
            "execution_error": authorization.get("execution_error") or "",
            "risk_level": authorization.get("risk_level"),
            "reasons": list(authorization.get("reasons") or []),
            "result": copy.deepcopy(authorization.get("result") or {}),
            "audit": copy.deepcopy(authorization.get("audit") or {}),
            "approval_id": authorization.get("approval_id"),
            "execution_delegated": True,
            "ct_trm": copy.deepcopy(authorization.get("ct_trm") or {}),
            "opencode": {
                "tool": authorization.get("raw_tool"),
                "policy_tool": authorization.get("mapped_tool"),
                "policy_args": copy.deepcopy(
                    authorization.get("mapped_args") or {}
                ),
            },
        }

    @staticmethod
    def _authorization_state(value: dict) -> tuple:
        """Fields that can change while an ASK approval is being resolved."""
        return (
            value.get("fusion_action") or value.get("action"),
            value.get("approval_status") or "not_required",
            bool(value.get("execution_authorized")),
            bool(value.get("execution_attempted")),
            value.get("execution_status") or "not_executed",
        )

    @staticmethod
    def _execution_is_authorized(authorization: dict) -> bool:
        """Accept ALLOW or an approved ASK only when execution is explicit."""
        explicit = authorization.get("execution_authorized")
        if explicit is not None:
            return bool(explicit)
        # Compatibility for traces written before execution_authorized existed.
        fusion_action = str(
            authorization.get("fusion_action")
            or authorization.get("action")
            or ""
        )
        approval_status = str(
            authorization.get("approval_status") or "not_required"
        )
        return fusion_action == "allow" or (
            fusion_action == "ask" and approval_status == "approved"
        )

    def _existing_result_audit(
        self,
        trace_id: str,
        call_id: str,
    ) -> dict | None:
        audit_store = getattr(self.gateway, "audit", None)
        finder = getattr(audit_store, "find_event", None)
        if finder is None:
            return None
        return finder(
            trace_id=trace_id,
            call_id=call_id,
            event_type="external_execution_result",
        )

    def _recover_authorization(
        self,
        trace_id: str,
        call_id: str,
    ) -> dict | None:
        snapshot = self.transparency.snapshot(trace_id)
        metadata = snapshot.get("metadata", {})
        if (
            snapshot.get("agent_id") != self.agent_id
            or metadata.get("integration") != "opencode"
        ):
            return None
        events = [
            event
            for event in snapshot.get("events", [])
            if event.get("details", {}).get("call_id") == call_id
        ]
        plan = next(
            (event for event in events if event.get("phase") == "agent_plan"),
            None,
        )
        policy_events = [
            event for event in events if event.get("phase") == "policy_decision"
        ]
        fusion_events = [
            event for event in events if event.get("phase") == "decision_fusion"
        ]
        audit_events = [
            event
            for event in events
            if event.get("phase") == "audit_record"
            and event.get("details", {}).get("audit_type")
            != "external_execution_result"
        ]
        if plan is None or not policy_events or not audit_events:
            return None
        details = plan.get("details", {})
        raw_tool = str(details.get("raw_tool") or details.get("tool") or "")
        raw_args = details.get("raw_arguments")
        if not isinstance(raw_args, dict):
            raw_args = details.get("arguments") or {}
        execution_context = details.get("execution_context") or {}
        fingerprint = str(
            details.get("request_fingerprint")
            or metadata.get("request_fingerprint")
            or ""
        )
        authorization_fingerprint = str(
            details.get("authorization_fingerprint")
            or metadata.get("authorization_fingerprint")
            or ""
        )
        if (
            not raw_tool
            or not fingerprint
            or not authorization_fingerprint
        ):
            return None
        policy_event = policy_events[0]
        policy_details = policy_event.get("details", {})
        # New traces assign the final Allow/Ask/Deny outcome exclusively to
        # Decision Fusion.  Traces written by older releases do not contain
        # that phase, so retain a strict fallback to their policy event.
        if fusion_events:
            decision_event = fusion_events[0]
            decision_details = decision_event.get("details", {})
        else:
            if policy_details.get("evidence_only"):
                # A new-format policy evidence event without its subsequent
                # fusion event is only a partial authorization trace.
                return None
            decision_event = policy_event
            decision_details = policy_details
        decision_audit_event = next(
            (
                event for event in audit_events
                if event.get("details", {}).get("audit_type")
                in {None, "", "decision"}
            ),
            None,
        )
        if decision_audit_event is None:
            return None
        lifecycle_audit_event = audit_events[-1]
        decision_audit_details = decision_audit_event.get("details", {})
        lifecycle_audit_details = lifecycle_audit_event.get("details", {})
        audit_store = getattr(self.gateway, "audit", None)
        getter = getattr(audit_store, "get_event", None)
        decision_audit_seq = decision_audit_details.get("audit_seq")
        decision_audit_record = (
            getter(int(decision_audit_seq))
            if getter is not None and decision_audit_seq
            else None
        )
        lifecycle_audit_seq = lifecycle_audit_details.get("audit_seq")
        lifecycle_audit_record = (
            getter(int(lifecycle_audit_seq))
            if getter is not None and lifecycle_audit_seq
            else decision_audit_record
        )
        mapped_tool = str(
            policy_details.get("tool") or details.get("tool") or ""
        )
        traced_fusion_action = (
            decision_details.get("decision")
            or decision_details.get("fusion_action")
            or decision_event.get("status")
        )
        if (
            decision_audit_record is None
            or decision_audit_record.get("event_type") != "decision"
            or decision_audit_record.get("trace_id") != trace_id
            or decision_audit_record.get("call_id") != call_id
            or decision_audit_record.get("tool") != mapped_tool
            or decision_audit_record.get("decision") != traced_fusion_action
            or lifecycle_audit_record is None
            or lifecycle_audit_record.get("trace_id") != trace_id
            or lifecycle_audit_record.get("call_id") != call_id
            or lifecycle_audit_record.get("tool") != mapped_tool
        ):
            return None
        lifecycle_evidence = lifecycle_audit_record.get("result_evidence") or {}
        fusion_action = str(
            lifecycle_evidence.get("fusion_action")
            or decision_audit_record.get("decision")
            or traced_fusion_action
            or ""
        )
        approval_event = next(
            (
                event for event in reversed(events)
                if event.get("phase") == "approval_decision"
            ),
            None,
        )
        approval_status = str(
            lifecycle_evidence.get("approval_status")
            or lifecycle_audit_record.get("approval_status")
            or (approval_event or {}).get("status")
            or decision_audit_record.get("approval_status")
            or ("pending" if fusion_action == "ask" else "not_required")
        )
        explicit_execution_authorized = lifecycle_evidence.get(
            "execution_authorized"
        )
        if explicit_execution_authorized is None:
            execution_authorized = (
                lifecycle_audit_record.get("decision") == "allow"
                and approval_status not in {"pending", "rejected", "expired"}
            )
        else:
            execution_authorized = bool(explicit_execution_authorized)
        execution_attempted = lifecycle_audit_record.get(
            "execution_attempted"
        )
        execution_status = str(
            lifecycle_audit_record.get("execution_status") or "not_executed"
        )
        execution_error = str(
            lifecycle_audit_record.get("execution_error") or ""
        )
        return {
            "trace_id": trace_id,
            "call_id": call_id,
            "fingerprint": fingerprint,
            "authorization_fingerprint": authorization_fingerprint,
            "raw_tool": raw_tool,
            "raw_args": raw_args,
            "mapped_tool": mapped_tool,
            "mapped_args": copy.deepcopy(
                policy_details.get("normalized_arguments")
                or details.get("arguments")
                or {}
            ),
            "task": snapshot.get("task") or "OpenCode tool call",
            "source": details.get("source") or "agent",
            "tainted": bool(details.get("tainted", False)),
            "conversation_id": str(
                metadata.get("session_id") or trace_id
            ),
            "fusion_action": fusion_action,
            "action": fusion_action,
            "approval_status": approval_status,
            "execution_authorized": execution_authorized,
            "execution_attempted": bool(execution_attempted),
            "execution_status": execution_status,
            "execution_error": execution_error,
            "risk_level": (
                decision_details.get("risk_level")
                or policy_details.get("risk_level")
                or "low"
            ),
            "reasons": list(
                decision_details.get("reasons")
                or policy_details.get("matched_rules")
                or []
            ),
            "audit": decision_audit_record,
            "resolution_audit": (
                lifecycle_audit_record
                if lifecycle_audit_record.get("seq")
                != decision_audit_record.get("seq")
                else None
            ),
            "approval_id": next(
                (
                    event.get("details", {}).get("approval_id")
                    for event in reversed(events)
                    if event.get("details", {}).get("approval_id")
                ),
                None,
            ),
            "ct_trm": {},
        }

    def _refresh_final_authorization(
        self,
        trace_id: str,
        call_id: str,
        authorization: dict,
    ) -> dict:
        recovered = self._recover_authorization(trace_id, call_id)
        if recovered is None:
            return authorization
        if recovered.get("fingerprint") != authorization.get("fingerprint"):
            raise ValueError("Stored OpenCode authorization fingerprint changed")
        if (
            recovered.get("authorization_fingerprint")
            != authorization.get("authorization_fingerprint")
        ):
            raise ValueError("Stored OpenCode authorization context changed")
        return recovered

    def _map_tool(
        self,
        tool: str,
        args: dict,
        metadata: dict | None = None,
    ) -> tuple[str, dict]:
        metadata = metadata or {}
        normalized = tool.strip().lower()
        if normalized == "bash":
            return "run_command", {
                "cmd": self._first(args, "cmd", "command", "script"),
                "timeout": args.get("timeout", 10),
                "cwd": self._working_directory(args, metadata),
            }
        if normalized == "read":
            path = self._path(args, metadata)
            try:
                target = Path(path)
                if self.workspace is not None and not target.is_absolute():
                    target = self.workspace / target
                is_directory = bool(path) and target.is_dir()
            except OSError:
                is_directory = False
            if is_directory:
                return "list_directory", {
                    "path": path,
                    "max_depth": 1,
                    "include_hidden": True,
                }
            return "read_file", {"path": path}
        if normalized == "write":
            return "write_file", {
                "path": self._path(args, metadata),
                "content": str(args.get("content", "")),
            }
        if normalized == "edit":
            return "write_file", {
                "path": self._path(args, metadata),
                "content": str(self._first(
                    args,
                    "newString",
                    "new_string",
                    "replacement",
                    "content",
                )),
            }
        if normalized == "grep":
            return "search_files", {
                "path": self._map_path(
                    self._first(args, "path", "directory", default="."),
                    metadata,
                ),
                "query": self._first(args, "pattern", "query"),
                "glob": self._first(args, "include", "glob", default="*"),
                "regex": True,
                "max_results": args.get("max_results", args.get("limit", 50)),
            }
        if normalized == "glob":
            return "list_directory", {
                "path": self._map_path(
                    self._glob_root(str(args.get("pattern", "")), args),
                    metadata,
                ),
                "max_depth": args.get("max_depth", 5),
                "include_hidden": bool(args.get("include_hidden", False)),
            }
        if normalized == "webfetch":
            return "http_request", {
                "url": self._first(args, "url", "uri"),
                "method": str(args.get("method", "GET")).upper(),
                "body": args.get("body"),
                "headers": args.get("headers") or {},
            }
        if normalized in self.INTERNAL_TOOLS:
            return "list_directory", {
                "path": ".",
                "max_depth": 1,
                "include_hidden": False,
            }
        return normalized, args

    @classmethod
    def _normalize_external_result(
        cls,
        tool: str,
        mapped_args: dict,
        result: Any,
    ) -> dict:
        if isinstance(result, dict):
            payload = copy.deepcopy(result)
        else:
            payload = {"output": result}
        payload.pop("_guard_result_fingerprint", None)
        metadata = payload.get("metadata")
        if not isinstance(metadata, dict):
            metadata = {}
        error = cls._first(
            payload,
            "error",
            default=metadata.get("error", ""),
        )
        exit_code = cls._first(
            payload,
            "exit_code",
            "exitCode",
            "code",
            default=cls._first(
                metadata,
                "exit_code",
                "exitCode",
                "code",
                default=None,
            ),
        )
        if tool == "read_file":
            content = cls._first_result_text(
                payload,
                "content",
                "text",
                "output",
                "stdout",
                "result",
            )
            normalized = {
                "path": mapped_args.get("path", ""),
                "content": cls._compact_result_text(content),
            }
            if error:
                normalized["error"] = cls._compact_result_text(error)
            return normalized
        if tool == "run_command":
            normalized = {
                "stdout": cls._compact_result_text(
                    cls._first_result_text(payload, "stdout", "output", "text")
                ),
                "stderr": cls._compact_result_text(
                    cls._first_result_text(payload, "stderr", "error")
                ),
                "exit_code": exit_code,
            }
            if error:
                normalized["error"] = cls._compact_result_text(error)
            return normalized
        if tool == "http_request":
            status = cls._first(
                payload,
                "status",
                "status_code",
                default=cls._first(
                    metadata,
                    "status",
                    "statusCode",
                    "status_code",
                    default=None,
                ),
            )
            normalized = {
                "url": mapped_args.get("url", ""),
                "status": status,
                "headers": payload.get("headers", {}),
                "body": cls._compact_result_text(
                    cls._first_result_text(payload, "body", "text", "output", "result")
                ),
            }
            if error:
                normalized["error"] = cls._compact_result_text(error)
            return normalized
        if tool == "write_file":
            normalized = {
                "path": mapped_args.get("path", ""),
                "written": not bool(error),
                "content": cls._compact_result_text(str(mapped_args.get("content", ""))),
            }
            if error:
                normalized["error"] = cls._compact_result_text(error)
            return normalized
        if error:
            payload["error"] = cls._compact_result_text(error)
        return cls._compact_result(payload)

    @classmethod
    def _compact_result(cls, value: Any) -> Any:
        if isinstance(value, str):
            return cls._compact_result_text(value)
        if isinstance(value, dict):
            return {
                str(key): cls._compact_result(item)
                for key, item in value.items()
                if str(key) not in {"blob", "buffer", "bytes"}
            }
        if isinstance(value, list):
            return [cls._compact_result(item) for item in value[:100]]
        return value

    @staticmethod
    def _compact_result_text(value: Any, limit: int = 12000) -> str:
        text = str(value or "")
        return text if len(text) <= limit else f"{text[:limit]}..."

    @staticmethod
    def _first_result_text(payload: dict, *keys: str) -> str:
        for key in keys:
            value = payload.get(key)
            if value not in (None, ""):
                return (
                    value
                    if isinstance(value, str)
                    else str(value)
                )
        return ""

    @staticmethod
    def _first(args: dict, *names: str, default: object = "") -> object:
        for name in names:
            value = args.get(name)
            if value not in (None, ""):
                return value
        return default

    def _path(self, args: dict, metadata: dict | None = None) -> str:
        return self._map_path(self._first(
            args,
            "path",
            "filePath",
            "file_path",
            "filepath",
            "file",
        ), metadata)

    def _map_path(self, value: object, metadata: dict | None = None) -> str:
        raw = str(value or "")
        if not raw:
            return raw
        normalized = raw.replace("\\", "/")
        metadata = metadata or {}

        if normalized.startswith("~"):
            home = str(metadata.get("home") or "").strip()
            if home and normalized in {"~", "~/"}:
                normalized = home
            elif home and normalized.startswith("~/"):
                normalized = f"{home.rstrip('/')}/{normalized[2:]}"
            else:
                return raw

        if not self._looks_absolute(normalized):
            base = self._normalize_host_path(
                self._working_directory({}, metadata)
            )
            if base and self._looks_absolute(base):
                try:
                    normalized = str(
                        (Path(base).expanduser() / normalized).resolve(strict=False)
                    )
                except (OSError, RuntimeError):
                    normalized = f"{base.rstrip('/')}/{normalized.lstrip('./')}"

        direct = self._workspace_relative(normalized)
        if direct is not None:
            return direct
        return normalized

    @classmethod
    def _working_directory(cls, args: dict, metadata: dict | None = None) -> str:
        metadata = metadata or {}
        for value in (
            args.get("workdir"),
            args.get("cwd"),
            metadata.get("directory"),
            metadata.get("worktree"),
        ):
            if value not in (None, ""):
                return cls._normalize_host_path(str(value))
        return ""

    @staticmethod
    def _normalize_host_path(value: str) -> str:
        normalized = str(value or "").strip()
        wsl_path = (
            re.match(r"^/mnt/([A-Za-z])/(.*)$", normalized)
            if os.name == "nt"
            else None
        )
        if wsl_path:
            drive = wsl_path.group(1).upper()
            remainder = wsl_path.group(2).replace("/", "\\")
            return f"{drive}:\\{remainder}"
        windows_path = (
            re.match(r"^([A-Za-z]):[\\/](.*)$", normalized)
            if os.name != "nt"
            else None
        )
        if windows_path:
            drive = windows_path.group(1).lower()
            remainder = windows_path.group(2).replace("\\", "/")
            return f"/mnt/{drive}/{remainder}"
        return normalized

    @classmethod
    def _execution_context(cls, args: dict, metadata: dict) -> dict:
        context = {
            "directory": cls._working_directory(args, metadata),
            "worktree": str(metadata.get("worktree") or ""),
        }
        return {key: value for key, value in context.items() if value}

    def _workspace_relative(self, value: str) -> str | None:
        if self.workspace is None:
            return None
        try:
            path = Path(value).expanduser()
            if not path.is_absolute():
                return None
            relative = path.resolve(strict=False).relative_to(self.workspace)
        except (OSError, RuntimeError, ValueError):
            return None
        return self._clean_relative(str(relative))

    def _workspace_path_exists(self, relative: str) -> bool:
        if self.workspace is None:
            return False
        clean = self._clean_relative(relative)
        if not clean or clean == "." or clean.startswith("../"):
            return False
        return (self.workspace / clean).exists()

    @staticmethod
    def _string_relative(path: str, base: str) -> str | None:
        clean_path = path.rstrip("/")
        clean_base = base.rstrip("/")
        if not clean_path or not clean_base:
            return None
        if clean_path.lower() == clean_base.lower():
            return ""
        prefix = f"{clean_base}/"
        if clean_path.lower().startswith(prefix.lower()):
            return clean_path[len(prefix):]
        return None

    @classmethod
    def _demo_repo_suffix(cls, value: str) -> str | None:
        normalized = value.replace("\\", "/").strip("/")
        lower = normalized.lower()
        marker = "demo-repo/"
        index = lower.find(marker)
        if index >= 0:
            return cls._clean_relative(normalized[index:])
        if lower.endswith("demo-repo"):
            return "demo-repo"
        return None

    @classmethod
    def _metadata_demo_base(cls, metadata: dict) -> str | None:
        for key in ("directory", "worktree", "project"):
            suffix = cls._demo_repo_suffix(str(metadata.get(key) or ""))
            if suffix:
                return suffix
        return None

    @staticmethod
    def _looks_absolute(value: str) -> bool:
        return (
            value.startswith("/")
            or value.startswith("\\")
            or (len(value) >= 3 and value[1:3] in (":/", ":\\"))
        )

    @staticmethod
    def _clean_relative(value: str) -> str:
        return str(value).replace("\\", "/").lstrip("/")

    @staticmethod
    def _glob_root(pattern: str, args: dict) -> str:
        explicit = args.get("path") or args.get("directory")
        if explicit:
            return str(explicit)
        if not pattern:
            return "."
        parts = Path(pattern).parts
        root_parts: list[str] = []
        wildcard_seen = False
        for part in parts:
            if any(marker in part for marker in ("*", "?", "[")):
                wildcard_seen = True
                break
            root_parts.append(part)
        if not wildcard_seen:
            candidate = str(Path(pattern).parent)
            return candidate if candidate else "."
        if not root_parts:
            return "."
        return str(Path(*root_parts))
