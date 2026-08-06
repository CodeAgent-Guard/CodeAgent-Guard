from __future__ import annotations

import copy
from pathlib import Path
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
        self._completed_calls: set[tuple[str, str]] = set()

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
        with self._request_lock:
            cached = self._authorization_cache.get(cache_key)
            if cached is not None:
                return copy.deepcopy(cached)
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
            )
            if len(self._authorization_cache) >= 1000:
                self._authorization_cache.pop(next(iter(self._authorization_cache)))
            self._authorization_cache[cache_key] = copy.deepcopy(result)
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
    ) -> dict:
        mapped_tool, mapped_args = self._map_tool(tool, args, metadata)
        policy_args = {
            **mapped_args,
            "_opencode": {
                "tool": tool,
                "args": args,
                **metadata,
            },
        }
        result = self.gateway.authorize(ToolCall(
            tool=mapped_tool,
            args=policy_args,
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
        actual_call_id = call_id or f"call-{uuid.uuid4().hex[:12]}"
        cache_key = (trace_id, actual_call_id)
        with self._request_lock:
            if cache_key in self._completed_calls:
                return self.transparency.snapshot(trace_id)
            snapshot = self._record_tool_result_uncached(
                trace_id=trace_id,
                task=task,
                tool=tool,
                args=args,
                result=result,
                call_id=actual_call_id,
                metadata=metadata,
            )
            if len(self._completed_calls) >= 1000:
                self._completed_calls.clear()
            self._completed_calls.add(cache_key)
            return snapshot

    def _record_tool_result_uncached(
        self,
        *,
        trace_id: str,
        task: str,
        tool: str,
        args: dict,
        result: Any,
        call_id: str,
        metadata: dict,
    ) -> dict:
        mapped_tool, mapped_args = self._map_tool(tool, args, metadata)
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
        if output_scan and output_scan.get("finding_count"):
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
                    **output_scan,
                },
            )
        observer = getattr(policy, "observe_tool_result", None)
        if observer is not None:
            observer(
                mapped_tool,
                mapped_args,
                sanitized_result,
                "allow",
                trace_id=trace_id,
                call_id=call_id,
                conversation_id=str(metadata.get("session_id") or trace_id),
            )
        self.transparency.emit(
            trace_id,
            phase="tool_result",
            actor=self.agent_id,
            label="OpenCode 工具执行结果",
            status="success",
            title=f"{mapped_tool} 返回结果",
            summary=TransparencyService.result_summary(sanitized_result),
            details={
                "call_id": call_id,
                "tool": mapped_tool,
                "external_tool": tool,
                "result": sanitized_result,
                "execution_delegated": True,
            },
        )
        return self.transparency.snapshot(trace_id)

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
            }
        if normalized == "read":
            return "read_file", {"path": self._path(args, metadata)}
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
            payload = result
        else:
            payload = {"output": result}
        if tool == "read_file":
            content = cls._first_result_text(
                payload,
                "content",
                "text",
                "output",
                "stdout",
                "result",
            )
            return {
                "path": mapped_args.get("path", ""),
                "content": cls._compact_result_text(content),
            }
        if tool == "run_command":
            return {
                "stdout": cls._compact_result_text(
                    cls._first_result_text(payload, "stdout", "output", "text")
                ),
                "stderr": cls._compact_result_text(
                    cls._first_result_text(payload, "stderr", "error")
                ),
                "exit_code": payload.get("exit_code", payload.get("code", 0)),
            }
        if tool == "http_request":
            return {
                "url": mapped_args.get("url", ""),
                "status": payload.get("status", payload.get("status_code", 200)),
                "headers": payload.get("headers", {}),
                "body": cls._compact_result_text(
                    cls._first_result_text(payload, "body", "text", "output", "result")
                ),
            }
        if tool == "write_file":
            return {
                "path": mapped_args.get("path", ""),
                "written": True,
                "content": cls._compact_result_text(str(mapped_args.get("content", ""))),
            }
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
        if normalized.startswith("~"):
            return raw

        direct = self._workspace_relative(raw)
        if direct is not None:
            return direct

        suffix = self._demo_repo_suffix(normalized)
        if suffix and self._workspace_path_exists(suffix):
            return suffix

        metadata = metadata or {}
        for key in ("directory", "worktree", "project"):
            base = str(metadata.get(key) or "")
            if not base:
                continue
            base_normalized = base.replace("\\", "/").rstrip("/")
            relative = self._string_relative(normalized, base_normalized)
            if relative is None:
                continue
            if relative and self._workspace_path_exists(relative):
                return relative
            base_suffix = self._demo_repo_suffix(base_normalized)
            if base_suffix and relative:
                candidate = f"{base_suffix.rstrip('/')}/{relative}"
                if self._workspace_path_exists(candidate):
                    return candidate

        relative_base = self._metadata_demo_base(metadata)
        if relative_base and not self._looks_absolute(normalized):
            candidate = f"{relative_base.rstrip('/')}/{normalized.lstrip('./')}"
            if self._workspace_path_exists(candidate):
                return candidate

        return raw

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
