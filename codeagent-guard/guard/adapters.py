from __future__ import annotations

from pathlib import Path
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
        mapped_tool, mapped_args = self._map_tool(tool, args)
        policy_args = {
            **mapped_args,
            "_opencode": {
                "tool": tool,
                "args": args,
                **(metadata or {}),
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
                (metadata or {}).get("session_id") or trace_id
            ),
            call_id=call_id or f"call-{uuid.uuid4().hex[:12]}",
        ))
        result["opencode"] = {
            "tool": tool,
            "policy_tool": mapped_tool,
            "policy_args": mapped_args,
        }
        return result

    def _map_tool(self, tool: str, args: dict) -> tuple[str, dict]:
        normalized = tool.strip().lower()
        if normalized == "bash":
            return "run_command", {
                "cmd": self._first(args, "cmd", "command", "script"),
                "timeout": args.get("timeout", 10),
            }
        if normalized == "read":
            return "read_file", {"path": self._path(args)}
        if normalized == "write":
            return "write_file", {
                "path": self._path(args),
                "content": str(args.get("content", "")),
            }
        if normalized == "edit":
            return "write_file", {
                "path": self._path(args),
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
                "path": self._first(args, "path", "directory", default="."),
                "query": self._first(args, "pattern", "query"),
                "glob": self._first(args, "include", "glob", default="*"),
                "regex": True,
                "max_results": args.get("max_results", args.get("limit", 50)),
            }
        if normalized == "glob":
            return "list_directory", {
                "path": self._glob_root(str(args.get("pattern", "")), args),
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

    @staticmethod
    def _first(args: dict, *names: str, default: object = "") -> object:
        for name in names:
            value = args.get(name)
            if value not in (None, ""):
                return value
        return default

    @classmethod
    def _path(cls, args: dict) -> str:
        return str(cls._first(
            args,
            "path",
            "filePath",
            "file_path",
            "filepath",
            "file",
        ))

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
