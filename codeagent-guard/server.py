#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import mimetypes
import os
import subprocess
import traceback
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from guard.agent import Agent
from guard.audit import AuditStore
from guard.catalog import TOOL_SCHEMAS
from guard.evaluation import EvaluationService
from guard.executors import ToolExecutorRegistry
from guard.policy import PolicyEngine
from guard.providers import LLMProvider
from guard.tools import ToolProxy
from guard.transparency import TransparencyService
from guard.trusted_workspaces import TrustedWorkspaceStore


ROOT = Path(__file__).resolve().parent
FRONTEND = ROOT / "frontend"
WORKSPACE = Path(os.getenv("GUARD_WORKSPACE", ROOT / "workspace")).resolve()
DATA = Path(os.getenv("GUARD_DATA_DIR", ROOT / "data")).resolve()


def _env_paths(name: str) -> tuple[Path, ...]:
    return tuple(
        Path(item.strip())
        for item in os.getenv(name, "").split(",")
        if item.strip()
    )


OPEN_DIRECTORY_ROOTS = _env_paths("GUARD_OPEN_DIRECTORY_ROOTS")
EXTERNAL_WRITE_ROOTS = _env_paths("GUARD_EXTERNAL_WRITE_ROOTS")
BUILD = "2026.06.21-trusted-workspaces-v4"
WORKSPACE.mkdir(parents=True, exist_ok=True)
DATA.mkdir(parents=True, exist_ok=True)

trusted_workspaces = TrustedWorkspaceStore(DATA / "trusted_workspaces.json")
audit = AuditStore(DATA / "audit.db")
transparency = TransparencyService(db_path=DATA / "traces.db")
policy = PolicyEngine(
    WORKSPACE,
    internal_domains=set(filter(None, os.getenv(
        "GUARD_INTERNAL_DOMAINS", "codeguard.local,localhost"
    ).split(","))),
    open_directory_roots=OPEN_DIRECTORY_ROOTS,
    external_write_roots=EXTERNAL_WRITE_ROOTS,
    trusted_workspace_roots=trusted_workspaces.roots(),
)
executor = ToolExecutorRegistry(
    WORKSPACE,
    DATA / "outbox",
    open_directory_roots=policy.open_directory_roots,
    external_write_roots=policy.external_write_roots,
    trusted_workspace_roots=policy.trusted_workspace_roots,
)
proxy = ToolProxy(
    WORKSPACE,
    audit,
    policy,
    DATA / "outbox",
    executor=executor,
    transparency=transparency,
)
provider = LLMProvider()
agent = Agent(proxy, provider, transparency, DATA / "agent_contexts.json")
evaluation = EvaluationService(policy, DATA / "evaluation", audit)


def _trusted_workspace_status() -> dict:
    return {
        "workspace": str(WORKSPACE),
        "roots": [
            {
                "path": str(path),
                "exists": path.exists(),
                "active": path.exists() and path.is_dir(),
            }
            for path in policy.trusted_workspace_roots
        ],
    }


def _normalized_trusted_workspace(raw_path: str, *, must_exist: bool) -> Path:
    if not raw_path.strip():
        raise ValueError("请选择或输入可信工作环境目录")
    normalized = policy._normalize_host_path(raw_path)
    if not normalized.is_absolute():
        raise ValueError("可信工作环境必须使用绝对路径")
    normalized = normalized.resolve(strict=False)
    if normalized == Path(normalized.anchor):
        raise ValueError("不能将整个磁盘根目录设为可信工作环境")
    if must_exist and (not normalized.exists() or not normalized.is_dir()):
        raise ValueError(f"目录不存在: {normalized}")
    return normalized


def _apply_trusted_workspaces() -> None:
    roots = trusted_workspaces.roots()
    policy.set_trusted_workspace_roots(roots)
    executor.set_trusted_workspace_roots(policy.trusted_workspace_roots)


def _remove_trusted_workspace(normalized: Path) -> bool:
    for stored in trusted_workspaces.roots():
        candidate = policy._normalize_host_path(str(stored)).resolve(strict=False)
        if candidate == normalized:
            return trusted_workspaces.remove(stored)
    return False


def _select_windows_directory() -> str:
    if os.name != "nt":
        raise ValueError("当前服务不是 Windows 进程，请直接输入绝对目录")
    script = """
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
Add-Type -AssemblyName System.Windows.Forms
$dialog = New-Object System.Windows.Forms.FolderBrowserDialog
$dialog.Description = '选择 CodeAgent Guard 可信工作环境'
$dialog.ShowNewFolderButton = $false
if ($dialog.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
    [Console]::Write($dialog.SelectedPath)
}
"""
    completed = subprocess.run(
        ["powershell.exe", "-NoProfile", "-STA", "-Command", script],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=180,
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
    )
    if completed.returncode != 0:
        raise RuntimeError(completed.stderr.strip() or "目录选择器启动失败")
    return completed.stdout.strip()


class Handler(BaseHTTPRequestHandler):
    server_version = "CodeAgentGuard/1.0"

    def log_message(self, fmt: str, *args) -> None:
        print(f"[http] {self.address_string()} {fmt % args}")

    def _json(self, data: object, status: int = 200) -> None:
        payload = json.dumps(data, ensure_ascii=False).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(payload)

    def _body(self) -> dict:
        length = int(self.headers.get("Content-Length", "0"))
        if length > 2_000_000:
            raise ValueError("请求体超过 2 MB")
        raw = self.rfile.read(length)
        return json.loads(raw or b"{}")

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        try:
            if parsed.path == "/api/health":
                self._json({
                    "ok": True,
                    "service": "CodeAgent Guard",
                    "build": BUILD,
                    "workspace": str(WORKSPACE),
                    "open_directory_roots": [
                        str(path) for path in policy.open_directory_roots
                    ],
                    "external_write_roots": [
                        str(path) for path in policy.external_write_roots
                    ],
                    "trusted_workspace_roots": [
                        str(path) for path in policy.trusted_workspace_roots
                    ],
                    "llm": agent.status(),
                })
            elif parsed.path == "/api/trusted-workspaces":
                self._json(_trusted_workspace_status())
            elif parsed.path == "/api/overview":
                self._json({**audit.overview(), "chain": audit.verify(), "llm": agent.status()})
            elif parsed.path == "/api/audit":
                query = parse_qs(parsed.query)
                self._json({
                    "events": audit.list_events(
                        int(query.get("limit", ["100"])[0]),
                        query.get("trace_id", [None])[0],
                    )
                })
            elif parsed.path == "/api/audit/verify":
                self._json(audit.verify())
            elif parsed.path == "/api/audit/integrity-experiment":
                self._json(audit.integrity_experiment())
            elif parsed.path == "/api/policies":
                self._json({"policies": policy.describe()})
            elif parsed.path == "/api/tools":
                self._json({
                    "tools": [
                        {
                            "name": item["function"]["name"],
                            "description": item["function"]["description"],
                            "parameters": item["function"]["parameters"],
                        }
                        for item in TOOL_SCHEMAS
                    ]
                })
            elif parsed.path == "/api/llm/providers":
                self._json({
                    "providers": provider.presets(),
                    "current": provider.status(),
                })
            elif parsed.path == "/api/evaluation":
                self._json(evaluation.last_result())
            elif parsed.path == "/api/approvals":
                self._json({"approvals": proxy.list_approvals()})
            elif parsed.path == "/api/agent/conversations":
                query = parse_qs(parsed.query)
                self._json(agent.list_conversations(
                    int(query.get("limit", ["50"])[0])
                ))
            elif parsed.path.startswith("/api/agent/conversations/"):
                conversation_id = parsed.path.rsplit("/", 1)[1]
                self._json(agent.conversation_snapshot(conversation_id))
            elif parsed.path == "/api/traces":
                query = parse_qs(parsed.query)
                self._json({
                    "traces": transparency.list_traces(
                        int(query.get("limit", ["50"])[0]),
                        agent_id=query.get("agent_id", [None])[0],
                    )
                })
            elif parsed.path.startswith("/api/traces/"):
                trace_id = parsed.path.rsplit("/", 1)[1]
                self._json(transparency.snapshot(trace_id))
            else:
                self._static(parsed.path)
        except Exception as exc:
            self._json({"error": str(exc)}, 400)

    def do_POST(self) -> None:
        parsed = urlparse(self.path)
        try:
            body = self._body()
            if parsed.path == "/api/tools/execute":
                if not isinstance(body.get("allowed_tools"), list):
                    raise ValueError("allowed_tools 必须由当前任务显式声明")
                result = proxy.execute(
                    str(body.get("tool", "")),
                    body.get("args") or {},
                    trace_id=body.get("trace_id"),
                    task=str(body.get("task", "手动工具调用")),
                    source=str(body.get("source", "user")),
                    tainted=bool(body.get("tainted", False)),
                    agent_id=str(body.get("agent_id", "external-agent")),
                    call_id=body.get("call_id"),
                    allowed_tools=body.get("allowed_tools"),
                )
                self._json(result)
            elif parsed.path == "/api/agent/run":
                if not isinstance(body.get("allowed_tools"), list):
                    raise ValueError("当前任务必须显式选择 allowed_tools")
                self._json(agent.run(
                    str(body.get("prompt", "")),
                    int(body.get("max_steps", 8)),
                    body.get("allowed_tools"),
                    conversation_id=body.get("conversation_id"),
                    context_max_chars=int(body.get("context_max_chars", 20000)),
                    new_context=bool(body.get("new_context", False)),
                ))
            elif parsed.path == "/api/approvals/resolve":
                self._json(agent.resolve_approval(
                    str(body.get("approval_id", "")),
                    approve=bool(body.get("approve", False)),
                    actor=str(body.get("actor", "user")),
                ))
            elif parsed.path == "/api/llm/config":
                self._json(agent.configure(body))
            elif parsed.path == "/api/trusted-workspaces/select":
                self._json({"path": _select_windows_directory()})
            elif parsed.path == "/api/trusted-workspaces":
                action = str(body.get("action", "add")).strip().lower()
                normalized = _normalized_trusted_workspace(
                    str(body.get("path", "")),
                    must_exist=action == "add",
                )
                if action == "add":
                    trusted_workspaces.add(normalized)
                elif action == "remove":
                    if not _remove_trusted_workspace(normalized):
                        raise ValueError("该目录不在可信工作环境列表中")
                else:
                    raise ValueError("action 必须是 add 或 remove")
                _apply_trusted_workspaces()
                self._json(_trusted_workspace_status())
            elif parsed.path == "/api/llm/test":
                self._json(agent.test_connection())
            elif parsed.path == "/api/evaluation/generate":
                self._json(evaluation.generate())
            elif parsed.path == "/api/evaluation/run":
                self._json(evaluation.run())
            elif parsed.path == "/api/traces/start":
                trace_id = str(body.get("trace_id") or "")
                if not trace_id:
                    raise ValueError("trace_id 不能为空")
                transparency.begin(
                    trace_id,
                    task=str(body.get("task", "外部 Agent 任务")),
                    agent_id=str(body.get("agent_id", "external-agent")),
                    metadata=body.get("metadata") or {},
                )
                self._json(transparency.snapshot(trace_id))
            elif parsed.path == "/api/traces/event":
                trace_id = str(body.get("trace_id") or "")
                if not trace_id:
                    raise ValueError("trace_id 不能为空")
                event = transparency.emit(
                    trace_id,
                    phase=str(body.get("phase", "agent_event")),
                    actor=str(body.get("actor", body.get("agent_id", "external-agent"))),
                    label=str(body.get("label", "外部 Agent 事件")),
                    status=str(body.get("status", "reported")),
                    title=str(body.get("title", "Agent 状态更新")),
                    summary=str(body.get("summary", "")),
                    details=body.get("details") or {},
                )
                self._json({"event": event, "trace": transparency.snapshot(trace_id)})
            elif parsed.path.startswith("/api/demo/"):
                scenario = parsed.path.rsplit("/", 1)[1]
                self._json(agent.demo(scenario))
            elif parsed.path == "/api/audit/reset":
                audit.reset()
                self._json({"ok": True})
            else:
                self._json({"error": "API endpoint not found"}, 404)
        except ValueError as exc:
            self._json({"error": str(exc)}, 400)
        except Exception as exc:
            traceback.print_exc()
            self._json({"error": str(exc)}, 500)

    def _static(self, request_path: str) -> None:
        relative = "index.html" if request_path in {"", "/"} else request_path.lstrip("/")
        target = (FRONTEND / relative).resolve()
        try:
            target.relative_to(FRONTEND)
        except ValueError:
            self.send_error(HTTPStatus.FORBIDDEN)
            return
        if not target.exists() or not target.is_file():
            if "." not in Path(relative).name:
                target = FRONTEND / "index.html"
            else:
                self.send_error(HTTPStatus.NOT_FOUND)
                return
        content = target.read_bytes()
        mime = mimetypes.guess_type(target.name)[0] or "application/octet-stream"
        self.send_response(200)
        self.send_header("Content-Type", f"{mime}; charset=utf-8" if mime.startswith("text/") else mime)
        self.send_header("Content-Length", str(len(content)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(content)


def main() -> None:
    parser = argparse.ArgumentParser(description="CodeAgent Guard")
    parser.add_argument("--host", default=os.getenv("HOST", "0.0.0.0"))
    parser.add_argument("--port", type=int, default=int(os.getenv("PORT", "8000")))
    args = parser.parse_args()
    server = ThreadingHTTPServer((args.host, args.port), Handler)
    print(f"CodeAgent Guard: http://localhost:{args.port}")
    print(f"Workspace: {WORKSPACE}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
