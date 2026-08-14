#!/usr/bin/env python3
from __future__ import annotations

import argparse
import atexit
import json
import mimetypes
import os
import socket
import subprocess
import threading
import time
import traceback
import uuid
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from guard.adapters import OpenCodeToolProxyAdapter
from guard.agent import Agent
from guard.audit import AuditStore
from guard.catalog import TOOL_SCHEMAS
from guard.ct_trm_evaluation import CTTRMEvaluationService
from guard.evaluation import EvaluationService
from guard.evaluation_ct_trm import (
    MODES as AGENT_TOOL_BENCH_MODES,
    load_cases as load_agent_tool_bench_cases,
    run_mode as run_agent_tool_bench_mode,
    write_reports as write_agent_tool_bench_reports,
)
from guard.executors import ToolExecutorRegistry
from guard.policy import PolicyEngine
from guard.providers import LLMProvider
from guard.state import RuntimeStateStore
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
BUILD = "2026.08.14-human-evidence-v1"
WORKSPACE.mkdir(parents=True, exist_ok=True)
DATA.mkdir(parents=True, exist_ok=True)

_INSTANCE_LOCK_TOKEN = ""
_INSTANCE_LOCK_STOP = threading.Event()
_INSTANCE_LOCK_PATH = DATA / "server.instance.lock"
_INSTANCE_ARBITER_STALE_AFTER = 10.0
_INSTANCE_ARBITER_WAIT_TIMEOUT = 12.0
_INSTANCE_ARBITER_POLL_INTERVAL = 0.05
_LOCK_PORT = int(os.getenv("PORT", "8000"))
for index, argument in enumerate(os.sys.argv[:-1]):
    if argument == "--port":
        try:
            _LOCK_PORT = int(os.sys.argv[index + 1])
        except ValueError:
            pass


def _release_instance_lock(lock_path: Path) -> None:
    try:
        arbiter_path, arbiter_marker, arbiter_token = _acquire_instance_arbiter(
            lock_path
        )
    except (OSError, RuntimeError):
        return
    try:
        if lock_path.read_text(encoding="utf-8").strip() == _INSTANCE_LOCK_TOKEN:
            lock_path.unlink(missing_ok=True)
    except OSError:
        pass
    finally:
        _release_instance_arbiter(arbiter_path, arbiter_marker, arbiter_token)


def _port_is_reachable(port: int, host: str = "127.0.0.1") -> bool:
    try:
        with socket.create_connection((host, port), timeout=0.5):
            return True
    except OSError:
        return False


def _instance_arbiter_path(lock_path: Path) -> Path:
    return lock_path.with_name(f"{lock_path.name}.arbiter")


def _remove_stale_instance_arbiter(arbiter_path: Path) -> bool:
    """Remove only the exact, expired owner markers observed in an arbiter."""
    try:
        arbiter_stat = arbiter_path.stat()
    except FileNotFoundError:
        return True

    if not arbiter_path.is_dir():
        if time.time() - arbiter_stat.st_mtime < _INSTANCE_ARBITER_STALE_AFTER:
            return False
        try:
            arbiter_path.unlink()
            return True
        except (FileNotFoundError, IsADirectoryError):
            return not arbiter_path.exists()
        except OSError:
            return False

    try:
        entries = tuple(arbiter_path.iterdir())
        newest_mtime = max(
            (arbiter_stat.st_mtime, *(entry.stat().st_mtime for entry in entries)),
        )
    except FileNotFoundError:
        return True
    except OSError:
        return False
    if time.time() - newest_mtime < _INSTANCE_ARBITER_STALE_AFTER:
        return False
    if any(not entry.is_file() or not entry.name.startswith("owner-") for entry in entries):
        return False

    # Marker names contain a UUID. A concurrent recovery can therefore remove
    # only markers from the stale directory it observed, never a new owner's.
    for entry in entries:
        try:
            entry.unlink()
        except FileNotFoundError:
            pass
        except OSError:
            return False
    try:
        arbiter_path.rmdir()
        return True
    except FileNotFoundError:
        return True
    except OSError:
        return False


def _acquire_instance_arbiter(lock_path: Path) -> tuple[Path, str, str]:
    """Acquire a short-lived, cross-process arbiter for the main lock."""
    arbiter_path = _instance_arbiter_path(lock_path)
    token = f"{os.getpid()}-{uuid.uuid4().hex}"
    marker_name = f"owner-{token}"
    candidate_path = arbiter_path.with_name(
        f".{arbiter_path.name}.{token}.candidate"
    )
    candidate_path.mkdir()
    marker_path = candidate_path / marker_name
    with marker_path.open("x", encoding="utf-8") as handle:
        handle.write(token)
        handle.flush()
        os.fsync(handle.fileno())

    deadline = time.monotonic() + _INSTANCE_ARBITER_WAIT_TIMEOUT
    try:
        while True:
            try:
                candidate_path.rename(arbiter_path)
                return arbiter_path, marker_name, token
            except OSError as exc:
                if not arbiter_path.exists():
                    if time.monotonic() >= deadline:
                        raise RuntimeError(
                            "Unable to acquire the CodeAgent Guard instance lock arbiter"
                        ) from exc
                    time.sleep(_INSTANCE_ARBITER_POLL_INTERVAL)
                    continue
            _remove_stale_instance_arbiter(arbiter_path)
            if time.monotonic() >= deadline:
                raise RuntimeError(
                    "Unable to acquire the CodeAgent Guard instance lock arbiter"
                )
            time.sleep(_INSTANCE_ARBITER_POLL_INTERVAL)
    finally:
        try:
            marker_path.unlink(missing_ok=True)
            candidate_path.rmdir()
        except OSError:
            pass


def _release_instance_arbiter(
    arbiter_path: Path,
    marker_name: str,
    token: str,
) -> None:
    marker_path = arbiter_path / marker_name
    try:
        if marker_path.read_text(encoding="utf-8").strip() != token:
            return
        marker_path.unlink()
        arbiter_path.rmdir()
    except OSError:
        pass


def _acquire_instance_lock(
    lock_path: Path,
    stale_after: float = 15.0,
    *,
    port: int | None = None,
) -> None:
    """Prevent Windows and WSL servers from sharing the same SQLite files."""
    global _INSTANCE_LOCK_TOKEN
    token = f"{os.getpid()}:{uuid.uuid4().hex}"
    arbiter_path, arbiter_marker, arbiter_token = _acquire_instance_arbiter(lock_path)
    try:
        for _ in range(3):
            try:
                descriptor = os.open(
                    lock_path,
                    os.O_CREAT | os.O_EXCL | os.O_WRONLY,
                )
            except FileExistsError:
                try:
                    age = time.time() - lock_path.stat().st_mtime
                except FileNotFoundError:
                    continue
                port_reachable = bool(port and _port_is_reachable(port))
                if port_reachable or age < stale_after:
                    location = (
                        f"，且 127.0.0.1:{port} 可连接"
                        if port_reachable
                        else "；端口在当前系统不可见，可能由 Windows/WSL 另一侧实例持有"
                    )
                    raise RuntimeError(
                        "CodeAgent Guard is already running for this data directory"
                        f"{location}。请打开 http://localhost:{port or 8000}/api/health "
                        "确认实例；不要结束 systemd-resolve 等无关系统进程。"
                    )
                try:
                    lock_path.unlink()
                except FileNotFoundError:
                    pass
                continue
            with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
                handle.write(token)
                handle.flush()
                os.fsync(handle.fileno())
            _INSTANCE_LOCK_TOKEN = token
            break
        else:
            raise RuntimeError("Unable to acquire the CodeAgent Guard instance lock")
    finally:
        _release_instance_arbiter(arbiter_path, arbiter_marker, arbiter_token)

    def heartbeat() -> None:
        while not _INSTANCE_LOCK_STOP.wait(2.0):
            try:
                if lock_path.read_text(encoding="utf-8").strip() != token:
                    return
                os.utime(lock_path, None)
            except OSError:
                return

    threading.Thread(target=heartbeat, daemon=True).start()
    atexit.register(_release_instance_lock, lock_path)


if __name__ == "__main__":
    try:
        _acquire_instance_lock(
            _INSTANCE_LOCK_PATH,
            port=_LOCK_PORT,
        )
    except RuntimeError as exc:
        raise SystemExit(str(exc)) from None


trusted_workspaces = TrustedWorkspaceStore(DATA / "trusted_workspaces.json")
runtime_state = RuntimeStateStore(DATA / "state.db")
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
    state_store=runtime_state,
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
    state_store=runtime_state,
)
provider = LLMProvider()
agent = Agent(proxy, provider, transparency, DATA / "agent_contexts.json")
opencode_adapter = OpenCodeToolProxyAdapter(proxy, transparency)
opencode_adapter.reconcile_external_results()
evaluation = EvaluationService(policy, DATA / "evaluation", audit)
ct_trm_evaluation = CTTRMEvaluationService(
    ROOT / "benchmarks" / "agent_tool_bench" / "ct_trm_cases.yaml",
    ROOT / "reports",
)
AGENT_TOOL_BENCH_CASES = (
    ROOT / "benchmarks" / "agent_tool_bench" / "cases" / "ct_trm_500.yaml"
)
AGENT_TOOL_BENCH_REPORTS = ROOT / "reports" / "ct_trm"
agent_tool_bench_lock = threading.Lock()


def _run_agent_tool_bench() -> dict:
    if not agent_tool_bench_lock.acquire(blocking=False):
        raise ValueError("AgentToolBench 评测正在运行")
    try:
        cases = load_agent_tool_bench_cases(AGENT_TOOL_BENCH_CASES)
        results = {
            mode: run_agent_tool_bench_mode(mode, cases)
            for mode in AGENT_TOOL_BENCH_MODES
        }
        return write_agent_tool_bench_reports(
            AGENT_TOOL_BENCH_CASES,
            AGENT_TOOL_BENCH_REPORTS,
            results,
        )
    finally:
        agent_tool_bench_lock.release()


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
            elif parsed.path == "/api/evaluation/ct-trm":
                self._json(ct_trm_evaluation.last_result())
            elif parsed.path == "/api/evaluation/agent-tool-bench":
                summary_path = ROOT / "reports" / "ct_trm" / "ablation_summary.json"
                self._json(
                    json.loads(summary_path.read_text(encoding="utf-8"))
                    if summary_path.exists()
                    else {"available": False}
                )
            elif parsed.path == "/api/approvals":
                self._json({"approvals": proxy.list_approvals()})
            elif parsed.path.startswith("/api/approvals/"):
                approval_id = parsed.path.rsplit("/", 1)[1]
                approval = proxy.get_approval_status(approval_id)
                if approval is None:
                    self._json(
                        {"error": "approval not found"},
                        HTTPStatus.NOT_FOUND,
                    )
                else:
                    self._json(approval)
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
                trace_id = str(
                    body.get("trace_id") or f"trace-{uuid.uuid4().hex[:12]}"
                )
                source_content = body.get("source_content")
                if source_content:
                    policy.register_context(
                        str(source_content),
                        str(body.get("source", "user")),
                        str(
                            body.get("source_origin")
                            or body.get("source")
                            or "source_content"
                        ),
                        trace_id=trace_id,
                        tool_call_id=body.get("call_id"),
                        conversation_id=body.get("conversation_id"),
                        metadata={"one_shot_source": True},
                    )
                result = proxy.execute(
                    str(body.get("tool", "")),
                    body.get("args") or {},
                    trace_id=trace_id,
                    task=str(body.get("task", "手动工具调用")),
                    source=str(body.get("source", "user")),
                    tainted=bool(body.get("tainted", False)),
                    agent_id=str(body.get("agent_id", "external-agent")),
                    call_id=body.get("call_id"),
                    allowed_tools=body.get("allowed_tools"),
                    conversation_id=body.get("conversation_id"),
                )
                self._json(result)
            elif parsed.path == "/api/opencode/authorize-tool":
                tool = str(body.get("tool", "")).strip()
                if not tool:
                    raise ValueError("tool 不能为空")
                args = body.get("args") or {}
                if not isinstance(args, dict):
                    raise ValueError("args 必须是对象")
                allowed_tools = body.get("allowed_tools")
                if allowed_tools is not None and not isinstance(allowed_tools, list):
                    raise ValueError("allowed_tools 必须是数组")
                result = opencode_adapter.authorize_tool(
                    trace_id=str(
                        body.get("trace_id")
                        or f"opencode-{body.get('session_id', 'session')}"
                    ),
                    task=str(body.get("task", "OpenCode 工具调用")),
                    tool=tool,
                    args=args,
                    source=str(body.get("source", "agent")),
                    tainted=bool(body.get("tainted", False)),
                    call_id=body.get("call_id"),
                    allowed_tools=allowed_tools,
                    metadata={
                        **(body.get("metadata") or {}),
                        "session_id": body.get("session_id"),
                    },
                )
                self._json(result)
            elif parsed.path == "/api/opencode/tool-result":
                tool = str(body.get("tool", "")).strip()
                if not tool:
                    raise ValueError("tool must not be empty")
                args = body.get("args") or {}
                if not isinstance(args, dict):
                    raise ValueError("args must be an object")
                result = opencode_adapter.record_tool_result(
                    trace_id=str(
                        body.get("trace_id")
                        or f"opencode-{body.get('session_id', 'session')}"
                    ),
                    task=str(body.get("task", "OpenCode tool call")),
                    tool=tool,
                    args=args,
                    result=body.get("result"),
                    call_id=body.get("call_id"),
                    metadata={
                        **(body.get("metadata") or {}),
                        "session_id": body.get("session_id"),
                    },
                )
                self._json(result)
            elif parsed.path == "/api/agent/run":
                if (
                    body.get("allowed_tools") is not None
                    and not isinstance(body.get("allowed_tools"), list)
                ):
                    raise ValueError("allowed_tools 必须是数组或 null")
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
            elif parsed.path == "/api/evaluation/ct-trm/run":
                self._json(ct_trm_evaluation.run())
            elif parsed.path == "/api/evaluation/agent-tool-bench/run":
                self._json(_run_agent_tool_bench())
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
                policy.register_context(
                    str(body.get("task", "外部 Agent 任务")),
                    "user_task",
                    "external_agent_task",
                    trace_id=trace_id,
                    conversation_id=body.get("conversation_id"),
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
    try:
        server = ThreadingHTTPServer((args.host, args.port), Handler)
    except OSError as exc:
        _release_instance_lock(_INSTANCE_LOCK_PATH)
        raise SystemExit(
            f"CodeAgent Guard 无法监听 {args.host}:{args.port}: {exc}"
        ) from None
    print(f"CodeAgent Guard: http://localhost:{args.port}")
    print(f"Workspace: {WORKSPACE}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
        _release_instance_lock(_INSTANCE_LOCK_PATH)


if __name__ == "__main__":
    main()
