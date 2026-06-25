from __future__ import annotations

import json
import sqlite3
import tempfile
import time
from pathlib import Path

from guard.adapters import OpenCodeToolProxyAdapter
from guard.audit import AuditStore
from guard.contracts import ToolCall
from guard.evaluation_ct_trm import (
    _apply_setup,
    _expand,
    _final_call,
    _prepare_workspace,
)
from guard.policy import PolicyEngine
from guard.state import RuntimeStateStore
from guard.tools import ToolProxy
from guard.transparency import TransparencyService


ROOT = Path(__file__).resolve().parents[3]
DEFAULT_CASES = ROOT / "benchmarks" / "agent_tool_bench" / "cases" / "ct_trm_500.yaml"
DEFAULT_SCENARIOS = Path(__file__).with_name("scenarios.yaml")


class MockExecutor:
    def __init__(self) -> None:
        self.calls: list[dict] = []

    def execute(self, tool: str, args: dict) -> dict:
        self.calls.append({"tool": tool, "args": args})
        return {
            "mocked": True,
            "tool": tool,
            "result": "BENCHMARK_MARKER",
        }


def load_inputs(
    cases_path: Path = DEFAULT_CASES,
    scenarios_path: Path = DEFAULT_SCENARIOS,
) -> tuple[dict[str, dict], list[dict]]:
    cases = json.loads(cases_path.read_text(encoding="utf-8"))
    scenarios = json.loads(scenarios_path.read_text(encoding="utf-8"))
    return {case["id"]: case for case in cases}, scenarios


def environment(root: Path) -> tuple[Path, dict[str, str]]:
    workspace = root / "workspace"
    fake_home = root / "fake_home"
    fake_root = root / "fake_root"
    mock_server = root / "mock_server"
    for path in (workspace, fake_home, fake_root, mock_server):
        path.mkdir(parents=True, exist_ok=True)
    _prepare_workspace(workspace)
    return workspace, {
        "${WORKSPACE}": str(workspace),
        "${FAKE_HOME}": str(fake_home),
        "${FAKE_ROOT}": str(fake_root),
        "${MOCK_SERVER}": str(mock_server),
    }


def guarded_components(
    root: Path,
    workspace: Path,
    *,
    mode: str,
    approval_ttl_seconds: int = 900,
) -> tuple[
    PolicyEngine,
    ToolProxy,
    MockExecutor,
    TransparencyService,
    RuntimeStateStore,
]:
    state = RuntimeStateStore(root / "state.db")
    policy = PolicyEngine(workspace, state_store=state)
    policy.default_ct_trm_mode = mode
    traces = TransparencyService(db_path=root / "traces.db")
    executor = MockExecutor()
    proxy = ToolProxy(
        workspace,
        AuditStore(root / "audit.db"),
        policy,
        root / "outbox",
        executor=executor,
        transparency=traces,
        state_store=state,
        approval_ttl_seconds=approval_ttl_seconds,
    )
    return policy, proxy, executor, traces, state


def invoke_builtin(
    proxy: ToolProxy,
    policy: PolicyEngine,
    case: dict,
    trace_id: str,
    *,
    mode: str,
) -> dict:
    call = _final_call(case)
    original = policy.evaluate

    def evaluate_with_mode(tool: str, args: dict, **kwargs):
        kwargs["ct_trm_mode"] = mode
        return original(tool, args, **kwargs)

    policy.evaluate = evaluate_with_mode  # type: ignore[method-assign]
    return proxy.invoke(ToolCall(
        tool=call["tool"],
        args=call.get("args") or {},
        trace_id=trace_id,
        task=case["user_task"],
        source=str(call.get("source", "agent")),
        tainted=bool(call.get("tainted", False)),
        agent_id="builtin-agent-validation",
        allowed_tools=(call["tool"],),
        call_id=f"call-{trace_id}",
    ))


def invoke_opencode(
    proxy: ToolProxy,
    traces: TransparencyService,
    case: dict,
    trace_id: str,
) -> dict:
    call = _final_call(case)
    adapter = OpenCodeToolProxyAdapter(proxy, traces)
    reverse = {
        "read_file": "read",
        "write_file": "write",
        "run_command": "bash",
        "http_request": "webfetch",
        "search_files": "grep",
        "list_directory": "glob",
    }
    tool = reverse.get(call["tool"], call["tool"])
    return adapter.authorize_tool(
        trace_id=trace_id,
        task=case["user_task"],
        tool=tool,
        args=call.get("args") or {},
        call_id=f"call-{trace_id}",
        allowed_tools=[call["tool"]],
        metadata={"session_id": trace_id},
    )


def resolve_directive(
    proxy: ToolProxy,
    state: RuntimeStateStore,
    outcome: dict,
    directive: str | None,
) -> tuple[dict, str | None]:
    approval_id = outcome.get("approval_id")
    if not approval_id or not directive:
        return outcome, None
    if directive == "approve":
        return proxy.resolve_approval(approval_id, approve=True), "approved"
    if directive == "reject":
        return proxy.resolve_approval(approval_id, approve=False), "rejected"
    if directive == "expire":
        with sqlite3.connect(state.db_path) as conn:
            conn.execute(
                "UPDATE pending_approvals SET expires_at=? WHERE approval_id=?",
                (time.time() - 1, approval_id),
            )
            conn.commit()
        status = proxy.get_approval_status(approval_id)
        return {
            **outcome,
            "action": "deny",
            "expiration_status": status["status"] if status else "missing",
        }, "expired"
    return outcome, None


def temporary_root():
    return tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
