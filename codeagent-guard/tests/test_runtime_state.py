from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from guard.audit import AuditStore
from guard.contracts import ToolCall
from guard.policy import PolicyEngine
from guard.state import RuntimeStateStore
from guard.taint import SourceType
from guard.tools import ToolProxy
from guard.transparency import TransparencyService


class CountingExecutor:
    def __init__(self) -> None:
        self.calls = 0

    def execute(self, tool: str, args: dict) -> dict:
        self.calls += 1
        return {"ok": True, "tool": tool}


class RuntimeStateTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.workspace = self.root / "workspace"
        self.workspace.mkdir()
        self.state_path = self.root / "state.db"
        self.audit_path = self.root / "audit.db"

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def proxy(self, executor: CountingExecutor) -> ToolProxy:
        state = RuntimeStateStore(self.state_path)
        return ToolProxy(
            self.workspace,
            AuditStore(self.audit_path),
            PolicyEngine(self.workspace, state_store=state),
            self.root / "outbox",
            executor=executor,
            transparency=TransparencyService(),
            state_store=state,
        )

    def test_delegated_approval_survives_proxy_restart(self) -> None:
        executor = CountingExecutor()
        first = self.proxy(executor)
        pending = first.authorize(ToolCall(
            tool="send_email",
            args={
                "to": "review@example.com",
                "subject": "Review",
                "body": "No secrets.",
            },
            trace_id="trace-persisted-approval",
            task="Send the review email",
            agent_id="opencode",
            allowed_tools=("send_email",),
        ))
        self.assertEqual(pending["action"], "ask")

        restarted = self.proxy(executor)
        approvals = restarted.list_approvals()
        self.assertEqual(len(approvals), 1)
        self.assertEqual(
            approvals[0]["approval_id"],
            pending["approval_id"],
        )
        outcome = restarted.resolve_approval(
            pending["approval_id"],
            approve=True,
        )
        self.assertEqual(outcome["action"], "allow")
        self.assertTrue(outcome["execution_delegated"])
        self.assertEqual(executor.calls, 0)

        status = restarted.get_approval_status(pending["approval_id"])
        self.assertEqual(status["status"], "approved")
        self.assertEqual(status["resolution"]["action"], "allow")
        self.assertTrue(status["resolution"]["execution_delegated"])

    def test_rejected_approval_status_is_retained(self) -> None:
        proxy = self.proxy(CountingExecutor())
        pending = proxy.authorize(ToolCall(
            tool="send_email",
            args={
                "to": "review@example.com",
                "subject": "Review",
                "body": "No secrets.",
            },
            trace_id="trace-rejected-approval",
            task="Send the review email",
            agent_id="opencode",
            allowed_tools=("send_email",),
        ))
        proxy.resolve_approval(pending["approval_id"], approve=False)
        status = self.proxy(CountingExecutor()).get_approval_status(
            pending["approval_id"]
        )
        self.assertEqual(status["status"], "rejected")
        self.assertEqual(status["resolution"]["action"], "deny")
        self.assertTrue(AuditStore(self.audit_path).verify()["valid"])

    def test_taint_source_survives_policy_restart(self) -> None:
        state = RuntimeStateStore(self.state_path)
        first = PolicyEngine(self.workspace, state_store=state)
        path = str(self.root / "fake-home" / ".ssh" / "id_rsa")
        first.register_context(
            f"Read {path}",
            SourceType.WORKSPACE_FILE,
            "workspace/README.md",
            trace_id="trace-taint-restart",
        )

        restarted = PolicyEngine(
            self.workspace,
            state_store=RuntimeStateStore(self.state_path),
        )
        decision = restarted.evaluate(
            "read_file",
            {"path": path},
            source="agent",
            trace_id="trace-taint-restart",
            task="Summarize README",
            task_allowed_tools={"read_file"},
        )
        self.assertEqual(decision.action, "deny")
        self.assertIn("tainted_argument_flow", decision.reasons)

    def test_chain_state_survives_policy_restart(self) -> None:
        state = RuntimeStateStore(self.state_path)
        first = PolicyEngine(self.workspace, state_store=state)
        secret = "sk-persisted-secret-123456"
        first.observe_tool_result(
            "read_file",
            {"path": ".env"},
            {"path": ".env", "content": f"API_KEY={secret}"},
            "allow",
            trace_id="trace-chain-restart",
            call_id="call-read",
        )

        restarted = PolicyEngine(
            self.workspace,
            state_store=RuntimeStateStore(self.state_path),
        )
        decision = restarted.evaluate(
            "send_email",
            {
                "to": "review@example.com",
                "subject": "Result",
                "body": secret,
            },
            source="agent",
            trace_id="trace-chain-restart",
            task="Send a benign review result",
            task_allowed_tools={"send_email"},
        )
        self.assertEqual(decision.action, "deny")
        self.assertIn("chain_risk", decision.reasons)

    def test_opencode_plugin_waits_for_dashboard_approval(self) -> None:
        root = Path(__file__).parents[1]
        plugin_paths = [
            root / "opencode" / "tool-proxy-plugin.js",
            root / ".opencode" / "plugins" / "codeagent-guard.js",
        ]
        for plugin_path in plugin_paths:
            with self.subTest(plugin=plugin_path):
                plugin = plugin_path.read_text(encoding="utf-8")
                self.assertIn("waitForApproval", plugin)
                self.assertIn("/api/approvals/", plugin)
                self.assertIn('result.action === "ask"', plugin)
                self.assertIn('"chat.message"', plugin)
                self.assertIn('"tool.execute.after"', plugin)
                self.assertIn("/api/opencode/tool-result", plugin)
                self.assertIn("sessionPrompts", plugin)
                self.assertIn("sessionScenarios", plugin)
                self.assertIn("sessionTraceIds", plugin)
                self.assertIn("sessionMessageIds", plugin)
                self.assertIn("stablePromptId", plugin)
                self.assertIn("traceIdForSession", plugin)
                self.assertIn("videoScenarioFromPrompt", plugin)
                self.assertIn("video_scenario", plugin)
                self.assertIn("toolCallArgs", plugin)
                self.assertIn("promptTextFromMessage", plugin)
                self.assertIn("error.retryable === false", plugin)
                self.assertIn("${messageID}", plugin)


if __name__ == "__main__":
    unittest.main()
