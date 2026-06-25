from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from guard.chain_risk import ChainRiskAnalyzer
from guard.risk_model import CTTRMRiskModel
from guard.taint import SourceType, TaintTracker
from guard.task_budget import infer_task_budget


class CTTRMRiskModelTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.workspace = Path(self.tmp.name) / "workspace"
        self.workspace.mkdir()
        self.tracker = TaintTracker(self.workspace)
        self.model = CTTRMRiskModel(
            self.workspace,
            self.tracker,
            ChainRiskAnalyzer(),
        )

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def test_hard_deny_cannot_be_lowered_by_task_authorization(self) -> None:
        assessment = self.model.assess_tool_call(
            "read_file",
            {"path": str(self.workspace / ".env")},
            {
                "base_reasons": ["sensitive_file_access"],
                "source_type": "user_task",
            },
            "trace-hard",
            infer_task_budget("读取 workspace/.env"),
        )
        self.assertTrue(assessment.hard_deny)
        self.assertEqual(assessment.action, "deny")

    def test_pytest_command_is_low_risk_when_explicitly_requested(self) -> None:
        assessment = self.model.assess_tool_call(
            "run_command",
            {"cmd": "pytest -q"},
            {"base_reasons": [], "source_type": "llm_plan"},
            "trace-pytest",
            infer_task_budget("运行 pytest 测试"),
        )
        self.assertEqual(assessment.action, "allow")
        self.assertLess(assessment.total_score, 25)

    def test_tainted_sensitive_path_explains_provenance(self) -> None:
        path = str(Path(self.tmp.name) / "fake_home" / ".ssh" / "id_rsa")
        self.tracker.register_context(
            f"read {path}",
            SourceType.WORKSPACE_FILE,
            "workspace/README.md",
            trace_id="trace-taint",
        )
        assessment = self.model.assess_tool_call(
            "read_file",
            {"path": path},
            {
                "base_reasons": ["sensitive_file_access"],
                "source_type": "llm_plan",
            },
            "trace-taint",
            infer_task_budget("总结 README"),
        )
        self.assertEqual(assessment.action, "deny")
        self.assertIn("tainted_argument_flow", assessment.reasons)
        self.assertTrue(assessment.provenance_edges)


if __name__ == "__main__":
    unittest.main()
