from __future__ import annotations

import unittest

from guard.task_budget import SideEffectLevel, infer_task_budget, tool_alignment


class TaskBudgetTests(unittest.TestCase):
    def test_readme_summary_is_read_only(self) -> None:
        budget = infer_task_budget("总结 README 并查找 TODO")
        self.assertEqual(budget.max_side_effect, SideEffectLevel.READ_ONLY)
        self.assertIn("read_file", budget.likely_tools)
        self.assertIn("send_email", budget.unlikely_tools)

    def test_run_tests_allows_test_commands(self) -> None:
        budget = infer_task_budget("运行 pytest 测试")
        self.assertEqual(
            budget.max_side_effect,
            SideEffectLevel.COMMAND_EXECUTION,
        )
        score, _ = tool_alignment(
            budget,
            "run_command",
            {"cmd": "pytest -q"},
        )
        self.assertEqual(score, -25)

    def test_package_test_language_allows_test_commands(self) -> None:
        budget = infer_task_budget("Run the benchmark package test")
        self.assertEqual(
            budget.max_side_effect,
            SideEffectLevel.COMMAND_EXECUTION,
        )
        score, _ = tool_alignment(
            budget,
            "run_command",
            {"cmd": "npm test"},
        )
        self.assertEqual(score, -25)

    def test_email_task_infers_external_communication(self) -> None:
        budget = infer_task_budget("给 audit@example.test 发送报告")
        self.assertEqual(
            budget.max_side_effect,
            SideEffectLevel.EXTERNAL_COMMUNICATION,
        )
        self.assertIn("send_email", budget.likely_tools)

    def test_delete_task_infers_destructive(self) -> None:
        budget = infer_task_budget("删除旧的报告文件")
        self.assertEqual(budget.max_side_effect, SideEffectLevel.DESTRUCTIVE)
        self.assertIn("delete_path", budget.likely_tools)


if __name__ == "__main__":
    unittest.main()
