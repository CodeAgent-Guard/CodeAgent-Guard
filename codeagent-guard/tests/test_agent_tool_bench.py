from __future__ import annotations

import unittest

from benchmarks.agent_tool_bench.generators.generate_ct_trm_cases import (
    CATEGORY_COUNTS,
    generate_cases,
)
from benchmarks.agent_tool_bench.generators.mutate_cases import (
    generate_redteam_cases,
)
from benchmarks.agent_tool_bench.generators.validate_cases import (
    validate_cases,
)
from guard.evaluation_ct_trm import MODES


class AgentToolBenchTests(unittest.TestCase):
    def test_generator_is_deterministic_and_has_exact_distribution(self) -> None:
        first = generate_cases()
        second = generate_cases()
        self.assertEqual(first, second)
        self.assertEqual(len(first), 500)
        for category, expected in CATEGORY_COUNTS.items():
            self.assertEqual(
                sum(case["category"] == category for case in first),
                expected,
            )

    def test_split_distribution_is_fixed(self) -> None:
        cases = generate_cases()
        self.assertEqual(sum(case["split"] == "dev" for case in cases), 150)
        self.assertEqual(
            sum(case["split"] == "regression" for case in cases),
            250,
        )
        self.assertEqual(
            sum(case["split"] == "holdout" for case in cases),
            100,
        )

    def test_generated_benchmark_passes_safety_validation(self) -> None:
        report = validate_cases(generate_cases())
        self.assertTrue(report["valid"])
        self.assertEqual(report["error_count"], 0)
        self.assertTrue(all(
            report["coverage"]["risk_patterns"][f"P{index}"] > 0
            for index in range(1, 16)
        ))
        self.assertTrue(all(
            report["coverage"]["chain_patterns"][f"C{index}"] > 0
            for index in range(1, 7)
        ))

    def test_redteam_generator_has_120_safe_cases(self) -> None:
        cases = generate_redteam_cases()
        self.assertEqual(len(cases), 120)
        self.assertTrue(validate_cases(cases)["valid"])

    def test_all_required_ablation_modes_exist(self) -> None:
        self.assertEqual(MODES, (
            "no_guard_mock",
            "baseline_rules",
            "rules_plus_source",
            "rules_plus_taint",
            "ct_trm_without_chain",
            "full_ct_trm",
        ))


if __name__ == "__main__":
    unittest.main()
