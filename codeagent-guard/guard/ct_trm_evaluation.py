from __future__ import annotations

import json
import statistics
import tempfile
import time
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .policy import PolicyEngine
from .taint import SourceType


MODES = ("baseline_rules", "rules_plus_source", "full_ct_trm")


class CTTRMEvaluationService:
    def __init__(
        self,
        benchmark_path: Path,
        report_dir: Path,
    ) -> None:
        self.benchmark_path = benchmark_path
        self.report_dir = report_dir
        self.report_dir.mkdir(parents=True, exist_ok=True)
        self.json_path = self.report_dir / "ct_trm_evaluation.json"
        self.markdown_path = self.report_dir / "ct_trm_evaluation.md"

    def load_cases(self) -> list[dict]:
        cases = json.loads(self.benchmark_path.read_text(encoding="utf-8"))
        if not isinstance(cases, list) or len(cases) < 45:
            raise ValueError("CT-TRM benchmark 至少需要 45 条用例")
        return cases

    def run(self) -> dict:
        cases = self.load_cases()
        mode_results = {
            mode: self._run_mode(mode, cases)
            for mode in MODES
        }
        report = {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "benchmark": str(self.benchmark_path),
            "total_cases": len(cases),
            "modes": mode_results,
            "observable_difference": self._difference(mode_results),
        }
        self.json_path.write_text(
            json.dumps(report, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
        self.markdown_path.write_text(
            self._markdown(report),
            encoding="utf-8",
        )
        return report

    def last_result(self) -> dict:
        if not self.json_path.exists():
            return {"available": False}
        return {
            "available": True,
            **json.loads(self.json_path.read_text(encoding="utf-8")),
        }

    def _run_mode(self, mode: str, cases: list[dict]) -> dict:
        results = []
        latencies = []
        action_counts: Counter[str] = Counter()
        category: dict[str, dict[str, int]] = defaultdict(
            lambda: {
                "total": 0,
                "passed": 0,
                "allow": 0,
                "ask": 0,
                "deny": 0,
            }
        )
        taint_count = 0
        chain_count = 0
        reason_coverage: set[str] = set()

        for case in cases:
            with tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                workspace = root / "workspace"
                fake_home = root / "fake_home"
                fake_root = root / "fake_root"
                workspace.mkdir()
                fake_home.mkdir()
                fake_root.mkdir()
                values = {
                    "${WORKSPACE}": str(workspace),
                    "${FAKE_HOME}": str(fake_home),
                    "${FAKE_ROOT}": str(fake_root),
                }
                expanded = self._expand(case, values)
                policy = PolicyEngine(workspace)
                trace_id = f"bench-{case['id']}-{mode}"
                self._apply_setup(policy, expanded.get("setup", []), trace_id)
                started = time.perf_counter()
                decision = policy.evaluate(
                    expanded["tool"],
                    expanded.get("args", {}),
                    source=expanded.get("source", "agent"),
                    tainted=bool(expanded.get("tainted", False)),
                    task_allowed_tools={expanded["tool"]},
                    trace_id=trace_id,
                    task=expanded["task"],
                    ct_trm_mode=mode,
                )
                latency = (time.perf_counter() - started) * 1000
                latencies.append(latency)
                expected = expanded["expected_action"]
                passed = decision.action == expected
                assessment = decision.assessment or {}
                taint_count += int(bool(assessment.get("taint_matches")))
                chain_count += int(bool(assessment.get("chain_findings")))
                reason_coverage.update(
                    reason for reason in decision.reasons
                    if reason not in {
                        "tool_not_allowed",
                        "user_confirmation_required",
                        "resource_scope_violation",
                    }
                )
                action_counts[decision.action] += 1
                bucket = category[expanded["category"]]
                bucket["total"] += 1
                bucket["passed"] += int(passed)
                bucket[decision.action] += 1
                results.append({
                    "id": expanded["id"],
                    "category": expanded["category"],
                    "expected_action": expected,
                    "actual_action": decision.action,
                    "risk_level": decision.risk_level,
                    "passed": passed,
                    "reasons": decision.reasons,
                    "latency_ms": round(latency, 4),
                    "taint_flow": bool(assessment.get("taint_matches")),
                    "chain_risk": bool(assessment.get("chain_findings")),
                    "patterns": [
                        item.get("pattern_id")
                        for item in assessment.get("risk_patterns", [])
                    ],
                })

        expected_denies = [
            result for result in results
            if result["expected_action"] == "deny"
        ]
        expected_allows = [
            result for result in results
            if result["expected_action"] == "allow"
        ]
        false_negative = sum(
            result["actual_action"] != "deny" for result in expected_denies
        )
        false_positive = sum(
            result["actual_action"] == "deny" for result in expected_allows
        )
        sorted_latencies = sorted(latencies)
        p95_index = max(0, int(len(sorted_latencies) * 0.95) - 1)
        return {
            "total_cases": len(results),
            "passed": sum(result["passed"] for result in results),
            "accuracy": round(
                sum(result["passed"] for result in results) / len(results) * 100,
                2,
            ),
            "allow_count": action_counts["allow"],
            "ask_count": action_counts["ask"],
            "deny_count": action_counts["deny"],
            "false_positive_count": false_positive,
            "false_negative_count": false_negative,
            "guard_block_rate": round(
                action_counts["deny"] / len(results) * 100,
                2,
            ),
            "ask_rate": round(action_counts["ask"] / len(results) * 100, 2),
            "policy_latency_avg_ms": round(statistics.mean(latencies), 4),
            "policy_latency_p95_ms": round(
                sorted_latencies[p95_index],
                4,
            ),
            "taint_flow_detected_count": taint_count,
            "chain_risk_detected_count": chain_count,
            "new_reason_coverage": sorted(reason_coverage),
            "per_category_breakdown": dict(category),
            "results": results,
        }

    def _apply_setup(
        self,
        policy: PolicyEngine,
        setup: list[dict],
        trace_id: str,
    ) -> None:
        for item in setup:
            kind = item.get("kind", "context")
            if kind == "context":
                policy.register_context(
                    str(item.get("content", "")),
                    SourceType(item.get("source_type", "workspace_file")),
                    str(item.get("origin", "benchmark")),
                    trace_id=trace_id,
                )
            elif kind == "result":
                policy.observe_tool_result(
                    str(item["tool"]),
                    item.get("args", {}),
                    item.get("result", {}),
                    str(item.get("decision", "allow")),
                    trace_id=trace_id,
                )
            elif kind == "file":
                path = Path(str(item["path"]))
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(str(item.get("content", "")), encoding="utf-8")

    @classmethod
    def _expand(cls, value: Any, replacements: dict[str, str]) -> Any:
        if isinstance(value, dict):
            return {
                key: cls._expand(item, replacements)
                for key, item in value.items()
            }
        if isinstance(value, list):
            return [cls._expand(item, replacements) for item in value]
        if isinstance(value, str):
            for marker, replacement in replacements.items():
                value = value.replace(marker, replacement)
            return value
        return value

    @staticmethod
    def _difference(mode_results: dict) -> dict:
        baseline = mode_results["baseline_rules"]
        full = mode_results["full_ct_trm"]
        return {
            "additional_taint_flows": (
                full["taint_flow_detected_count"]
                - baseline["taint_flow_detected_count"]
            ),
            "additional_chain_risks": (
                full["chain_risk_detected_count"]
                - baseline["chain_risk_detected_count"]
            ),
            "false_negative_reduction": (
                baseline["false_negative_count"]
                - full["false_negative_count"]
            ),
            "accuracy_delta": round(
                full["accuracy"] - baseline["accuracy"],
                2,
            ),
        }

    @staticmethod
    def _markdown(report: dict) -> str:
        rows = []
        for mode, result in report["modes"].items():
            rows.append(
                f"| `{mode}` | {result['total_cases']} | "
                f"{result['accuracy']}% | {result['allow_count']} | "
                f"{result['ask_count']} | {result['deny_count']} | "
                f"{result['false_positive_count']} | "
                f"{result['false_negative_count']} | "
                f"{result['taint_flow_detected_count']} | "
                f"{result['chain_risk_detected_count']} | "
                f"{result['policy_latency_avg_ms']} | "
                f"{result['policy_latency_p95_ms']} |"
            )
        category_rows = []
        full = report["modes"]["full_ct_trm"]["per_category_breakdown"]
        for name, value in sorted(full.items()):
            category_rows.append(
                f"| {name} | {value['total']} | {value['passed']} | "
                f"{value['allow']} | {value['ask']} | {value['deny']} |"
            )
        difference = report["observable_difference"]
        return f"""# CT-TRM 消融评测报告

生成时间：{report['generated_at']}

## 总体指标

| 模式 | 用例 | 准确率 | Allow | Ask | Deny | FP | FN | Taint Flow | Chain Risk | Avg ms | P95 ms |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
{chr(10).join(rows)}

## Full CT-TRM 分类结果

| 分类 | 用例 | 通过 | Allow | Ask | Deny |
|---|---:|---:|---:|---:|---:|
{chr(10).join(category_rows)}

## 可观测差异

- 新增污染传播检测：{difference['additional_taint_flows']}
- 新增调用链风险检测：{difference['additional_chain_risks']}
- 漏报减少：{difference['false_negative_reduction']}
- 准确率变化：{difference['accuracy_delta']} 个百分点

## 口径

- `baseline_rules`：仅运行原有参数级规则。
- `rules_plus_source`：加入来源风险评分，不启用传播与序列状态。
- `full_ct_trm`：启用来源、实体、传播、任务预算、风险模式与序列检测。
- 全部样本使用临时 workspace、fake_home、fake_root 和 example.test，不执行工具、不访问网络、不发送邮件。
"""
