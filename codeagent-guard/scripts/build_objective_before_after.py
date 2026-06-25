from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any


DATASETS = (
    ("blind_llm_test", "Blind LLM Test"),
    ("real_agent_e2e", "Real Agent E2E"),
    ("external_redteam", "External Red-Team"),
)


def load(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    return json.loads(path.read_text(encoding="utf-8"))


def value(data: dict[str, Any], key: str) -> Any:
    return data.get(key, "-") if data else "-"


def delta(before: Any, after: Any) -> str:
    if not isinstance(before, (int, float)) or not isinstance(after, (int, float)):
        return "-"
    change = round(after - before, 2)
    prefix = "+" if change > 0 else ""
    return f"{prefix}{change}"


def row(dataset: str, label: str, key: str, before: dict[str, Any], after: dict[str, Any]) -> str:
    before_value = value(before, key)
    after_value = value(after, key)
    return (
        f"| {dataset} | {label} | {before_value} | "
        f"{after_value} | {delta(before_value, after_value)} |"
    )


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--report-dir",
        type=Path,
        default=Path("reports/objective_eval"),
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("reports/objective_eval/objective_before_after.md"),
    )
    args = parser.parse_args()
    report_dir = args.report_dir

    before = {
        name: load(report_dir / f"{name}.json")
        for name, _ in DATASETS
    }
    after = {
        name: load(report_dir / f"{name}_after.json")
        for name, _ in DATASETS
    }

    lines = [
        "# Objective Evaluation Before / After",
        "",
        "This report compares the original objective evaluation outputs with "
        "the post-usability-calibration outputs. The goal is lower normal and "
        "gray-task friction while preserving attack intervention and complete "
        "false-negative behavior.",
        "",
        "| Dataset | Metric | Before | After | Delta |",
        "|---|---|---:|---:|---:|",
    ]

    metric_sets = {
        "blind_llm_test": (
            ("Accuracy %", "accuracy"),
            ("Normal disruption %", "normal_task_disruption_rate"),
            ("Complete FN %", "complete_false_negative_rate"),
            ("Attack intervention %", "attack_intervention_rate"),
            ("P95 latency ms", "policy_latency_p95_ms"),
        ),
        "real_agent_e2e": (
            ("Accuracy %", "accuracy"),
            ("Strict task completion %", "strict_task_completion_rate"),
            ("Assisted task completion %", "assisted_task_completion_rate"),
            ("Legacy task completion %", "task_completion_rate"),
            ("False positive %", "false_positive_rate"),
            ("Hard false positive %", "hard_false_positive_rate"),
            ("User friction %", "user_friction_rate"),
            ("Complete FN %", "complete_false_negative_rate"),
            ("Attack intervention %", "attack_intervention_rate"),
            ("P95 latency ms", "policy_latency_p95_ms"),
        ),
        "external_redteam": (
            ("Accuracy %", "accuracy"),
            ("Strong block %", "strong_block_rate"),
            ("Complete FN %", "complete_false_negative_rate"),
            ("Attack intervention %", "attack_intervention_rate"),
            ("P95 latency ms", "policy_latency_p95_ms"),
        ),
    }

    for name, title in DATASETS:
        for label, key in metric_sets[name]:
            lines.append(row(title, label, key, before[name], after[name]))

    lines.extend([
        "",
        "## Interpretation",
        "",
        "- `Normal disruption` and `hard false positive` should go down.",
        "- `Attack intervention` should remain at or near 100%.",
        "- `Complete FN` should remain 0 or close to 0.",
        "- `Assisted task completion` counts normal tasks that can proceed "
        "after explicit approval; `user friction` records those approval stops.",
        "",
        "## Manual Labeling",
        "",
        "Blind LLM review worksheets are generated for two reviewers, but "
        "manual review is pending unless reviewer files are filled by humans.",
    ])

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(json.dumps({"output": str(args.output)}, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
