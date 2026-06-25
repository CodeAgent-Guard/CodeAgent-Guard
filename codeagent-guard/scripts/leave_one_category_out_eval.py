from __future__ import annotations

import argparse
import csv
import json
import sys
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from guard.evaluation_ct_trm import load_cases, run_mode


DATASETS = [
    Path("benchmarks/agent_tool_bench/cases/benchmark.jsonl"),
    Path("benchmarks/agent_tool_bench/cases/dev_calibration.jsonl"),
    Path("benchmarks/agent_tool_bench/cases/holdout_generated.jsonl"),
    Path("benchmarks/agent_tool_bench/cases/redteam_unseen.jsonl"),
]


FIELDS = [
    "category",
    "cases",
    "accuracy",
    "attack_intervention_rate",
    "strong_block_rate",
    "complete_false_negative_rate",
    "normal_task_disruption_rate",
    "macro_f1",
    "failures",
]


def collect_cases() -> list[dict]:
    cases: list[dict] = []
    for path in DATASETS:
        if path.exists():
            cases.extend(load_cases(path))
    return cases


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path("reports/objective_eval"),
    )
    args = parser.parse_args()
    output_dir = args.output_dir
    output_dir.mkdir(parents=True, exist_ok=True)

    buckets: dict[str, list[dict]] = defaultdict(list)
    for case in collect_cases():
        buckets[str(case["category"])].append(case)

    rows = []
    failures_by_category = {}
    for category, cases in sorted(buckets.items()):
        result = run_mode("full_ct_trm", cases)
        row = {
            "category": category,
            "cases": result["total_cases"],
            "accuracy": result["accuracy"],
            "attack_intervention_rate": result["attack_intervention_rate"],
            "strong_block_rate": result["strong_block_rate"],
            "complete_false_negative_rate": result[
                "complete_false_negative_rate"
            ],
            "normal_task_disruption_rate": result[
                "normal_task_disruption_rate"
            ],
            "macro_f1": result["macro_f1"],
            "failures": len(result.get("failure_cases", [])),
        }
        rows.append(row)
        failures_by_category[category] = result.get("failure_cases", [])

    csv_path = output_dir / "leave_one_category_out.csv"
    with csv_path.open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=FIELDS)
        writer.writeheader()
        writer.writerows(rows)

    json_path = output_dir / "leave_one_category_out.json"
    json_path.write_text(
        json.dumps({
            "categories": rows,
            "failures_by_category": failures_by_category,
            "note": (
                "No thresholds or rules are changed in this script; each row "
                "treats one category as a held-out evaluation slice."
            ),
        }, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )

    lines = [
        "# Leave-One-Category-Out Evaluation",
        "",
        "This analysis evaluates each category as a held-out slice. It does "
        "not tune thresholds or rules during the run.",
        "",
        "| Category | Cases | Accuracy | Attack Intervention | Strong Block | Complete FN | Normal Disruption | Macro F1 | Failures |",
        "|---|---:|---:|---:|---:|---:|---:|---:|---:|",
    ]
    for row in rows:
        lines.append(
            f"| {row['category']} | {row['cases']} | {row['accuracy']}% | "
            f"{row['attack_intervention_rate']}% | "
            f"{row['strong_block_rate']}% | "
            f"{row['complete_false_negative_rate']}% | "
            f"{row['normal_task_disruption_rate']}% | "
            f"{row['macro_f1']}% | {row['failures']} |"
        )
    (output_dir / "leave_one_category_out.md").write_text(
        "\n".join(lines) + "\n",
        encoding="utf-8",
    )
    print(json.dumps({
        "categories": len(rows),
        "output_csv": str(csv_path),
        "output_md": str(output_dir / "leave_one_category_out.md"),
    }, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
