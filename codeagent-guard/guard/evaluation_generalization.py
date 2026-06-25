from __future__ import annotations

import argparse
import csv
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .evaluation_ct_trm import load_cases, run_mode


DATASETS = {
    "dev_calibration": Path(
        "benchmarks/agent_tool_bench/cases/dev_calibration.jsonl"
    ),
    "benchmark_jsonl_external_fixed": Path(
        "benchmarks/agent_tool_bench/cases/benchmark.jsonl"
    ),
    "holdout_generated": Path(
        "benchmarks/agent_tool_bench/cases/holdout_generated.jsonl"
    ),
    "redteam_unseen": Path(
        "benchmarks/agent_tool_bench/cases/redteam_unseen.jsonl"
    ),
}


METRICS = [
    "total_cases",
    "accuracy",
    "attack_intervention_rate",
    "strong_block_rate",
    "complete_false_negative_rate",
    "deny_miss_rate",
    "false_positive_rate",
    "normal_task_disruption_rate",
    "overblocking_rate",
    "deny_precision",
    "deny_recall",
    "deny_f1",
    "macro_f1",
    "policy_latency_p95_ms",
]


def _summary(dataset: str, path: Path, result: dict[str, Any]) -> dict[str, Any]:
    row = {
        "dataset": dataset,
        "path": str(path),
        "mode": result["mode"],
    }
    for metric in METRICS:
        row[metric] = result.get(metric, 0)
    row["expected_allow"] = result.get("expected_allow", 0)
    row["expected_ask"] = result.get("expected_ask", 0)
    row["expected_deny"] = result.get("expected_deny", 0)
    row["actual_allow"] = result.get("actual_allow", 0)
    row["actual_ask"] = result.get("actual_ask", 0)
    row["actual_deny"] = result.get("actual_deny", 0)
    row["failure_count"] = len(result.get("failure_cases", []))
    return row


def _write_failure_files(
    output_dir: Path,
    dataset: str,
    failures: list[dict[str, Any]],
) -> None:
    failure_dir = output_dir / "failures_by_dataset"
    failure_dir.mkdir(parents=True, exist_ok=True)
    jsonl_path = failure_dir / f"{dataset}.jsonl"
    with jsonl_path.open("w", encoding="utf-8", newline="\n") as handle:
        for failure in failures:
            handle.write(json.dumps(failure, ensure_ascii=False) + "\n")
    lines = [f"# Failures: {dataset}", ""]
    if not failures:
        lines.append("No failures.")
    for item in failures:
        lines.append(
            f"- `{item['id']}` `{item['category']}` / "
            f"`{item.get('subcategory', '')}`: expected "
            f"`{item['expected_action']}`, got `{item['actual_action']}`; "
            f"reasons={', '.join(item.get('reasons', [])) or '-'}"
        )
    (failure_dir / f"{dataset}.md").write_text(
        "\n".join(lines) + "\n",
        encoding="utf-8",
    )


def _write_category_breakdown(
    output_dir: Path,
    dataset: str,
    result: dict[str, Any],
) -> None:
    category_dir = output_dir / "category_breakdown"
    category_dir.mkdir(parents=True, exist_ok=True)
    fields = [
        "dataset",
        "category",
        "total",
        "passed",
        "allow",
        "ask",
        "deny",
        "false_positive",
        "false_negative",
    ]
    with (category_dir / f"{dataset}.csv").open(
        "w", encoding="utf-8-sig", newline=""
    ) as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        for category, values in result.get("cases_by_category", {}).items():
            writer.writerow({
                "dataset": dataset,
                "category": category,
                **{
                    field: values.get(field, 0)
                    for field in fields
                    if field not in {"dataset", "category"}
                },
            })


def _markdown_table(rows: list[dict[str, Any]]) -> str:
    lines = [
        "| Dataset | Cases | Accuracy | Attack Intervention | Strong Block | Complete FN | Deny Miss | Normal Disruption | Overblock | DENY F1 | Macro F1 | P95 ms | Failures |",
        "|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|",
    ]
    for row in rows:
        lines.append(
            f"| {row['dataset']} | {row['total_cases']} | "
            f"{row['accuracy']}% | {row['attack_intervention_rate']}% | "
            f"{row['strong_block_rate']}% | "
            f"{row['complete_false_negative_rate']}% | "
            f"{row['deny_miss_rate']}% | "
            f"{row['normal_task_disruption_rate']}% | "
            f"{row['overblocking_rate']}% | {row['deny_f1']}% | "
            f"{row['macro_f1']}% | {row['policy_latency_p95_ms']} | "
            f"{row['failure_count']} |"
        )
    return "\n".join(lines)


def _write_report(output_dir: Path, rows: list[dict[str, Any]]) -> None:
    redteam = next(
        (row for row in rows if row["dataset"] == "redteam_unseen"),
        None,
    )
    holdout = next(
        (row for row in rows if row["dataset"] == "holdout_generated"),
        None,
    )
    fixed = next(
        (
            row for row in rows
            if row["dataset"] == "benchmark_jsonl_external_fixed"
        ),
        None,
    )
    intervention_values = [
        row["attack_intervention_rate"]
        for row in rows
        if row["dataset"] != "dev_calibration"
    ]
    fn_values = [
        row["complete_false_negative_rate"]
        for row in rows
        if row["dataset"] != "dev_calibration"
    ]
    intervention_range = (
        f"{min(intervention_values)}%-{max(intervention_values)}%"
        if intervention_values else "n/a"
    )
    fn_range = (
        f"{min(fn_values)}%-{max(fn_values)}%"
        if fn_values else "n/a"
    )
    markdown = f"""# CT-TRM Generalization Report

## Purpose

This report checks whether CT-TRM behavior remains stable outside the fixed
`benchmark.jsonl` set. The goal is to detect overfitting to individual cases,
fixed wording, or a narrow Ask/Deny boundary.

## Split Usage

- `dev_calibration`: generated calibration set; this is the only split allowed
  for rule calibration and threshold exploration.
- `benchmark_jsonl_external_fixed`: the existing `benchmark.jsonl`, marked as
  `external_fixed_test`. It is not a training set.
- `holdout_generated`: generated holdout with different carriers, commands,
  paths, recipients, and URL variants. It is used only for final validation.
- `redteam_unseen`: stronger bypass set used only for final validation.

## Summary

{_markdown_table(rows)}

## Interpretation

Across the non-calibration datasets, CT-TRM kept attack intervention in the
range {intervention_range} and complete false negative rate in the range
{fn_range}. This does not claim generalization to all unknown attacks; it shows
that the current rules retain behavior across several deterministic datasets
that did not participate in calibration.

"""
    if fixed and holdout:
        markdown += (
            "Fixed benchmark vs holdout accuracy delta: "
            f"{round(fixed['accuracy'] - holdout['accuracy'], 2)} percentage "
            "points. If the fixed benchmark improves while holdout or red-team "
            "drops, treat that as an overfit signal rather than proof of "
            "generalization.\n\n"
        )
    if redteam:
        markdown += (
            "Red-team unseen coverage includes double encoding, IPv6 and "
            "decimal IP forms, redirect and DNS-private SSRF, symlink chains, "
            "environment expansion, command substitution, chunked secrets, "
            "attachment exfiltration, and indirect package scripts.\n\n"
            "The red-team split is intentionally DENY-only. Its three-class "
            "Macro F1 is therefore less informative than strong block rate and "
            "DENY F1 for that split.\n\n"
        )
    sensitivity_path = output_dir / "threshold_sensitivity.json"
    if sensitivity_path.exists():
        sensitivity = json.loads(sensitivity_path.read_text(encoding="utf-8"))
        recommended = sensitivity.get("recommended", {})
        status_counts = sensitivity.get("status_counts", {})
        markdown += f"""## Threshold Sensitivity

- Recommended ask_threshold: `{recommended.get('ask_threshold')}`
- Recommended deny_threshold: `{recommended.get('deny_threshold')}`
- Recommendation score: `{recommended.get('score')}`
- Robust regions: {status_counts.get('robust_region', 0)}
- Overfit-risk regions: {status_counts.get('overfit_risk', 0)}

The recommendation is based on dev, holdout, and red-team performance rather
than optimizing the external fixed benchmark alone.

"""
    markdown += (
        "Detailed failure files are under `failures_by_dataset/`; category "
        "breakdowns are under `category_breakdown/`.\n"
    )
    (output_dir / "generalization_report.md").write_text(
        markdown,
        encoding="utf-8",
    )
    (output_dir / "generalization_summary.md").write_text(
        "# CT-TRM Generalization Summary\n\n"
        + _markdown_table(rows)
        + "\n",
        encoding="utf-8",
    )


def evaluate_all(output_dir: Path) -> dict[str, Any]:
    output_dir.mkdir(parents=True, exist_ok=True)
    dataset_results: dict[str, dict[str, Any]] = {}
    rows: list[dict[str, Any]] = []
    for dataset, path in DATASETS.items():
        cases = load_cases(path)
        result = run_mode("full_ct_trm", cases)
        dataset_results[dataset] = result
        (output_dir / f"{dataset}.json").write_text(
            json.dumps(result, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )
        _write_failure_files(output_dir, dataset, result["failure_cases"])
        _write_category_breakdown(output_dir, dataset, result)
        rows.append(_summary(dataset, path, result))

    summary = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "mode": "full_ct_trm",
        "datasets": rows,
        "metric_definitions": {
            "complete_false_negative_rate": (
                "malicious cases whose actual action is allow"
            ),
            "deny_miss_rate": (
                "expected deny cases whose actual action is ask or allow"
            ),
            "attack_intervention_rate": (
                "malicious cases whose actual action is ask or deny"
            ),
            "strong_block_rate": (
                "malicious cases whose actual action is deny"
            ),
            "normal_task_disruption_rate": (
                "expected allow cases whose actual action is ask or deny"
            ),
            "overblocking_rate": (
                "expected ask cases whose actual action is deny"
            ),
        },
    }
    (output_dir / "generalization_summary.json").write_text(
        json.dumps(summary, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    with (output_dir / "generalization_summary.csv").open(
        "w", encoding="utf-8-sig", newline=""
    ) as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)
    _write_report(output_dir, rows)
    return summary


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--all", action="store_true")
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path("reports/generalization"),
    )
    args = parser.parse_args()
    if not args.all:
        parser.error("use --all")
    summary = evaluate_all(args.output_dir)
    print(json.dumps(summary["datasets"], ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
