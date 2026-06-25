from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from guard.evaluation_ct_trm import run_mode


ACTIONS = {"allow", "ask", "deny"}


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    cases: list[dict[str, Any]] = []
    for line_number, raw in enumerate(
        path.read_text(encoding="utf-8").splitlines(),
        start=1,
    ):
        if not raw.strip():
            continue
        try:
            item = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise ValueError(f"{path}:{line_number}: invalid JSON: {exc}") from exc
        cases.append(item)
    return cases


def write_jsonl(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="\n") as handle:
        for row in rows:
            handle.write(json.dumps(row, ensure_ascii=False) + "\n")


def write_json(path: Path, data: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(data, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )


def _final_call(case: dict[str, Any]) -> dict[str, Any]:
    if isinstance(case.get("tool_call"), dict):
        return dict(case["tool_call"])
    sequence = case.get("expected_sequence") or []
    if sequence:
        return dict(sequence[-1])
    if isinstance(case.get("expected_tool_call"), dict):
        return dict(case["expected_tool_call"])
    raise ValueError(f"{case.get('id', '<unknown>')} has no tool call")


def normalize_objective_case(
    case: dict[str, Any],
    *,
    default_split: str,
) -> dict[str, Any]:
    label = str(
        case.get("label")
        or case.get("expected_guard_decision")
        or case.get("expected_action")
        or ""
    ).lower()
    if label not in ACTIONS:
        raise ValueError(f"{case.get('id', '<unknown>')} invalid label: {label!r}")
    call = _final_call(case)
    tool = str(call.get("tool", ""))
    if not tool:
        raise ValueError(f"{case.get('id', '<unknown>')} tool is empty")
    return {
        "id": str(case["id"]),
        "split": str(case.get("split") or default_split),
        "category": str(case.get("category", "uncategorized")),
        "subcategory": str(case.get("subcategory", "")),
        "user_task": str(case.get("user_task") or case.get("description") or case["id"]),
        "description": str(case.get("user_task") or case.get("description") or case["id"]),
        "workspace_setup": case.get("workspace_setup") or [],
        "expected_guard_decision": label,
        "malicious": bool(case.get("malicious", label == "deny")),
        "expected_tool_call": {
            "tool": tool,
            "args": call.get("args") or {},
            "source": str(call.get("source", case.get("source", "agent"))),
            "tainted": bool(call.get("tainted", case.get("tainted", False))),
        },
        "rationale": str(case.get("rationale", "")),
        "safe_execution": bool(case.get("safe_execution", True)),
    }


def evaluate_objective_cases(
    cases: list[dict[str, Any]],
    *,
    split: str,
    mode: str = "full_ct_trm",
) -> dict[str, Any]:
    normalized = [
        normalize_objective_case(case, default_split=split)
        for case in cases
    ]
    result = run_mode(mode, normalized)
    result["dataset_split"] = split
    return result


def metric_subset(result: dict[str, Any]) -> dict[str, Any]:
    keys = [
        "total_cases",
        "accuracy",
        "attack_intervention_rate",
        "strong_block_rate",
        "complete_false_negative_rate",
        "deny_miss_rate",
        "normal_task_disruption_rate",
        "overblocking_rate",
        "deny_precision",
        "deny_recall",
        "deny_f1",
        "macro_f1",
        "policy_latency_p95_ms",
    ]
    return {key: result.get(key, 0) for key in keys}


def metric_table(rows: list[dict[str, Any]], dataset_key: str = "dataset") -> str:
    lines = [
        "| Dataset | Cases | Accuracy | Attack Intervention | Strong Block | Complete FN | Normal Disruption | DENY F1 | Macro F1 | P95 ms | Failures |",
        "|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|",
    ]
    for row in rows:
        lines.append(
            f"| {row[dataset_key]} | {row['total_cases']} | "
            f"{row['accuracy']}% | {row['attack_intervention_rate']}% | "
            f"{row['strong_block_rate']}% | "
            f"{row['complete_false_negative_rate']}% | "
            f"{row['normal_task_disruption_rate']}% | "
            f"{row['deny_f1']}% | {row['macro_f1']}% | "
            f"{row['policy_latency_p95_ms']} | {row.get('failures', 0)} |"
        )
    return "\n".join(lines)


def result_row(dataset: str, result: dict[str, Any]) -> dict[str, Any]:
    row = {"dataset": dataset, **metric_subset(result)}
    row["failures"] = len(result.get("failure_cases", []))
    return row
