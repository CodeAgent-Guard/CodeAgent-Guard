from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from benchmarks.objective_eval.common import (
    evaluate_objective_cases,
    read_jsonl,
    write_json,
)

DEFAULT_CASES = Path(__file__).with_name("redteam_submissions.jsonl")


def top_failure_patterns(failures: list[dict]) -> dict:
    counter: Counter[str] = Counter()
    for failure in failures:
        if failure.get("patterns"):
            counter.update(failure["patterns"])
        elif failure.get("reasons"):
            counter.update(failure["reasons"])
        else:
            counter["no_pattern_or_reason"] += 1
    return dict(counter.most_common(12))


def write_report(result: dict, output: Path) -> None:
    failures = result.get("failure_cases", [])
    lines = [
        "# External Red-Team Evaluation",
        "",
        "Samples are expected to come from authors who do not know CT-TRM "
        "internal rules. This repository includes a small local submission set "
        "to exercise the interface.",
        "",
        f"- Total cases: {result['total_cases']}",
        f"- Accuracy: {result['accuracy']}%",
        f"- Attack intervention rate: {result['attack_intervention_rate']}%",
        f"- Complete false negative rate: {result['complete_false_negative_rate']}%",
        f"- Strong block rate: {result['strong_block_rate']}%",
        f"- Normal task disruption rate: {result['normal_task_disruption_rate']}%",
        f"- Failures: {len(failures)}",
        "",
        "## Top Failure Patterns",
        "",
    ]
    patterns = top_failure_patterns(failures)
    if not patterns:
        lines.append("No failures.")
    else:
        for pattern, count in patterns.items():
            lines.append(f"- `{pattern}`: {count}")
    lines.extend(["", "## Failure Cases", ""])
    if not failures:
        lines.append("No failures.")
    else:
        for item in failures:
            lines.append(
                f"- `{item['id']}` `{item['category']}`: expected "
                f"`{item['expected_action']}`, got `{item['actual_action']}`; "
                f"reasons={', '.join(item.get('reasons', [])) or '-'}"
            )
    output.with_suffix(".md").write_text(
        "\n".join(lines) + "\n",
        encoding="utf-8",
    )


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--cases", type=Path, default=DEFAULT_CASES)
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("reports/objective_eval/external_redteam.json"),
    )
    args = parser.parse_args()
    cases = read_jsonl(args.cases)
    result = evaluate_objective_cases(cases, split="external_redteam")
    result["top_failure_patterns"] = top_failure_patterns(
        result.get("failure_cases", [])
    )
    write_json(args.output, result)
    write_report(result, args.output)
    print(json.dumps({
        "total_cases": result["total_cases"],
        "accuracy": result["accuracy"],
        "attack_intervention_rate": result["attack_intervention_rate"],
        "output": str(args.output),
    }, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
