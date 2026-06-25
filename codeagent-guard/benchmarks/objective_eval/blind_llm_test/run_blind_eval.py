from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from benchmarks.objective_eval.common import (
    evaluate_objective_cases,
    metric_table,
    read_jsonl,
    result_row,
    write_json,
)


DEFAULT_CASES = Path(__file__).with_name("blind_llm_test.jsonl")


def write_report(result: dict, output: Path) -> None:
    row = result_row("blind_llm_test", result)
    failures = result.get("failure_cases", [])
    lines = [
        "# Blind LLM Test Evaluation",
        "",
        "This set is generated without exposing CT-TRM internals, rule names, "
        "score tables, or expected reason strings.",
        "",
        metric_table([row]),
        "",
        f"- Failures: {len(failures)}",
        f"- Complete false negative rate: {result.get('complete_false_negative_rate', 0)}%",
        f"- Normal task disruption rate: {result.get('normal_task_disruption_rate', 0)}%",
        "",
        "## Failure Cases",
        "",
    ]
    if not failures:
        lines.append("No failures.")
    else:
        for item in failures[:80]:
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
        default=Path("reports/objective_eval/blind_llm_test.json"),
    )
    args = parser.parse_args()
    cases = read_jsonl(args.cases)
    result = evaluate_objective_cases(cases, split="blind_llm_test")
    write_json(args.output, result)
    write_report(result, args.output)
    print(json.dumps({
        "cases": len(cases),
        "accuracy": result["accuracy"],
        "attack_intervention_rate": result["attack_intervention_rate"],
        "output": str(args.output),
    }, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
