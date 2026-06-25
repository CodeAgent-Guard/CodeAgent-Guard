from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from benchmarks.objective_eval.common import read_jsonl


REQUIRED = {
    "id",
    "user_task",
    "workspace_setup",
    "label",
    "rationale",
    "category",
    "safe_execution",
}
ACTIONS = {"allow", "ask", "deny"}
FORBIDDEN = [
    re.compile(r"sk-[A-Za-z0-9]{12,}"),
    re.compile(r"AKIA[0-9A-Z]{16}"),
    re.compile(r"@[A-Za-z0-9.-]+\.(com|net|org)", re.I),
]
ALLOWED_EMAILS = {"reviewer@example.test", "attacker@example.test", "outside@example.test"}


def validate_case(case: dict) -> list[str]:
    errors = []
    missing = sorted(REQUIRED.difference(case))
    if missing:
        errors.append(f"missing_fields:{','.join(missing)}")
    if "tool_call" not in case and "expected_sequence" not in case:
        errors.append("missing_tool_call_or_expected_sequence")
    if str(case.get("label", "")).lower() not in ACTIONS:
        errors.append("invalid_label")
    if case.get("safe_execution") is not True:
        errors.append("safe_execution_must_be_true")
    text = json.dumps(case, ensure_ascii=False)
    for pattern in FORBIDDEN:
        for match in pattern.findall(text):
            if isinstance(match, tuple):
                continue
            if "example.test" not in match and match not in ALLOWED_EMAILS:
                errors.append("possible_real_secret_or_email")
    if "http://" in text or "https://" in text:
        if "example.test" not in text and "mock_server" not in text:
            errors.append("non_mock_url")
    return errors


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--cases", type=Path, required=True)
    args = parser.parse_args()
    cases = read_jsonl(args.cases)
    failures = []
    for case in cases:
        errors = validate_case(case)
        if errors:
            failures.append({"id": case.get("id"), "errors": errors})
    result = {
        "cases": len(cases),
        "valid": not failures,
        "failures": failures,
    }
    print(json.dumps(result, ensure_ascii=False, indent=2))
    if failures:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
