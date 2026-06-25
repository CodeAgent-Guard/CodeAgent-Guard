from __future__ import annotations

import json
import re
import sys
from pathlib import Path


GUARD_FILES = [
    Path("guard/policy.py"),
    Path("guard/risk_model.py"),
    Path("guard/risk_patterns.py"),
    Path("guard/taint.py"),
    Path("guard/chain_risk.py"),
]

PROHIBITED = [
    (
        "benchmark_case_id",
        re.compile(r"\b(?:ATB|ATK|GEN)-(?:[A-Z]+-)?\d{4}\b"),
        "guard code must not branch on fixed benchmark case ids",
    ),
    (
        "expected_label_decision",
        re.compile(r"\bexpected_(?:guard_decision|action|label)\b"),
        "guard code must not read expected labels to decide actions",
    ),
    (
        "case_id_logic",
        re.compile(r"\bcase_id\b"),
        "guard code must not use benchmark case_id logic",
    ),
    (
        "benchmark_path_logic",
        re.compile(r"benchmark\.jsonl|agent_tool_bench/cases/benchmark", re.I),
        "guard code must not special-case benchmark.jsonl",
    ),
]


def scan(root: Path) -> list[dict]:
    failures = []
    for relative in GUARD_FILES:
        path = root / relative
        text = path.read_text(encoding="utf-8")
        for line_no, line in enumerate(text.splitlines(), start=1):
            stripped = line.strip()
            if stripped.startswith("#"):
                continue
            for check_id, pattern, message in PROHIBITED:
                if pattern.search(line):
                    failures.append({
                        "file": str(relative),
                        "line": line_no,
                        "check_id": check_id,
                        "message": message,
                        "text": stripped[:220],
                    })
    return failures


def main() -> int:
    root = Path.cwd()
    failures = scan(root)
    if failures:
        print(json.dumps({
            "status": "failed",
            "failures": failures,
        }, indent=2, ensure_ascii=False))
        return 1
    print(json.dumps({
        "status": "passed",
        "checked_files": [str(path) for path in GUARD_FILES],
    }, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    sys.exit(main())
