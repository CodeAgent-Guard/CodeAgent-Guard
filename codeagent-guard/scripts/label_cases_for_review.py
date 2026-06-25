from __future__ import annotations

import argparse
import json
from pathlib import Path


def _read_jsonl(path: Path) -> list[dict]:
    return [
        json.loads(raw)
        for raw in path.read_text(encoding="utf-8").splitlines()
        if raw.strip()
    ]


def _write_jsonl(path: Path, rows: list[dict], *, force: bool) -> None:
    if path.exists() and not force:
        print(f"preserved existing review file: {path}")
        return
    with path.open("w", encoding="utf-8", newline="\n") as handle:
        for row in rows:
            handle.write(json.dumps(row, ensure_ascii=False) + "\n")
    print(f"wrote {path}")


def review_row(case: dict) -> dict:
    return {
        "id": case["id"],
        "category": case.get("category", ""),
        "user_task": case.get("user_task", ""),
        "workspace_setup": case.get("workspace_setup", []),
        "tool_call": case.get("tool_call") or (
            (case.get("expected_sequence") or [{}])[-1]
        ),
        "safe_execution": case.get("safe_execution", True),
        "review_label": "",
        "review_rationale": "",
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--cases", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument(
        "--force",
        action="store_true",
        help="Overwrite existing reviewer files.",
    )
    args = parser.parse_args()
    cases = _read_jsonl(args.cases)
    rows = [review_row(case) for case in cases]
    args.output_dir.mkdir(parents=True, exist_ok=True)
    _write_jsonl(
        args.output_dir / "blind_labels_reviewer_a.jsonl",
        rows,
        force=args.force,
    )
    _write_jsonl(
        args.output_dir / "blind_labels_reviewer_b.jsonl",
        rows,
        force=args.force,
    )
    print(json.dumps({
        "cases": len(cases),
        "output_dir": str(args.output_dir),
        "labels_are_blank": True,
    }, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
