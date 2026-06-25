from __future__ import annotations

import argparse
import json
from collections import Counter, defaultdict
from pathlib import Path


ACTIONS = {"allow", "ask", "deny"}


def _read_jsonl(path: Path) -> list[dict]:
    return [
        json.loads(raw)
        for raw in path.read_text(encoding="utf-8").splitlines()
        if raw.strip()
    ]


def _write_jsonl(path: Path, rows: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="\n") as handle:
        for row in rows:
            handle.write(json.dumps(row, ensure_ascii=False) + "\n")


def _case_file_from_review(path: Path) -> Path | None:
    candidate = path.parent.parent / "blind_llm_test.jsonl"
    return candidate if candidate.exists() else None


def _label(row: dict) -> str:
    value = str(row.get("review_label", "")).strip().lower()
    return value if value in ACTIONS else ""


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--review-a", type=Path, required=True)
    parser.add_argument("--review-b", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    review_a = {row["id"]: row for row in _read_jsonl(args.review_a)}
    review_b = {row["id"]: row for row in _read_jsonl(args.review_b)}
    ids = sorted(set(review_a) | set(review_b))
    category_counts: dict[str, Counter] = defaultdict(Counter)
    agreement = 0
    disagreement = 0
    incomplete = 0
    adjudication_needed: list[dict] = []

    for case_id in ids:
        a = review_a.get(case_id, {})
        b = review_b.get(case_id, {})
        category = str(a.get("category") or b.get("category") or "unknown")
        label_a = _label(a)
        label_b = _label(b)
        if not label_a or not label_b:
            incomplete += 1
            category_counts[category]["incomplete"] += 1
            adjudication_needed.append({
                "id": case_id,
                "category": category,
                "reason": "missing_reviewer_label",
                "reviewer_a_label": label_a,
                "reviewer_b_label": label_b,
            })
            continue
        category_counts[category]["reviewed"] += 1
        if label_a == label_b:
            agreement += 1
            category_counts[category]["agreement"] += 1
        else:
            disagreement += 1
            category_counts[category]["disagreement"] += 1
            adjudication_needed.append({
                "id": case_id,
                "category": category,
                "reason": "label_disagreement",
                "reviewer_a_label": label_a,
                "reviewer_b_label": label_b,
                "reviewer_a_rationale": a.get("review_rationale", ""),
                "reviewer_b_rationale": b.get("review_rationale", ""),
            })

    reviewed = agreement + disagreement
    per_category = {}
    for category, counts in sorted(category_counts.items()):
        reviewed_category = counts["reviewed"]
        per_category[category] = {
            "reviewed": reviewed_category,
            "agreement": counts["agreement"],
            "disagreement": counts["disagreement"],
            "incomplete": counts["incomplete"],
            "agreement_rate": (
                round(counts["agreement"] / reviewed_category * 100, 2)
                if reviewed_category else None
            ),
        }

    output = {
        "total_cases": len(ids),
        "reviewed_cases": reviewed,
        "agreement_count": agreement,
        "disagreement_count": disagreement,
        "incomplete_count": incomplete,
        "agreement_rate": (
            round(agreement / reviewed * 100, 2) if reviewed else None
        ),
        "per_category": per_category,
        "adjudication_needed_path": str(
            args.output.with_name("adjudication_needed.jsonl")
        ),
        "note": (
            "Blank reviewer labels are counted as incomplete; CT-TRM outputs "
            "are never used for agreement."
        ),
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(output, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    _write_jsonl(args.output.with_name("adjudication_needed.jsonl"), adjudication_needed)

    case_file = _case_file_from_review(args.review_a)
    if case_file:
        cases = _read_jsonl(case_file)
        by_id_a = review_a
        by_id_b = review_b
        adjudicated = []
        for case in cases:
            label_a = _label(by_id_a.get(case["id"], {}))
            label_b = _label(by_id_b.get(case["id"], {}))
            if label_a and label_a == label_b:
                status = "dual_review_agreed"
                label = label_a
            else:
                status = "original_label_used_pending_adjudication"
                label = case["label"]
            adjudicated.append({
                **case,
                "label": label,
                "adjudication_status": status,
            })
        _write_jsonl(case_file.with_name("blind_llm_test_adjudicated.jsonl"), adjudicated)

    print(json.dumps(output, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
