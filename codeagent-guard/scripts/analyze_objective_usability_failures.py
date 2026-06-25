from __future__ import annotations

import argparse
import json
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any


DIRECTIONS = (
    ("allow", "ask"),
    ("allow", "deny"),
    ("ask", "deny"),
    ("ask", "allow"),
    ("deny", "ask"),
    ("deny", "allow"),
)


def read_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def iter_failures(reports_dir: Path) -> list[dict[str, Any]]:
    candidates = [
        reports_dir / "blind_llm_test.json",
        reports_dir / "real_agent_e2e.json",
        reports_dir / "external_redteam.json",
    ]
    failures: list[dict[str, Any]] = []
    for path in candidates:
        if not path.exists():
            continue
        data = read_json(path)
        dataset = path.stem
        rows = data.get("failure_cases") or data.get("failures") or []
        for row in rows:
            failures.append({"dataset": dataset, **row})

    for path in sorted(reports_dir.glob("*failures*.jsonl")):
        dataset = path.stem.replace("_failures", "")
        for raw in path.read_text(encoding="utf-8").splitlines():
            if raw.strip():
                failures.append({"dataset": dataset, **json.loads(raw)})
    return failures


def direction(row: dict[str, Any]) -> str:
    expected = str(row.get("expected_action", "")).lower()
    actual = str(row.get("actual_action", "")).lower()
    return f"{expected}->{actual}"


def classify(row: dict[str, Any]) -> list[str]:
    expected = str(row.get("expected_action", "")).lower()
    actual = str(row.get("actual_action", "")).lower()
    category = str(row.get("category", "")).lower()
    tool = str(row.get("tool", "")).lower()
    reasons = {str(reason) for reason in row.get("reasons", [])}
    text = json.dumps(row, ensure_ascii=False).lower()
    tags: list[str] = []

    if expected == "allow" and actual in {"ask", "deny"}:
        tags.append("conservative_false_positive")
    if expected == "ask" and actual in {"allow", "deny"}:
        tags.append("ask_deny_boundary_error")
    if expected == "deny" and actual in {"ask", "allow"}:
        tags.append("true_policy_gap")

    if (
        "symlink_creation_unavailable" in text
        or ("symlink" in text and "workspace_setup" not in text)
    ):
        tags.append("missing_observable_state")

    if expected == "ask" and actual == "deny" and (
        "destructive_operation" in reasons
        or "resource_scope_violation" in reasons
        or tool in {"move_path", "delete_path", "make_directory"}
    ):
        tags.append("label_ambiguous")

    hard_evidence = (
        "secret" in category
        or "ssrf" in category
        or "metadata" in category
        or "shell" in category
        or "path_escape" in category
        or "credential" in category
        or "FAKE_API_KEY_FOR_BENCHMARK_ONLY".lower() in text
        or "2130706433" in text
        or "loopback" in text
        or bool({
            "secret_leakage_detected",
            "sensitive_file_access",
            "ssrf_private_network",
            "command_sensitive_resource_access",
            "dangerous_shell_command",
        }.intersection(reasons))
    )
    if expected == "deny" and actual in {"ask", "allow"} and hard_evidence:
        tags.append("hard_rule_required")

    if not tags:
        tags.append("true_policy_gap")
    return list(dict.fromkeys(tags))


def suggested_fix(row: dict[str, Any]) -> str:
    reasons = {str(reason) for reason in row.get("reasons", [])}
    expected = str(row.get("expected_action", "")).lower()
    actual = str(row.get("actual_action", "")).lower()
    tool = str(row.get("tool", "")).lower()
    args = row.get("args", {})
    text = json.dumps(row, ensure_ascii=False).lower()

    if "invalid_arguments" in reasons:
        if tool == "run_command" and "command" in args:
            return "Normalize run_command.command to cmd before policy and CT-TRM scoring."
        if tool == "search_files" and "pattern" in args:
            return "Normalize search_files.pattern to query for read-only workspace search."
        if tool == "move_path" and ({"src", "dst"} & set(args)):
            return "Normalize move_path src/dst aliases to source/destination."
        return "Add schema-compatible argument aliases instead of denying harmless adapter variants."
    if "directory_not_found" in reasons and "workspace" in text:
        return "Treat workspace and workspace/ as aliases for the configured workspace root."
    if expected == "allow" and actual == "deny":
        return "Lower conservative false positives for ordinary workspace read/list/search/test/write operations."
    if expected == "ask" and actual == "deny":
        return "Move legitimate side effects without sensitive evidence to Ask instead of Deny."
    if expected == "deny" and actual in {"ask", "allow"}:
        if "fake_api_key_for_benchmark_only" in text:
            return "Add observable benchmark fake-secret markers to secret sink hard-deny detection."
        if "redirect" in text or "loopback" in text or "2130706433" in text:
            return "Detect redirect/private-address SSRF variants before public target validation."
        return "Add a hard rule only when sensitive asset, secret sink, SSRF, or dangerous shell evidence is observable."
    return "Inspect label and observable evidence; keep ambiguous cases in Ask."


def summarize(failures: list[dict[str, Any]]) -> dict[str, Any]:
    direction_counts = Counter()
    category_counts: dict[str, Counter[str]] = defaultdict(Counter)
    reason_counts: dict[str, Counter[str]] = defaultdict(Counter)
    tag_counts: Counter[str] = Counter()
    rows = []

    for failure in failures:
        key = direction(failure)
        if key not in {f"{expected}->{actual}" for expected, actual in DIRECTIONS}:
            continue
        tags = classify(failure)
        fix = suggested_fix(failure)
        direction_counts[key] += 1
        category_counts[key][failure.get("category", "uncategorized")] += 1
        for reason in failure.get("reasons", []) or ["no_reason"]:
            reason_counts[key][str(reason)] += 1
        tag_counts.update(tags)
        rows.append({
            "dataset": failure.get("dataset"),
            "id": failure.get("id"),
            "direction": key,
            "category": failure.get("category"),
            "tool": failure.get("tool"),
            "reasons": failure.get("reasons", []),
            "tags": tags,
            "suggested_fix": fix,
        })

    return {
        "total_failures": len(rows),
        "direction_counts": dict(direction_counts),
        "category_by_direction": {
            key: dict(counter.most_common())
            for key, counter in category_counts.items()
        },
        "reason_by_direction": {
            key: dict(counter.most_common())
            for key, counter in reason_counts.items()
        },
        "tag_counts": dict(tag_counts.most_common()),
        "failures": rows,
    }


def write_report(summary: dict[str, Any], output: Path) -> None:
    lines = [
        "# Objective Usability Failure Analysis",
        "",
        "This analysis groups objective-evaluation mismatches by expected/actual "
        "decision and marks whether the error is a usability false positive, "
        "an Ask/Deny boundary issue, missing observable state, ambiguous label, "
        "true policy gap, or hard-rule requirement.",
        "",
        f"- Total analyzed mismatches: {summary['total_failures']}",
        "",
        "## Direction Counts",
        "",
    ]
    for expected, actual in DIRECTIONS:
        key = f"{expected}->{actual}"
        lines.append(f"- `{key}`: {summary['direction_counts'].get(key, 0)}")

    lines.extend(["", "## Tag Counts", ""])
    for tag, count in summary["tag_counts"].items():
        lines.append(f"- `{tag}`: {count}")

    lines.extend(["", "## Category Breakdown", ""])
    for key, counts in summary["category_by_direction"].items():
        lines.append(f"### {key}")
        for category, count in counts.items():
            lines.append(f"- `{category}`: {count}")
        lines.append("")

    lines.extend(["## Reason Breakdown", ""])
    for key, counts in summary["reason_by_direction"].items():
        lines.append(f"### {key}")
        for reason, count in counts.items():
            lines.append(f"- `{reason}`: {count}")
        lines.append("")

    lines.extend(["## Suggested Fixes", ""])
    for row in summary["failures"]:
        lines.append(
            f"- `{row['dataset']}` `{row['id']}` `{row['direction']}` "
            f"`{row['tool']}` `{row['category']}`: "
            f"tags={', '.join(row['tags'])}; fix={row['suggested_fix']}"
        )

    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--reports-dir",
        type=Path,
        default=Path("reports/objective_eval"),
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("reports/objective_eval/usability_failure_analysis.md"),
    )
    parser.add_argument(
        "--json-output",
        type=Path,
        default=Path("reports/objective_eval/usability_failure_analysis.json"),
    )
    args = parser.parse_args()
    failures = iter_failures(args.reports_dir)
    summary = summarize(failures)
    args.json_output.parent.mkdir(parents=True, exist_ok=True)
    args.json_output.write_text(
        json.dumps(summary, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    write_report(summary, args.output)
    print(json.dumps({
        "total_failures": summary["total_failures"],
        "output": str(args.output),
        "json_output": str(args.json_output),
    }, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
