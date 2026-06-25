from __future__ import annotations

import argparse
import json
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any


def load_jsonl(path: Path) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    for line_number, raw in enumerate(
        path.read_text(encoding="utf-8").splitlines(),
        start=1,
    ):
        if not raw.strip():
            continue
        try:
            records.append(json.loads(raw))
        except json.JSONDecodeError as exc:
            raise ValueError(
                f"{path}:{line_number}: invalid JSON: {exc}"
            ) from exc
    return records


def load_benchmark(path: Path) -> dict[str, dict[str, Any]]:
    if not path.exists():
        return {}
    return {
        str(case["id"]): case
        for case in load_jsonl(path)
        if "id" in case
    }


def error_pair(record: dict[str, Any]) -> str:
    return (
        f"{str(record.get('expected_action', 'unknown')).upper()} -> "
        f"{str(record.get('actual_action', 'unknown')).upper()}"
    )


def _setup_items(case: dict[str, Any]) -> list[dict[str, Any]]:
    values: list[dict[str, Any]] = []
    for key in ("workspace_setup", "setup"):
        raw = case.get(key)
        if isinstance(raw, list):
            values.extend(item for item in raw if isinstance(item, dict))
    return values


def insufficient_observable_state(
    record: dict[str, Any],
    benchmark_case: dict[str, Any],
) -> tuple[bool, str]:
    combined = " ".join(str(benchmark_case.get(key, "")) for key in (
        "subcategory",
        "description",
        "attack_target",
    )).lower()
    expected_reasons = {
        str(value).lower()
        for value in benchmark_case.get("expected_reasons", [])
    }
    claims_symlink = (
        any(term in combined for term in (
            "symlink",
            "symbolic link",
            "soft link",
            "softlink",
            "符号链接",
            "软链接",
        ))
        or "symlink_escape" in expected_reasons
    )
    if not claims_symlink:
        return False, ""

    args_text = json.dumps(
        record.get("args", {}),
        ensure_ascii=False,
        default=str,
    ).lower()
    command_observes_link = any(token in args_text for token in (
        "ln -s ",
        "ln -sf ",
        "readlink ",
        "symlink(",
    ))
    setup_observes_link = any(
        str(item.get("kind", "")).lower() in {
            "symlink",
            "symbolic_link",
            "special_file",
        }
        or "symlink" in str(item.get("type", "")).lower()
        for item in _setup_items(benchmark_case)
    )
    if command_observes_link or setup_observes_link:
        return False, ""
    return (
        True,
        "The label depends on a symlink or special filesystem object, but the "
        "case provides neither observable setup nor a command that creates or "
        "inspects that object.",
    )


def suggested_fix(
    record: dict[str, Any],
    *,
    insufficient: bool,
) -> str:
    if insufficient:
        return (
            "Extend the benchmark schema with workspace_setup describing the "
            "link path, target, and object type; do not infer it from prose."
        )

    expected = str(record.get("expected_action", "")).lower()
    actual = str(record.get("actual_action", "")).lower()
    tool = str(record.get("tool", "")).lower()
    category = (
        f"{record.get('category', '')} "
        f"{record.get('subcategory', '')}"
    ).lower()
    args_text = json.dumps(
        record.get("args", {}),
        ensure_ascii=False,
        default=str,
    ).lower()

    if expected == "deny" and actual != "deny":
        if tool == "run_command":
            return (
                "Add a content-derived hard rule for the observed shell "
                "primitive: remote execution, reverse shell, substitution, "
                "decoder, sensitive redirection, privilege change, or "
                "interpreter-driven execution."
            )
        if tool in {"send_email", "http_request"} and any(
            marker in args_text for marker in (
                "ghp_",
                "xox",
                "eyj",
                "postgresql://",
                "mysql://",
                "aiza",
                "/etc/passwd",
            )
        ):
            return (
                "Expand secret and sensitive-content recognition at external "
                "sinks; keep this as a hard deny independent of task budget."
            )
        if "ssrf" in category or "metadata" in category:
            return (
                "Recognize the observed metadata host or payload-bearing URL "
                "and re-check normalized hosts, redirects, and resolved IPs."
            )
        if "path" in category or "路径" in category:
            return (
                "Normalize overlong and repeated encodings before traversal "
                "and sensitive-target checks."
            )
        return (
            "Add a deterministic feature based on tool arguments or observed "
            "runtime state, not the case id or expected label."
        )

    if expected == "allow" and actual == "ask":
        if tool == "run_command":
            return (
                "Classify explicitly requested read-only inspection and test "
                "commands as low inherent risk when no dangerous shell "
                "primitive is present."
            )
        if tool == "http_request":
            return (
                "Reduce risk for authorized public HTTPS GET/HEAD requests; "
                "keep state-changing requests and private targets gated."
            )
        if tool == "send_email":
            return (
                "Configure the benchmark's declared internal mail domain and "
                "keep unknown or external recipients at Ask."
            )
        return (
            "Reduce task-budget friction for an authorized workspace-local "
            "operation while retaining sensitive-path and secret hard rules."
        )

    if expected == "ask" and actual == "deny":
        if tool == "run_command":
            return (
                "Replace source-only denial with Ask when low-trust context "
                "controls a command that has side effects but no dangerous "
                "content-derived primitive."
            )
        return (
            "Preserve explicit confirmation semantics for authorized but "
            "side-effecting operations unless a hard security condition is "
            "observable."
        )

    if expected == "ask" and actual == "allow":
        return (
            "Add an Ask boundary for the observable side effect. If the tool "
            "and arguments do not perform the described action, fix the "
            "benchmark tool call instead of adding a prose-based policy rule."
        )
    return "Review the case and add an observable, content-derived rule."


def analyze(
    failures: list[dict[str, Any]],
    benchmark: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    pair_counts: Counter[str] = Counter()
    category_counts: dict[str, Counter[str]] = defaultdict(Counter)
    subcategory_counts: dict[str, Counter[str]] = defaultdict(Counter)
    reason_counts: dict[str, Counter[str]] = defaultdict(Counter)
    enriched: list[dict[str, Any]] = []

    for failure in failures:
        pair = error_pair(failure)
        pair_counts[pair] += 1
        category = str(failure.get("category", "unknown"))
        subcategory = str(failure.get("subcategory", "unknown"))
        category_counts[category][pair] += 1
        subcategory_counts[subcategory][pair] += 1
        for reason in failure.get("reasons", []):
            reason_counts[str(reason)][pair] += 1

        source_case = benchmark.get(str(failure.get("id")), {})
        insufficient, insufficient_reason = insufficient_observable_state(
            failure,
            source_case,
        )
        enriched.append({
            **failure,
            "error_pair": pair,
            "suggested_fix": suggested_fix(
                failure,
                insufficient=insufficient,
            ),
            "insufficient_observable_state": insufficient,
            "insufficient_observable_reason": insufficient_reason,
        })

    return {
        "total_failures": len(failures),
        "error_pairs": dict(pair_counts.most_common()),
        "by_category": {
            key: dict(value.most_common())
            for key, value in sorted(category_counts.items())
        },
        "by_subcategory": {
            key: dict(value.most_common())
            for key, value in sorted(subcategory_counts.items())
        },
        "reason_distribution": {
            key: {
                "total": sum(value.values()),
                "by_error_pair": dict(value.most_common()),
            }
            for key, value in sorted(
                reason_counts.items(),
                key=lambda item: (-sum(item[1].values()), item[0]),
            )
        },
        "insufficient_observable_state_count": sum(
            item["insufficient_observable_state"] for item in enriched
        ),
        "failures": enriched,
    }


def _group_table(groups: dict[str, dict[str, int]]) -> str:
    lines = ["| Group | Total | Error distribution |", "|---|---:|---|"]
    for name, values in groups.items():
        distribution = ", ".join(
            f"{pair}: {count}" for pair, count in values.items()
        )
        lines.append(
            f"| {name.replace('|', '/')} | {sum(values.values())} | "
            f"{distribution} |"
        )
    return "\n".join(lines)


def render_markdown(analysis: dict[str, Any]) -> str:
    pair_rows = "\n".join(
        f"| {pair} | {count} |"
        for pair, count in analysis["error_pairs"].items()
    )
    reason_rows = "\n".join(
        f"| `{reason}` | {value['total']} | "
        f"{', '.join(f'{pair}: {count}' for pair, count in value['by_error_pair'].items())} |"
        for reason, value in analysis["reason_distribution"].items()
    )
    insufficient = [
        item for item in analysis["failures"]
        if item["insufficient_observable_state"]
    ]
    insufficient_rows = "\n".join(
        f"| `{item['id']}` | {item.get('description', '')} | "
        f"{item['insufficient_observable_reason']} |"
        for item in insufficient
    ) or "| - | None | - |"
    failure_rows = "\n".join(
        f"| `{item['id']}` | {item['error_pair']} | "
        f"{str(item.get('subcategory', '')).replace('|', '/')} | "
        f"{'yes' if item['insufficient_observable_state'] else 'no'} | "
        f"{item['suggested_fix'].replace('|', '/')} |"
        for item in analysis["failures"]
    )
    return f"""# Benchmark Failure Analysis

## Summary

- Total failures: {analysis['total_failures']}
- Insufficient observable state: {
    analysis['insufficient_observable_state_count']
  }

| Expected / Actual | Count |
|---|---:|
{pair_rows}

## Category Distribution

{_group_table(analysis['by_category'])}

## Subcategory Distribution

{_group_table(analysis['by_subcategory'])}

## Reason Distribution

| Reason | Total | Error distribution |
|---|---:|---|
{reason_rows}

## Insufficient Observable State

These cases cannot be safely hard-denied from the current tool arguments and
runtime setup. The benchmark should provide an observable filesystem object.

| Case | Description | Why state is insufficient |
|---|---|---|
{insufficient_rows}

## Suggested Fixes

| Case | Error | Subcategory | Insufficient state | Suggested fix |
|---|---|---|---|---|
{failure_rows}
"""


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--failures",
        type=Path,
        default=Path(
            "reports/benchmark_jsonl/full_ct_trm_failures.jsonl"
        ),
    )
    parser.add_argument(
        "--benchmark",
        type=Path,
        default=Path(
            "benchmarks/agent_tool_bench/cases/benchmark.jsonl"
        ),
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path("reports/benchmark_jsonl"),
    )
    args = parser.parse_args()

    failures = load_jsonl(args.failures)
    benchmark = load_benchmark(args.benchmark)
    analysis = analyze(failures, benchmark)
    args.output_dir.mkdir(parents=True, exist_ok=True)
    (args.output_dir / "failure_analysis.json").write_text(
        json.dumps(analysis, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    (args.output_dir / "failure_analysis.md").write_text(
        render_markdown(analysis),
        encoding="utf-8",
    )
    print(json.dumps({
        "failures": analysis["total_failures"],
        "insufficient_observable_state": (
            analysis["insufficient_observable_state_count"]
        ),
        "output_dir": str(args.output_dir),
    }, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
