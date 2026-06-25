from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import re
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any
from urllib.parse import urlparse


REQUIRED_FIELDS = {
    "id",
    "category",
    "subcategory",
    "severity",
    "split",
    "user_task",
    "attack_vector",
    "workspace_setup",
    "expected_guard_decision",
    "expected_risk_level",
    "expected_reasons",
    "expected_ct_trm_features",
    "expected_taint_flow",
    "expected_chain_risk",
    "false_positive_probe",
    "safe_execution",
    "success_criteria",
    "notes",
}
ENUMS = {
    "severity": {"low", "medium", "high", "critical"},
    "expected_risk_level": {"low", "medium", "high", "critical"},
    "split": {"dev", "regression", "holdout"},
    "expected_guard_decision": {"allow", "ask", "deny"},
}
ALLOWED_EMAIL_DOMAINS = {
    "example.test",
    "company.test",
    "cornpany.test",
    "evil.test",
    "codeguard.local",
}
ALLOWED_HOSTS = {
    "localhost",
    "127.0.0.1",
    "0.0.0.0",
    "::1",
    "10.0.0.5",
    "172.16.0.1",
    "192.168.1.1",
    "169.254.169.254",
    "2130706433",
    "0177.0.0.1",
    "metadata.test",
}
SAFE_SECRET_MARKERS = {
    "FAKE_API_KEY_FOR_BENCHMARK_ONLY",
    "FAKE_PRIVATE_KEY_FOR_BENCHMARK_ONLY",
    "FAKE_BEARER_TOKEN_FOR_BENCHMARK",
    "FAKE_PASSWORD_FOR_BENCHMARK",
    "BENCHMARK_SECRET_MARKER",
    "BENCHMARK_BASE64_PAYLOAD",
    "BENCHMARK_MARKER",
}
EMAIL_RE = re.compile(
    r"(?i)\b[A-Z0-9._%+-]+@([A-Z0-9.-]+\.[A-Z]{2,63}|codeguard\.local)\b"
)
URL_RE = re.compile(r"(?i)\bhttps?://[^\s\"'<>]+")
SECRET_LIKE_RE = re.compile(
    r"(?i)(?:\bsk-[A-Za-z0-9_-]{8,}\b|"
    r"\bAKIA[0-9A-Z]{16}\b|"
    r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----)"
)


def load_cases(path: Path) -> list[dict]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, list):
        raise ValueError("benchmark root must be a list")
    return data


def _walk(value: Any):
    if isinstance(value, dict):
        for key, item in value.items():
            yield key, item
            yield from _walk(item)
    elif isinstance(value, list):
        for item in value:
            yield from _walk(item)


def _all_text(case: dict) -> str:
    return json.dumps(case, ensure_ascii=False, sort_keys=True)


def _tool_call(case: dict) -> dict:
    call = case.get("expected_tool_call")
    if isinstance(call, dict):
        return call
    sequence = case.get("expected_sequence") or []
    return sequence[-1] if sequence else {}


def _target_type(call: dict) -> str:
    args = call.get("args") or {}
    target = str(
        args.get("path")
        or args.get("source")
        or args.get("url")
        or args.get("to")
        or args.get("cmd")
        or ""
    ).lower()
    markers = (
        ("fake_home", "fake_home"),
        ("fake_root", "fake_root"),
        ("metadata", "metadata"),
        ("127.0.0.1", "loopback"),
        ("localhost", "loopback"),
        (".github/workflows", "persistence"),
        ("example.test", "external_test"),
        ("workspace", "workspace"),
    )
    for marker, name in markers:
        if marker in target:
            return name
    return "other"


def canonical_signature(case: dict) -> str:
    call = _tool_call(case)
    vector = case.get("attack_vector") or {}
    signature = {
        "category": case.get("category"),
        "subcategory": case.get("subcategory"),
        "tool": call.get("tool"),
        "target_type": _target_type(call),
        "reasons": sorted(case.get("expected_reasons") or []),
        "attack_type": vector.get("type"),
        "features": sorted(case.get("expected_ct_trm_features") or []),
    }
    return hashlib.sha256(
        json.dumps(signature, sort_keys=True).encode()
    ).hexdigest()[:20]


def validate_cases(cases: list[dict]) -> dict:
    errors: list[dict] = []
    warnings: list[dict] = []
    ids: set[str] = set()
    signatures: dict[str, list[str]] = defaultdict(list)

    for index, case in enumerate(cases):
        case_id = str(case.get("id") or f"index-{index}")
        missing = sorted(REQUIRED_FIELDS - set(case))
        if missing:
            errors.append({
                "id": case_id,
                "type": "missing_fields",
                "fields": missing,
            })
        if not case.get("expected_tool_call") and not case.get("expected_sequence"):
            errors.append({
                "id": case_id,
                "type": "missing_tool_call_or_sequence",
            })
        if case_id in ids:
            errors.append({"id": case_id, "type": "duplicate_id"})
        ids.add(case_id)
        for field, values in ENUMS.items():
            if case.get(field) not in values:
                errors.append({
                    "id": case_id,
                    "type": "invalid_enum",
                    "field": field,
                    "value": case.get(field),
                })
        if not case.get("safe_execution"):
            errors.append({"id": case_id, "type": "unsafe_execution_flag"})

        text = _all_text(case)
        for match in EMAIL_RE.finditer(text):
            domain = match.group(1).lower()
            if not any(
                domain == allowed or domain.endswith(f".{allowed}")
                for allowed in ALLOWED_EMAIL_DOMAINS
            ):
                errors.append({
                    "id": case_id,
                    "type": "non_test_email_domain",
                    "domain": domain,
                })
        for match in URL_RE.finditer(text):
            raw = match.group(0).rstrip(".,;:)}]")
            host = (urlparse(raw).hostname or "").lower()
            try:
                private_ip = ipaddress.ip_address(host).is_private
            except ValueError:
                private_ip = False
            if not (
                host in ALLOWED_HOSTS
                or host.rstrip(".") in ALLOWED_HOSTS
                or private_ip
                or host.endswith(".example.test")
                or host.endswith(".evil.test")
                or host.endswith(".company.test")
            ):
                errors.append({
                    "id": case_id,
                    "type": "non_mock_url",
                    "url": raw,
                })
        for match in SECRET_LIKE_RE.finditer(text):
            if not any(marker in match.group(0) for marker in SAFE_SECRET_MARKERS):
                errors.append({
                    "id": case_id,
                    "type": "non_benchmark_secret",
                    "value": "[REDACTED]",
                })

        call = _tool_call(case)
        args_text = json.dumps(call.get("args") or {}, ensure_ascii=False)
        path_like = call.get("tool") in {
            "read_file", "write_file", "list_directory", "search_files",
            "delete_path", "move_path", "make_directory", "open_directory",
        }
        if path_like and args_text:
            allowed_path = any(marker in args_text for marker in (
                "${WORKSPACE}", "${FAKE_HOME}", "${FAKE_ROOT}",
                "workspace", "fake_home", "fake_root", "~/.ssh",
                "C:\\\\fake_home", "$HOME/.ssh",
            ))
            if not allowed_path:
                errors.append({
                    "id": case_id,
                    "type": "path_outside_fake_roots",
                    "args": args_text[:300],
                })
        signatures[canonical_signature(case)].append(case_id)

    duplicates = [
        {"signature": signature, "case_ids": case_ids}
        for signature, case_ids in signatures.items()
        if len(case_ids) > 1
    ]
    for duplicate in duplicates:
        warnings.append({
            "type": "possible_duplicate",
            **duplicate,
        })

    coverage = coverage_report(cases)
    return {
        "valid": not errors,
        "total_cases": len(cases),
        "error_count": len(errors),
        "warning_count": len(warnings),
        "possible_duplicate_groups": len(duplicates),
        "errors": errors,
        "warnings": warnings,
        "coverage": coverage,
    }


def coverage_report(cases: list[dict]) -> dict:
    patterns = Counter()
    chains = Counter()
    tools = Counter()
    sources = Counter()
    categories = Counter()
    decisions = Counter()
    severities = Counter()
    splits = Counter()
    for case in cases:
        categories[case["category"]] += 1
        decisions[case["expected_guard_decision"]] += 1
        severities[case["severity"]] += 1
        splits[case["split"]] += 1
        call = _tool_call(case)
        tools[str(call.get("tool", "unknown"))] += 1
        for feature in case.get("expected_ct_trm_features") or []:
            if re.fullmatch(r"P(?:[1-9]|1[0-5])", feature):
                patterns[feature] += 1
            elif re.fullmatch(r"C[1-6]", feature):
                chains[feature] += 1
        for setup in case.get("workspace_setup") or []:
            if setup.get("kind") == "context":
                sources[str(setup.get("source_type", "unknown"))] += 1
    return {
        "categories": dict(sorted(categories.items())),
        "risk_patterns": {
            f"P{index}": patterns[f"P{index}"] for index in range(1, 16)
        },
        "chain_patterns": {
            f"C{index}": chains[f"C{index}"] for index in range(1, 7)
        },
        "tools": dict(sorted(tools.items())),
        "source_types": dict(sorted(sources.items())),
        "decisions": dict(sorted(decisions.items())),
        "severities": dict(sorted(severities.items())),
        "splits": dict(sorted(splits.items())),
    }


def markdown_report(report: dict, cases_path: Path) -> str:
    coverage = report["coverage"]
    duplicate_lines = [
        f"- `{item['signature']}`: {', '.join(item['case_ids'][:12])}"
        for item in report["warnings"]
        if item["type"] == "possible_duplicate"
    ]
    error_lines = [
        f"- `{item['id']}` `{item['type']}`: "
        f"{json.dumps(item, ensure_ascii=False)}"
        for item in report["errors"]
    ]
    return f"""# AgentToolBench Validation Report

- Cases: `{cases_path}`
- Total: {report['total_cases']}
- Valid: {report['valid']}
- Errors: {report['error_count']}
- Possible duplicate groups: {report['possible_duplicate_groups']}

## Category Distribution

```json
{json.dumps(coverage['categories'], ensure_ascii=False, indent=2)}
```

## Split Distribution

```json
{json.dumps(coverage['splits'], ensure_ascii=False, indent=2)}
```

## P1-P15 Coverage

```json
{json.dumps(coverage['risk_patterns'], ensure_ascii=False, indent=2)}
```

## C1-C6 Coverage

```json
{json.dumps(coverage['chain_patterns'], ensure_ascii=False, indent=2)}
```

## Validation Errors

{chr(10).join(error_lines) if error_lines else 'None.'}

## Possible Semantic Duplicates

These groups are reported for review and are not deleted automatically.

{chr(10).join(duplicate_lines) if duplicate_lines else 'None.'}
"""


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--cases", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    cases = load_cases(args.cases)
    report = validate_cases(cases)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(report, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    markdown = args.output.with_suffix(".md")
    markdown.write_text(
        markdown_report(report, args.cases),
        encoding="utf-8",
    )
    coverage_path = args.output.parent / "coverage_report.json"
    coverage_path.write_text(
        json.dumps(report["coverage"], ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    print(json.dumps({
        "valid": report["valid"],
        "total_cases": report["total_cases"],
        "errors": report["error_count"],
        "duplicate_groups": report["possible_duplicate_groups"],
        "output": str(args.output),
        "coverage": str(coverage_path),
    }, ensure_ascii=False, indent=2))
    if not report["valid"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
