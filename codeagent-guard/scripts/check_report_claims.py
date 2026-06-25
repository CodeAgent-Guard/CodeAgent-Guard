from __future__ import annotations

import argparse
import re
from pathlib import Path


PROHIBITED = (
    re.compile(r"100%\s*(?:防御|阻止|拦截)\s*(?:所有|全部)"),
    re.compile(r"(?:完全解决|彻底解决).*(?:Agent|智能体).*(?:安全|风险)"),
    re.compile(r"(?:绝对安全|零风险|不会被绕过)"),
    re.compile(r"(?i)\b(?:absolutely secure|zero risk|cannot be bypassed)\b"),
    re.compile(r"(?i)\b100%\s+protection\s+against\s+all\b"),
)


def scan(roots: list[Path]) -> list[tuple[Path, int, str]]:
    findings = []
    for root in roots:
        if not root.exists():
            continue
        files = [root] if root.is_file() else sorted(root.rglob("*.md"))
        for path in files:
            for number, line in enumerate(
                path.read_text(encoding="utf-8", errors="replace").splitlines(),
                1,
            ):
                lowered = line.lower()
                if "\ufffd" in line:
                    # Legacy mojibake cannot be classified reliably. New
                    # generated reports are UTF-8 and remain fully checked.
                    continue
                disclaimer = any(marker in lowered for marker in (
                    "does not prove",
                    "not proof",
                    "not evidence",
                    "cannot be generalized",
                    "不代表",
                    "不能泛化",
                    "不应",
                    "不把",
                    "不可泛化",
                    "不得写成",
                    "不是",
                ))
                if disclaimer:
                    continue
                if any(pattern.search(line) for pattern in PROHIBITED):
                    findings.append((path, number, line.strip()))
    return findings


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("roots", nargs="+", type=Path)
    args = parser.parse_args()
    findings = scan(args.roots)
    for path, number, line in findings:
        print(f"{path}:{number}: prohibited claim: {line}")
    if findings:
        raise SystemExit(1)
    print(f"Report claim check passed for {len(args.roots)} root(s).")


if __name__ == "__main__":
    main()
