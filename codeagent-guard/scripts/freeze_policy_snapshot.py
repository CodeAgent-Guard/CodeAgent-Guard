from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
from datetime import datetime, timezone
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
POLICY_FILES = [
    "guard/policy.py",
    "guard/risk_model.py",
    "guard/risk_patterns.py",
    "guard/taint.py",
    "guard/chain_risk.py",
    "guard/task_budget.py",
]


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _git(args: list[str]) -> str:
    try:
        return subprocess.check_output(
            ["git", *args],
            cwd=ROOT,
            text=True,
            stderr=subprocess.DEVNULL,
        ).strip()
    except Exception:
        return "unknown"


def build_snapshot() -> dict:
    files = {}
    for relative in POLICY_FILES:
        path = ROOT / relative
        files[relative] = {
            "sha256": _sha256(path),
            "size_bytes": path.stat().st_size,
        }
    canonical = json.dumps(files, sort_keys=True, separators=(",", ":"))
    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "git_commit": _git(["rev-parse", "HEAD"]),
        "git_status_short": _git(["status", "--short"]),
        "policy_files": files,
        "policy_snapshot_hash": hashlib.sha256(
            canonical.encode("utf-8")
        ).hexdigest(),
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("reports/objective_eval/policy_snapshot.json"),
    )
    args = parser.parse_args()
    snapshot = build_snapshot()
    output = args.output if args.output.is_absolute() else ROOT / args.output
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(
        json.dumps(snapshot, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    print(json.dumps({
        "output": str(output),
        "policy_snapshot_hash": snapshot["policy_snapshot_hash"],
        "git_commit": snapshot["git_commit"],
    }, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
