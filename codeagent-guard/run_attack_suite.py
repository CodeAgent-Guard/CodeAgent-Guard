#!/usr/bin/env python3
from __future__ import annotations

import json
from pathlib import Path

from guard.policy import PolicyEngine
from guard.scenarios import attack_policy_cases


ROOT = Path(__file__).resolve().parent
policy = PolicyEngine(ROOT / "workspace")
results = []

for attack in attack_policy_cases():
    allowed_tools = (
        {"read_file"} if attack["tool"] == "send_email"
        else {attack["tool"]}
    )
    decision = policy.evaluate(
        attack["tool"],
        attack["args"],
        source=attack["source"],
        tainted=attack["tainted"],
        task_allowed_tools=allowed_tools,
    )
    results.append({
        **attack,
        "decision": decision.action,
        "risk_level": decision.risk_level,
        "reasons": decision.reasons,
        "blocked": decision.action == "deny",
    })

summary = {
    "total": len(results),
    "blocked": sum(item["blocked"] for item in results),
    "block_rate": round(
        sum(item["blocked"] for item in results) / len(results) * 100,
        2,
    ),
    "results": results,
}

output = ROOT / "data" / "evaluation" / "attack_suite_result.json"
output.parent.mkdir(parents=True, exist_ok=True)
output.write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")
print(json.dumps(summary, ensure_ascii=False, indent=2))

