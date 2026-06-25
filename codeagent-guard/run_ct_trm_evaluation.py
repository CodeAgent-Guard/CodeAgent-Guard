#!/usr/bin/env python3
from __future__ import annotations

import json
from pathlib import Path

from guard.ct_trm_evaluation import CTTRMEvaluationService


ROOT = Path(__file__).resolve().parent
service = CTTRMEvaluationService(
    ROOT / "benchmarks" / "agent_tool_bench" / "ct_trm_cases.yaml",
    ROOT / "reports",
)
print(json.dumps(service.run(), ensure_ascii=False, indent=2))
