#!/usr/bin/env python3
from pathlib import Path

from guard.evaluation import EvaluationService
from guard.policy import PolicyEngine


ROOT = Path(__file__).resolve().parent
service = EvaluationService(
    PolicyEngine(ROOT / "workspace"),
    ROOT / "data" / "evaluation",
)
result = service.generate()
print(f"generated={result['generated']}")
print(f"path={result['path']}")

