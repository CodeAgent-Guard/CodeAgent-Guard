# AgentToolBench

AgentToolBench is a deterministic, local-only benchmark for Agent tool-call
authorization. JSON is used inside `.yaml` files so the suite remains valid
YAML while requiring only Python's standard library.

Safety constraints:

- Files are limited to temporary `workspace`, `fake_home`, and `fake_root`.
- URLs use test domains or mock private/metadata targets and are never fetched.
- Email addresses use test domains and are never delivered.
- Commands are policy inputs only and are never executed by benchmark runners.
- Secrets use explicit benchmark markers and must not be copied to Trace/Audit.

Dataset splits:

- `dev_calibration.jsonl` (`split=dev_calibration`): generated calibration
  set used to tune general rules and inspect threshold behavior.
- `benchmark.jsonl` (`split=external_fixed_test`): externally supplied fixed
  test set. It is not a training set and must not be used for case-specific
  rules.
- `holdout_generated.jsonl` (`split=holdout_generated`): deterministic holdout
  generated with different carriers, paths, URLs, commands, and recipients from
  the fixed benchmark. It is used only for final validation.
- `redteam_unseen.jsonl` (`split=redteam_unseen`): stronger bypass set covering
  double encoding, IPv6 and decimal IP forms, redirect and DNS-private SSRF,
  symlink chains, environment expansion, command substitution, chunked secrets,
  attachment exfiltration, and indirect package scripts. It is used only for
  final validation.

Overfitting controls:

- Guard code must not branch on benchmark IDs, expected labels, or the
  `benchmark.jsonl` path.
- Threshold recommendations are selected from dev, holdout, and red-team
  behavior rather than by optimizing the external fixed test alone.
- Benchmark runners never execute shell commands, send email, fetch real
  network URLs, or read real sensitive files.

Generate and validate:

```bash
python -m benchmarks.agent_tool_bench.generators.generate_ct_trm_cases \
  --output benchmarks/agent_tool_bench/cases/ct_trm_500.yaml \
  --count 500 --seed 20260622

python -m benchmarks.agent_tool_bench.generators.validate_cases \
  --cases benchmarks/agent_tool_bench/cases/ct_trm_500.yaml \
  --output reports/ct_trm/validation_report.json

python -m benchmarks.agent_tool_bench.generators.generate_generalization_sets \
  --output-dir benchmarks/agent_tool_bench/cases
```
