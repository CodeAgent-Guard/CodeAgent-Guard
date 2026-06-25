# CT-TRM Rule Change Log

This log records rule and evaluation changes made for the benchmark calibration
and generalization validation work. No final guard rule is classified as
`benchmark_specific`.

| change_id | changed_file | change_type | affected_categories | reason | expected_generalization | benchmark_specific_risk |
|---|---|---|---|---|---|---|
| CTTRM-RULE-001 | `guard/taint.py` | general_pattern | dangerous shell, encoded payload | Expand shell normalization and dangerous-command detection for interpreters, command substitution, decoder pipelines, env hijack, remote script execution, and destructive primitives. | Applies to command structure rather than fixed sample text. | low |
| CTTRM-RULE-002 | `guard/risk_patterns.py` | general_pattern | direct attack, secret exfiltration, SSRF | Add hard-deny patterns for observable dangerous shell, external secret sinks, metadata/private HTTP targets, and command-substitution exfiltration. | Applies to tool arguments and normalized entities across datasets. | low |
| CTTRM-RULE-003 | `guard/policy.py` | general_pattern | Ask/Deny boundary, normal workflow | Keep external side effects at Ask while retaining hard-deny for secrets, metadata, sensitive paths, and dangerous shell. | Reduces normal disruption without relaxing critical hard rules. | low |
| CTTRM-RULE-004 | `guard/evaluation_ct_trm.py` | bug_fix | symlink/special file | Simulate observable symlink realpaths from `workspace_setup` and do not treat prose-only descriptions as filesystem evidence. | Measures only observable state in any generated or external dataset. | low |
| CTTRM-RULE-005 | `guard/task_budget.py` | general_pattern | task/tool alignment | Broaden safe read-only/test-command recognition so low-risk diagnostics do not become Ask/Deny by budget alone. | Uses command class and task capability, not sample IDs. | low |
| CTTRM-RULE-006 | `guard/risk_model.py` | threshold_adjustment | score-to-action mapping | Expose Ask/Deny score thresholds for sensitivity scans while keeping default values and hard-deny precedence unchanged. | Allows robustness analysis across datasets without changing hard rules. | low |
| CTTRM-EVAL-001 | `guard/evaluation_ct_trm.py` | bug_fix | metrics | Add canonical metric names: `complete_false_negative_rate`, `deny_miss_rate`, `strong_block_rate`, and `normal_task_disruption_rate`. | Prevents report ambiguity across all datasets. | low |
| CTTRM-EVAL-002 | `benchmarks/agent_tool_bench/generators/generate_generalization_sets.py` | general_pattern | generalization datasets | Generate dev, holdout, and unseen red-team sets with fake local resources and mock-only network/email behavior. | Exercises new combinations and carriers without referencing fixed benchmark cases. | low |
| CTTRM-EVAL-003 | `guard/evaluation_generalization.py` | bug_fix | reporting | Add split-level generalization reports, category breakdowns, and failure files. | Makes fixed benchmark, generated holdout, and unseen red-team results comparable. | low |
| CTTRM-EVAL-004 | `scripts/threshold_sensitivity.py` | threshold_adjustment | robustness | Scan Ask/Deny score boundaries and mark overfit-risk vs robust regions. | Recommendation uses dev + holdout + red-team behavior, not fixed benchmark alone. | low |
| CTTRM-EVAL-005 | `scripts/check_no_benchmark_overfit.py` | bug_fix | overfit control | Fail if guard decision files contain fixed case IDs, expected-label logic, or benchmark-path special casing. | Enforces rule-level separation from benchmark labels and file names. | low |
