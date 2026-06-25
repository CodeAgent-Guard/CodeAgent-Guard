# Objective CT-TRM Evaluation Report

## Why The Existing Benchmark Is Not Enough

The fixed `benchmark.jsonl` and generated holdout sets are useful regression
checks, but they are still controlled by this repository. High scores there can
come from dataset construction choices, repeated templates, or Ask/Deny
boundary calibration. This report adds more objective checks that do not expose
CT-TRM internals to case authors or reviewers.

## Policy Snapshot

- Snapshot file: `reports\objective_eval\policy_snapshot.json`
- Git commit: `79f0de15f3942a29b8002ca3165b6c3ae84921e5`
- Policy snapshot hash: `fe9481859311f10776dfc0d77d529819467f5e68c69d8b1e1c6380e685e6de59`
- Results after policy change: `False`
- Changed policy files after snapshot: `none`

## Data Use

- `blind_llm_test`: blind case set; not used for tuning.
- dual-review files: intended for independent human labels; CT-TRM output is
  hidden from reviewers.
- leave-one-category-out: held-out category slices; no threshold or rule changes
  during evaluation.
- `real_agent_e2e`: adapter-level Agent emits real ToolProxy calls with a mock
  executor; not used for tuning.
- `external_redteam`: independent red-team submission interface and local sample
  submissions; not used for tuning.

## Dataset Results

| Dataset | Cases | Accuracy | Intervention | Strong Block / Deny | Complete FN / E2E Success | Normal Disruption / FP | Macro F1 | Failures |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| blind_llm_test | 200 | 66.5% | 100.0% | 90.0% | 0.0% | 37.5% | 64.72% | 67 |
| real_agent_e2e | 40 | 67.5% | 100.0% | 80.0% | 0.0% | 40.0% | 67.67% | 13 |
| external_redteam | 40 | 65.0% | 100.0% | 62.16% | 0.0% | 0.0% | 35.56% | 14 |

## Benchmark Reference

Reference source: `reports\generalization\benchmark_jsonl_external_fixed.json`

| Dataset | Cases | Accuracy | Intervention | Strong Block | Complete FN | Normal Disruption | Macro F1 | Failures |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| benchmark_jsonl_reference | 473 | 96.83% | 98.86% | 98.58% | 1.14% | 6.78% | 94.03% | 15 |

## Label Agreement

- Total cases: 200
- Reviewed cases: 0
- Agreement count: 0
- Disagreement count: 0
- Incomplete count: 200
- Agreement rate: None

If reviewer files are blank, agreement is intentionally reported as unavailable
instead of inferred from CT-TRM output.

## Real Agent End-to-End

- Task completion rate: 60.0%
- Attack trigger rate: 100.0%
- Guard intervention rate: 100.0%
- End-to-end attack success rate: 0.0%
- False positive rate: 40.0%
- Ask rate: 22.5%
- Deny rate: 55.0%
- P95 policy latency: 8.607 ms

## Leave-One-Category-Out Summary

Categories evaluated: 21

Lowest-accuracy categories:

- `G. 符号链接与特殊文件攻击`: accuracy 85.71%, cases 28, failures 4
- `E. 工具输出污染`: accuracy 90.0%, cases 30, failures 3
- `A. 正常任务 (Benign)`: accuracy 90.91%, cases 55, failures 5
- `C. 多轮诱导攻击`: accuracy 96.67%, cases 30, failures 1
- `F. 路径穿越攻击`: accuracy 97.5%, cases 40, failures 1
- `D. 间接提示注入`: accuracy 98.0%, cases 50, failures 1
- `benign_normal_workflow`: accuracy 100.0%, cases 151, failures 0
- `legitimate_side_effect_requires_consent`: accuracy 100.0%, cases 110, failures 0
- `ssrf_and_private_network`: accuracy 100.0%, cases 92, failures 0
- `context_pollution`: accuracy 100.0%, cases 86, failures 0

## Red-Team Failure Analysis

- `user_confirmation_required`: 10
- `ct_trm_risk_score`: 9
- `insecure_transport`: 5
- `external_recipient`: 5
- `untrusted_context_requires_confirmation`: 5

## Results Lower Than `benchmark.jsonl`

- blind_llm_test accuracy 66.5% < benchmark 96.83%
- external_redteam accuracy 65.0% < benchmark 96.83%

## Current Failure Categories

- `benign_development`: 30
- `gray_user_confirmation`: 30
- `secret_exfiltration`: 12
- `ssrf_bypass`: 9
- `normal_development_task`: 6
- `gray_confirmation_task`: 4
- `attack_task`: 3

## Overfitting Signal

An overfitting signal is present if the fixed benchmark remains high while
blind, red-team, or real-agent results drop materially. The rows above should be
read together with the policy snapshot; if `results_after_policy_change` is
true, results must be regenerated before drawing conclusions.

## Limitations

- This does not prove protection against all unknown attacks.
- The blind LLM set is still not a third-party standard benchmark.
- The external red-team sample size is limited unless more third-party
  submissions are added.
- Real Agent behavior can vary with model/provider choices; this runner uses a
  scripted adapter-level Agent to make results reproducible.
- The wording of any public claim should stay bounded to these datasets and
  should not imply universal coverage.

## Careful Conclusion

The cautious claim is: CT-TRM retains measurable intervention behavior across
several non-calibration evaluation paths in this repository, while remaining
subject to independent labeling, larger third-party red-team submissions, and
more diverse real Agent executions.
