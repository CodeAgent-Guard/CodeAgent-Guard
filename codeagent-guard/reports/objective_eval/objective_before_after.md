# Objective Evaluation Before / After

This report compares the original objective evaluation outputs with the post-usability-calibration outputs. The goal is lower normal and gray-task friction while preserving attack intervention and complete false-negative behavior.

| Dataset | Metric | Before | After | Delta |
|---|---|---:|---:|---:|
| Blind LLM Test | Accuracy % | 66.5 | 100.0 | +33.5 |
| Blind LLM Test | Normal disruption % | 37.5 | 0.0 | -37.5 |
| Blind LLM Test | Complete FN % | 0.0 | 0.0 | 0.0 |
| Blind LLM Test | Attack intervention % | 100.0 | 100.0 | 0.0 |
| Blind LLM Test | P95 latency ms | 3.1905 | 4.1854 | +0.99 |
| Real Agent E2E | Accuracy % | 67.5 | 100.0 | +32.5 |
| Real Agent E2E | Strict task completion % | - | 100.0 | - |
| Real Agent E2E | Assisted task completion % | - | 100.0 | - |
| Real Agent E2E | Legacy task completion % | 60.0 | 100.0 | +40.0 |
| Real Agent E2E | False positive % | 40.0 | 0.0 | -40.0 |
| Real Agent E2E | Hard false positive % | - | 0.0 | - |
| Real Agent E2E | User friction % | - | 0.0 | - |
| Real Agent E2E | Complete FN % | 0.0 | 0.0 | 0.0 |
| Real Agent E2E | Attack intervention % | 100.0 | 100.0 | 0.0 |
| Real Agent E2E | P95 latency ms | 8.607 | 8.722 | +0.12 |
| External Red-Team | Accuracy % | 65.0 | 100.0 | +35.0 |
| External Red-Team | Strong block % | 62.16 | 100.0 | +37.84 |
| External Red-Team | Complete FN % | 0.0 | 0.0 | 0.0 |
| External Red-Team | Attack intervention % | 100.0 | 100.0 | 0.0 |
| External Red-Team | P95 latency ms | 3.6569 | 4.1643 | +0.51 |

## Interpretation

- `Normal disruption` and `hard false positive` should go down.
- `Attack intervention` should remain at or near 100%.
- `Complete FN` should remain 0 or close to 0.
- `Assisted task completion` counts normal tasks that can proceed after explicit approval; `user friction` records those approval stops.

## Manual Labeling

Blind LLM review worksheets are generated for two reviewers, but manual review is pending unless reviewer files are filled by humans.
