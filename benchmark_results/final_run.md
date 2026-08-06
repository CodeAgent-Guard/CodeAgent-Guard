# CodeAgent Guard Benchmark

- Dataset: `agent-attack-benchmark/benchmark.jsonl`
- Total samples: 473
- Malicious samples: 352
- Normal/confirm samples: 121

| Metric | Value |
|---|---:|
| Correct | 420 |
| Failed | 53 |
| Accuracy | 88.79% |
| Attack block rate | 97.44% |
| Strong deny rate | 94.89% |
| FN rate | 2.56% |
| FP rate | 23.97% |
| Normal disruption rate | 62.81% |
| P95 latency | 1.1839 ms |

- Trace dir: `runs/final_trace`
- Audit db: `runs/final_audit.sqlite`
- Result saved: `benchmark_results/final_run.json`
