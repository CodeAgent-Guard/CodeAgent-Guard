# CT-TRM Generalization Report

## Purpose

This report checks whether CT-TRM behavior remains stable outside the fixed
`benchmark.jsonl` set. The goal is to detect overfitting to individual cases,
fixed wording, or a narrow Ask/Deny boundary.

## Split Usage

- `dev_calibration`: generated calibration set; this is the only split allowed
  for rule calibration and threshold exploration.
- `benchmark_jsonl_external_fixed`: the existing `benchmark.jsonl`, marked as
  `external_fixed_test`. It is not a training set.
- `holdout_generated`: generated holdout with different carriers, commands,
  paths, recipients, and URL variants. It is used only for final validation.
- `redteam_unseen`: stronger bypass set used only for final validation.

## Summary

| Dataset | Cases | Accuracy | Attack Intervention | Strong Block | Complete FN | Deny Miss | Normal Disruption | Overblock | DENY F1 | Macro F1 | P95 ms | Failures |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| dev_calibration | 300 | 97.33% | 100.0% | 100.0% | 0.0% | 0.0% | 0.0% | 0.0% | 100.0% | 96.32% | 5.206 | 8 |
| benchmark_jsonl_external_fixed | 473 | 96.83% | 98.86% | 98.58% | 1.14% | 1.42% | 6.78% | 8.06% | 98.58% | 94.03% | 3.1194 | 15 |
| holdout_generated | 300 | 99.33% | 100.0% | 100.0% | 0.0% | 0.0% | 0.0% | 0.0% | 100.0% | 98.98% | 4.7347 | 2 |
| redteam_unseen | 150 | 100.0% | 100.0% | 100.0% | 0.0% | 0.0% | 0.0% | 0.0% | 100.0% | 33.33% | 3.2751 | 0 |

## Interpretation

Across the non-calibration datasets, CT-TRM kept attack intervention in the
range 98.86%-100.0% and complete false negative rate in the range
0.0%-1.14%. This does not claim generalization to all unknown attacks; it shows
that the current rules retain behavior across several deterministic datasets
that did not participate in calibration.

Fixed benchmark vs holdout accuracy delta: -2.5 percentage points. If the fixed benchmark improves while holdout or red-team drops, treat that as an overfit signal rather than proof of generalization.

Red-team unseen coverage includes double encoding, IPv6 and decimal IP forms, redirect and DNS-private SSRF, symlink chains, environment expansion, command substitution, chunked secrets, attachment exfiltration, and indirect package scripts.

The red-team split is intentionally DENY-only. Its three-class Macro F1 is therefore less informative than strong block rate and DENY F1 for that split.

## Threshold Sensitivity

- Recommended ask_threshold: `25`
- Recommended deny_threshold: `60`
- Recommendation score: `80.5553`
- Robust regions: 24
- Overfit-risk regions: 0

The recommendation is based on dev, holdout, and red-team performance rather
than optimizing the external fixed benchmark alone.

Detailed failure files are under `failures_by_dataset/`; category breakdowns are under `category_breakdown/`.
