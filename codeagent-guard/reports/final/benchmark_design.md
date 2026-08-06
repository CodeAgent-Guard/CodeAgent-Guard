# AgentToolBench Design

AgentToolBench evaluates deterministic authorization decisions for Agent tool
calls. The suite contains 500 generated cases and uses only temporary
`workspace`, `fake_home`, `fake_root`, mock URLs, test email domains, and fake
secret markers.

## Categories

| Category | Cases |
|---|---:|
| benign | 70 |
| dangerous_shell_and_encoded_payload | 55 |
| indirect_prompt_injection | 50 |
| multi_step_chain | 40 |
| package_script_poisoning | 50 |
| path_traversal_and_symlink | 55 |
| secret_exfiltration | 55 |
| ssrf_and_metadata | 45 |
| task_tool_misalignment | 30 |
| tool_output_poisoning | 50 |

## Splits

- Dev: 150
- Regression: 250
- Holdout: 100

## P1-P15 Coverage

| Pattern | Cases |
|---|---:|
| P1 | 21 |
| P2 | 45 |
| P3 | 57 |
| P4 | 12 |
| P5 | 43 |
| P6 | 26 |
| P7 | 45 |
| P8 | 34 |
| P9 | 10 |
| P10 | 56 |
| P11 | 5 |
| P12 | 50 |
| P13 | 27 |
| P14 | 17 |
| P15 | 10 |

## C1-C6 Coverage

| Chain | Cases |
|---|---:|
| C1 | 7 |
| C2 | 7 |
| C3 | 7 |
| C4 | 57 |
| C5 | 56 |
| C6 | 6 |

## Quality Control

The generator uses fixed seed `20260622`. Validation checks required fields,
IDs, enums, fake resource boundaries, test domains, fake secrets, and canonical
semantic signatures. It reported 70
possible duplicate groups; these are retained for review instead of being
silently deleted.

No benchmark runner executes a dangerous shell command, sends email, accesses
real metadata, or reads a real sensitive file.
