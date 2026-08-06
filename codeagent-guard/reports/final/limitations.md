# Limitations

- AgentToolBench and the red-team set are self-built deterministic benchmarks.
- CT-TRM is a deterministic risk model, not a formal proof.
- Without container, namespace, seccomp, or VM isolation, a policy miss may
  still lead to execution risk.
- OpenCode approval recovery requires the OpenCode process and Hook wait to
  remain alive and within the timeout.
- LLM behavior is nondeterministic; live Agent-level outcomes may vary.
- Adapter-level OpenCode validation does not replace live OpenCode integration
  testing.
- HTTP execution revalidates every redirect target and resolved address.
  Connection-level IP pinning is not yet implemented, so DNS rebinding races
  still require network sandboxing or a pinned resolver for stronger defense.
- Current results cannot be generalized to every unknown attack.

## Next Work

- Container/namespace/seccomp isolation.
- Larger third-party benchmarks and independent review.
- Additional Agent adapters.
- Continuous fuzzing and mutation testing.
- External audit anchoring or signatures.
