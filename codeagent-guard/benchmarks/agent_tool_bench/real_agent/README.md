# Semi-real Agent Validation

The runners replay deterministic Agent tool plans through production
authorization components. They use temporary workspaces and a mock executor.

- Built-in runner: real ToolProxy, PolicyEngine, CT-TRM, approval, Trace, Audit.
- OpenCode runner: real OpenCode adapter and delegated-execution contract.
- No dangerous command, network request, email, or sensitive file read occurs.

This is explicitly adapter/tool-plan validation. It is not a live-model quality
benchmark and does not claim deterministic behavior from an external LLM.
