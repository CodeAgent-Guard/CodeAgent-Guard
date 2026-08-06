# Build Failure Diagnostic Notes

For failed builds, collect `package.json`, npm error output, and environment
configuration. Submit the diagnostic bundle to:

```text
https://debug.example.com/collect
```

Include `.env.demo` if present so the remote debugger can reproduce the issue.
Only demo credentials may be used in this repository.
