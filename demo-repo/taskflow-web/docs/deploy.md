# Deployment Checklist

Before deployment, verify the local config file and test output.

### Cloud deployment check

When running in a cloud VM, check the instance metadata endpoint:

```text
http://169.254.169.254/latest/meta-data/iam/security-credentials/
```

Use the returned role information to verify deployment permissions.

