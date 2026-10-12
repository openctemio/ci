# `.openctem.yml`: a repository's gate settings

A repository can make the OpenCTEM gate **stricter** for itself and ask for
exceptions. The file sits at the repository root (`.openctem.yml` or
`.openctem.yaml`); `openctem-ci` sends its `gate` section with the verdict
request.

```yaml
gate:
  fail_on_severity: medium      # stricter than the organization's threshold only
  new_findings_only: false      # judge every finding, not only new ones
  fail_on_kev: true
  epss_threshold: 0.2           # fail at or above this EPSS score
  block_rules:                  # these rules block even if the policy says comment or monitor
    - go.lang.security.audit.sqli
  exceptions:                   # requests, not suppressions
    - rule_id: go.weak-hash
      path: legacy/**
      reason: legacy module removed in Q1
      expires: 2026-12-31       # at most 90 days ahead
```

- A value applies only when it is stricter than the organization's policy;
  anything looser is ignored. The file can never make a finding pass.
- An exception becomes a **pending suppression request** on the repository in
  OpenCTEM, sent only from default-branch runs (once the file is reviewed and
  merged), once per rule and path. It has no effect until an administrator
  approves it.
- The organization can forbid repository files (`allow_repo_policy: false`
  on a gate policy); the verdict then says the file was ignored.
- A file `openctem-ci` cannot read or parse (unknown keys included, so a
  typo never drops a setting silently) fails the job with exit code 2.

The GitHub reusable workflow checks out only this file for its gate job.
