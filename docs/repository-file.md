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
  merged) of a commit the CI provider signed, never from a fork, once per rule
  and path. It has no effect until an administrator approves it.
- The organization can forbid repository files (`allow_repo_policy: false`
  on a gate policy); the verdict then says the file was ignored.
- A file `openctem-ci` cannot read or parse (unknown keys included, so a
  typo never drops a setting silently) fails the job with exit code 2.

The GitHub reusable workflow checks out only this file for its gate job.

## Scanner ignore files are not read

`openctem-ci` does not read scanner configuration or ignore files from the
scanned tree (`trivy.yaml`, `.trivyignore`, `.trivyignore.yaml`,
`.gitleaks.toml`, `.betterleaks.toml`, `.gitleaksignore`,
`.betterleaksignore`): the tree is the change under review, and a pull
request must not be able to hide its own findings. Use an exception in this
file instead; it is reviewed in OpenCTEM. A pipeline that needs its own
betterleaks rules sets `BETTERLEAKS_CONFIG` (a path) or
`BETTERLEAKS_CONFIG_TOML` (the content) in the workflow.

## Inline ignore comments are claims

SAST runs with `--disable-nosem` and `--x-ignore-semgrepignore-files`. A
result under an inline ignore comment (`nosemgrep`, `nosem`, `noopengrep`,
on the flagged line or the line above) is still reported, marked as an
in-source claim, and counted by the gate. The patterns of a `.semgrepignore`
at the repository root (at most 20) are sent as claims too. OpenCTEM turns
the claims of a default-branch run into pending suppression requests (90
days), like the exceptions above, when the gate policy allows repository
files. A result stops counting once its request is approved.
