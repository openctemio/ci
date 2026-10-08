# GitLab CI

Templates in `gitlab/templates/`:

| Template | Jobs |
|---|---|
| `all.yml` | `openctem-sast`, `openctem-sca`, `openctem-secrets`, `openctem-iac` in parallel, reported into one OpenCTEM run, and `openctem-gate` (stage `.post`) judging them once |
| `sast.yml`, `sca.yml`, `secrets.yml`, `iac.yml` | one job each, judged on its own |
| `container.yml` | `openctem-container`: scans `$OPENCTEM_SCAN_IMAGE` (runs only when it is set) |

## Use

```yaml
include:
  - remote: https://raw.githubusercontent.com/openctemio/ci/v0.1.0/gitlab/templates/all.yml

variables:
  OPENCTEM_API_URL: https://openctem.example.com
  OPENCTEM_TENANT_ID: <organization id>
```

Pin the include to a release tag (or a commit), never `main`. The templates
are self-contained files, so they can also be copied into a project or
mirrored to a GitLab project for the CI/CD Catalog.

| Variable | Meaning |
|---|---|
| `OPENCTEM_API_URL`, `OPENCTEM_TENANT_ID` | report to OpenCTEM (OIDC; no stored key) |
| `OPENCTEM_FAIL_ON` | local gate threshold when the platform gate cannot decide |
| `OPENCTEM_SCAN_ARGS` | extra `openctem-ci scan` flags, e.g. `--target services/api` or `--semgrep-config p/golang` |
| `OPENCTEM_SCAN_IMAGE` | image to scan (`container.yml`) |
| `OPENCTEM_DISABLED` | `"true"` turns every job off |

## What GitLab shows

Each job writes the GitLab security report of its capability
(`artifacts:reports`: `sast`, `dependency_scanning`, `secret_detection`,
`container_scanning`; infrastructure as code as `sast`), schema 15.2.5, so
findings appear in the merge request security widget and the pipeline
security tab. A SARIF file and the job status are kept as artifacts.

## Identity

Each job requests an ID token with `id_tokens: OPENCTEM_ID_TOKEN` and the
audience `openctem:tenant:$OPENCTEM_TENANT_ID`, and `openctem-ci` exchanges it
once for a run token of at most 15 minutes. Add a GitLab trust configuration
in OpenCTEM (**CI/CD > Trust and gate**) for your GitLab issuer.
A merge request from a fork never uploads (the job scans only).

## Rules

The jobs run in merge request pipelines and in branch pipelines, and not
twice for a branch with an open merge request.

## Cache

The trivy jobs cache the vulnerability database in `.openctem-trivy-cache/`
(`cache:key: openctem-trivy-db`), excluded from the scan.

## Rollout

Exit codes: 0 pass, 1 the gate failed, 2 a scan cannot be trusted. To report
without blocking while findings are triaged, set on the job (or on
`openctem-gate` with `all.yml`):

```yaml
openctem-gate:
  allow_failure:
    exit_codes: [1]
```

## Tested

`scripts/gitlab-local-test.sh` runs `all.yml` as a pipeline with
gitlab-ci-local on `testdata/fixture` and validates every report against the
published schemas; the Self-test workflow runs it on every change.
