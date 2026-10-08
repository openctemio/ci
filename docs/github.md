# GitHub Actions

Two ways to run OpenCTEM scans in GitHub Actions.

## Reusable workflow: one parallel job per capability (recommended)

```yaml
name: Security
on:
  pull_request:
  push:
    branches: [main]

jobs:
  openctem:
    uses: openctemio/ci/.github/workflows/scan.yml@v0.1.0   # a release tag, or a commit
    with:
      capabilities: sast,sca,secrets,iac
      api-url: https://openctem.example.com
      tenant-id: <organization id>
      upload-sarif: true        # also show findings in GitHub code scanning
    permissions:
      contents: read
      id-token: write           # report with the job's OIDC identity
      security-events: write    # upload-sarif only
```

Every capability runs in its own job and image, in parallel, and reports
into **one** OpenCTEM CI run; a final `gate` job asks the platform gate for
the verdict on all of them. A capability job that fails, is cancelled or does
not upload fails the gate. The workflow runs the action of its own commit
(`job.workflow_sha`), so a release tag such as `@v0.1.0` is fully pinned.

Pin to a full release tag (`vX.Y.Z`) or a commit. By default the images
run with the tag of the action or workflow ref when it is a release tag,
else `edge`; set `image-tag` when you pin to a commit.

## Action: one job

```yaml
jobs:
  openctem:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      id-token: write
    steps:
      - uses: actions/checkout@<sha> # pin actions by commit
        with:
          persist-credentials: false
      - uses: openctemio/ci@v0.1.0   # a release tag, or a commit
        with:
          capabilities: sast,secrets
          api-url: https://openctem.example.com
          tenant-id: <organization id>
```

Several capabilities run in sequence in the job, report into one run and
are judged once.

## Inputs

Inputs of both the action and the reusable workflow:

| Input | Default | |
|---|---|---|
| `capabilities` | `sast,sca,secrets` | `sast`, `sca`, `secrets`, `iac`, `container`, or `all` |
| `api-url`, `tenant-id` | | turn on reporting (OIDC; needs `id-token: write`) |
| `oidc-audience` | `openctem:tenant:<id>` | when the trust configuration uses another audience |
| `target` | `.` | directory to scan, inside the checkout |
| `image` | | image to scan (`container`) |
| `fail-on` | | local gate threshold when the platform gate cannot decide |
| `enforce` | `true` | `false`: a failing gate does not fail the job (a scan error still does) |
| `upload-sarif` | `false` | upload SARIF to GitHub code scanning (`security-events: write`) |
| `image-tag` | the action or workflow version, else `edge` | image tag |
| `scanner-image` | | run this image for every capability instead of the per-tool images (testing a build) |
| `verify-signature` | `true` | resolve the tag to a digest, verify its cosign signature, run the digest |

Inputs of the action only:

| Input | Default | |
|---|---|---|
| `path` | `.` | directory of the checkout, relative to the workspace |
| `semgrep-config` | `p/default` | semgrep rule pack or a path in the repository |
| `aggregate` | `auto` | `auto` (several capabilities report into one run and one gate decides), `true` or `false` |
| `skip-gate` | `false` | with `aggregate`: do not run the gate here (a later job runs `command: gate`) |
| `command` | `scan` | `scan`, or `gate` (judge the status files of earlier capability jobs in `status-dir`) |
| `status-dir` | | `command: gate`: directory, relative to the workspace, holding the `*.status.json` files |

Outputs of the action: `exit-code` (0 pass, 1 gate failed, 2 a scan cannot
be trusted), `sarif-dir`, `status-dir`. The reusable workflow outputs
`exit-code`.

## Security notes

- **No stored key.** The job's OIDC token is exchanged for a run token of at
  most 15 minutes; set up the trust in OpenCTEM (Settings > Scanning > CI
  pipelines). Do not grant `id-token: write` to jobs that do not need it.
- **Forks.** A fork pull request gets no OIDC token from GitHub and is
  detected by `openctem-ci`: it scans only and never uploads. Do not run the
  scan on `pull_request_target` with the fork's code.
- **Isolation.** Each capability runs with `docker run --read-only
  --cap-drop ALL --security-opt no-new-privileges`, as the runner user; the
  checkout is mounted at `/src`, outputs go to `$RUNNER_TEMP/openctem`, and
  the OIDC request variables are passed only when reporting is on.
- **Pinned images.** Images are resolved to a digest and their signature is
  verified against `openctemio/ci`'s image workflow before they run.
