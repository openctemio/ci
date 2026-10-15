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
    uses: openctemio/ci/.github/workflows/scan.yml@v0.3.0   # a release tag, or a commit
    with:
      capabilities: sast,sca,secrets,iac
      api-url: https://openctem.example.com
      tenant-id: <organization id>
      upload-sarif: true        # also show findings in GitHub code scanning
    permissions:
      contents: read
      id-token: write           # report with the job's OIDC identity
      security-events: write    # required, even with upload-sarif: false
```

Every capability runs in its own job and image, in parallel, and reports
into **one** OpenCTEM CI run; a final `gate` job asks the platform gate for
the verdict on all of them. A capability job that fails, is cancelled or does
not upload fails the gate. The workflow runs the action of its own commit
(`job.workflow_sha`), so a release tag such as `@v0.3.0` is fully pinned.

The caller must grant all three permissions: GitHub checks the permissions
of every job of a reusable workflow when it starts, so a missing
`security-events: write` fails the run even when `upload-sarif` is false.
Use the action below for a job without it.

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
      - uses: openctemio/ci@v0.3.0   # a release tag, or a commit
        with:
          capabilities: sast,secrets
          api-url: https://openctem.example.com
          tenant-id: <organization id>
```

Several capabilities run in sequence in the job, report into one run and
are judged once.

On pull requests `sast` is diff-aware: it reports only findings new since
the merge base with the target branch. Check out with `fetch-depth: 0` for
that (the reusable workflow does it for the sast job); with a shallow
checkout the scan runs in full and says so. `diff: off` (or
`OPENCTEM_DIFF=off`) always scans in full. Default-branch runs always scan
in full, which keeps OpenCTEM's baseline complete.

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
| `enforce` | `true` | `false`: a failing gate does not fail the job (a scan error still does), and a job with `tenant-id` but no OIDC token runs as a scan only instead of failing |
| `upload-sarif` | `false` | upload SARIF to GitHub code scanning (`security-events: write`) |
| `image-tag` | the action or workflow version, else `edge` | image tag |
| `scanner-image` | | run this image for every capability instead of the per-tool images (testing a build) |
| `verify-signature` | `true` | resolve the tag to a digest, verify its cosign signature, run the digest |

Inputs of the action only:

| Input | Default | |
|---|---|---|
| `path` | `.` | directory of the checkout, relative to the workspace |
| `sast-rules` | the OpenCTEM rules pack in the image | `openctem` (the image's signed rules pack), a path in the repository, or a registry pack the engine fetches on the runner |
| `semgrep-config` | | deprecated alias of `sast-rules` |
| `aggregate` | `auto` | `auto` (several capabilities report into one run and one gate decides), `true` or `false` |
| `skip-gate` | `false` | with `aggregate`: do not run the gate here (a later job runs `command: gate`) |
| `command` | `scan` | `scan`, or `gate` (judge the status files of earlier capability jobs in `status-dir`) |
| `status-dir` | | `command: gate`: directory, relative to the workspace, holding the `*.status.json` files |
| `ca-bundle` | | self-hosted runners with a private CA: a PEM file in the workspace with every CA the scan must trust ([below](#self-hosted-runners-proxy-and-private-ca)) |

Outputs of the action: `exit-code` (0 pass, 1 gate failed, 2 a scan cannot
be trusted), `sarif-dir`, `status-dir`. The reusable workflow outputs
`exit-code`.

## Security notes

- **No stored key.** The job's OIDC token is exchanged for a run token of at
  most 15 minutes; set up the trust in OpenCTEM (**Discovery > CI/CD > Trust
  and gate**). GitHub Enterprise Server and enterprise issuers are set there
  too (**GitHub Enterprise issuer**). Do not grant `id-token: write` to jobs that do not need it.
- **Forks.** A fork pull request gets no OIDC token from GitHub and is
  detected by `openctem-ci`: it scans only and never uploads. Do not run the
  scan on `pull_request_target` with the fork's code.
- **Isolation.** Each capability runs with `docker run --read-only
  --cap-drop ALL --security-opt no-new-privileges`, as the runner user; the
  checkout is mounted at `/src`, outputs go to `$RUNNER_TEMP/openctem`, and
  the OIDC request variables are passed only when reporting is on.
- **Pinned images.** Images are resolved to a digest and their signature is
  verified against `openctemio/ci`'s image workflow before they run.

## Self-hosted runners: proxy and private CA

The action passes the job's `HTTP_PROXY`, `HTTPS_PROXY` and `NO_PROXY`
(either case) into each scanner container by name, so a proxy URL with
credentials never appears on a command line. For a private CA (a TLS
inspecting proxy, an internal OpenCTEM), commit or create a PEM bundle in
the workspace with every CA the scan must trust, the public roots included,
and set `ca-bundle`:

```yaml
      - uses: openctemio/ci@v0.3.0
        with:
          capabilities: sast,sca,secrets
          ca-bundle: .ci/ca-bundle.pem
```

It is mounted read-only and used for the scanners' downloads (rules,
vulnerability database) and for the upload to OpenCTEM.

The image signature is checked against the build that made it: an image
of release `vX.Y.Z` must be signed by this repository's image workflow at
the tag `vX.Y.Z`, `edge` by its build of `main`.
