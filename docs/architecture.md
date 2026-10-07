# openctem-ci architecture

`openctem-ci` runs one scan capability in a CI job and reports it to
OpenCTEM. It is the CI half of the platform's scanning: the sensor daemon
runs long-lived, platform-dispatched scans; CI jobs run this binary in a
small per-tool image. Both produce the same CTIS reports.

## Flow of `openctem-ci scan`

```
CI job ── checkout ──▶ openctem-ci scan --capability sast
                         │ 1. read the CI environment (repository, branch, commit, PR/MR, fork)
                         │ 2. resolve the target inside the workspace (symlinks followed)
                         │ 3. run the tool (fixed argv, filtered env, private temp dir, timeout)
                         │ 4. convert its native output to CTIS (ctis/importer)
                         │ 5. scope: one repository asset, repository-relative paths
                         │ 6. redact: mask secrets everywhere, then check every output
                         │ 7. write SARIF / GitLab report / CTIS / status file
                         │ 8. exchange the job's OIDC token for a run token, upload
                         └ 9. ask the platform gate for the verdict (or the local gate)
```

Exit codes: `0` pass (or no gate asked), `1` the gate failed, `2` the scan
cannot be trusted (tool, parse, upload, redaction or configuration error).
A broken scan never exits 0.

## Capabilities

Users choose capabilities, never images or tools. The one mapping is
`internal/capability/capability.go`; its ids are the platform capability
taxonomy ids (`ctis/capability`), checked by a test.

| Name | Capability id | Tool | Image | GitLab report |
|---|---|---|---|---|
| `sast` | `sast.code@1` | semgrep | `ghcr.io/openctemio/ci-semgrep` | `sast` |
| `sca` | `sca.deps@1` | trivy (`fs`, vulnerabilities) | `ghcr.io/openctemio/ci-trivy` | `dependency_scanning` |
| `secrets` | `secrets.code@1` | betterleaks | `ghcr.io/openctemio/ci-betterleaks` | `secret_detection` |
| `iac` | `iac.misconfig@1` | trivy (`config`) | `ghcr.io/openctemio/ci-trivy` | `sast` |
| `container` | `container.image@1` | trivy (`image`) | `ghcr.io/openctemio/ci-trivy` | `container_scanning` |

`all` selects every repository capability (`container` needs `--image` and is
never implied). `ghcr.io/openctemio/ci` carries every tool.

## Identity: OIDC only

A job proves who it is with its CI provider's OIDC token (GitHub Actions
`id-token: write`; GitLab `id_tokens` with the trust configuration's
audience, default `openctem:tenant:<tenant id>`; Azure Pipelines from
`System.OidcRequestUri`; Bitbucket `BITBUCKET_STEP_OIDC_TOKEN`; CircleCI and
Jenkins a token minted or bound into `OPENCTEM_ID_TOKEN`, see
[other-ci.md](other-ci.md)). `openctem-ci` exchanges it
at `POST /api/v1/ci/oidc/exchange` for a run token (`octci_`, at most 15
minutes) bound to one run on one repository. No API key is stored in CI.

- The run token stays inside `internal/platform`: never printed, logged or
  part of an error; `String()` redacts it.
- The platform URL must be https (plain http only for localhost); redirects
  are not followed, so the bearer cannot be sent to another host.
- The repository, branch and commit of a run come from the verified token
  on the platform, not from the report.
- Where the token signs no commit (CircleCI, Jenkins without a `sha`
  claim) or no repository name (Bitbucket), the exchange carries the job's
  own value; the platform uses it only then and marks it.
- GitHub and Azure mint a token on request, so a long job renews its run
  token; elsewhere the job's single token is exchanged once.
- A CI system without OIDC runs in scan-only mode: SARIF, reports and the
  local gate, no upload.

## Aggregate run

A pipeline that runs several capability jobs in parallel reports into one
platform run: each job calls `scan --aggregate`, and a final job calls
`gate`. The exchange carries `aggregate: true`; the platform finds or opens
the run shared by every job of the same pipeline run (same pipeline,
commit and attempt) and gives each job its own token for it. Only `gate`
asks for the verdict, on everything the jobs uploaded.

Scan jobs hand a status file (`<capability>.status.json`: ok, pushed, counts
per severity, no finding text) to the gate job as a CI artifact. A
capability that is expected but missing, failed or not uploaded counts as a
scan failure, and any scan failure fails the gate (fail closed).

A platform that does not answer `aggregate: true` is refused
(`ErrNoAggregate`): otherwise the gate job would judge an empty run and pass.

## Threat model

| Threat | Control |
|---|---|
| A fork pull/merge request exfiltrates the platform credential or uploads forged results | A fork is detected from the event (GitHub: head repository differs or is a fork; GitLab: source project differs) and never uploads or uses a credential; GitHub gives forks no OIDC token; the platform trust refuses forks by default |
| A long-lived key leaks from CI settings or logs | No key exists: OIDC per job, short-lived run token, never printed |
| A scanned repository runs code through the tool's environment | The tool gets an allow-listed environment (no OIDC request token, ID token, job token, platform or API key); the tool is resolved only from absolute PATH entries |
| A raw secret reaches the platform, an artifact or the log | Secret scanner output goes to a private 0700 temp dir, removed after the run; every finding is masked (`ctis.RedactSecretFinding` with the raw values); every output is checked for the raw values before it is written or sent, and the run stops instead (`ErrSecretInOutput`); SARIF and GitLab reports carry no snippet; the secret scanner is never run with `--verbose` |
| A report names another repository or a path outside the checkout | The target must resolve inside the workspace; the report keeps one repository asset; paths outside the repository are cleared; the platform re-validates (`ScopeReport`) |
| Hostile tool output (huge, deep, malformed) | Bounded reads (512 MB), `ctis/importer` limits; a parse error is a scan failure |
| Platform or scanner text forges CI log lines | Control characters and `::` workflow-command prefixes are removed before printing |
| Option injection through user input | Fixed argument lists, no shell; image references and semgrep configs that start with `-` are refused |
| A broken scan turns the pipeline green | Every failure exits 2 and is recorded as a scan failure on the run; the gate job counts missing statuses |

## Local gate

`--fail-on <severity>` is the offline fallback: it decides only when the
platform's verdict is unavailable (scan-only mode, platform unreachable).
Unknown severities block, and a finding that is actively exploited (KEV) or
has a known exploit blocks below the threshold.

## Dependencies

Only `github.com/openctemio/ctis` (CTIS types, importers, redaction,
capability taxonomy), pinned to a commit on its `main` branch
(`.github/scripts/check-deps-on-main.sh`).
