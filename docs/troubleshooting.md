# Troubleshooting

What a job log says when reporting to OpenCTEM fails, and what to change.
The local reports (SARIF, GitLab report, status file) are written in every
case.

## No OIDC token

`OPENCTEM_TENANT_ID is set but this job has no OIDC token` (exit 2): the job
is configured to report but cannot. It fails instead of passing as a scan
only, so a pipeline never turns green while nothing reached OpenCTEM.

- GitHub Actions: `permissions: id-token: write` on the job.
- GitLab CI: `id_tokens: OPENCTEM_ID_TOKEN: aud: <audience>` on the job (the
  templates set it).
- Azure Pipelines: map `SYSTEM_ACCESSTOKEN: $(System.AccessToken)`.
- Bitbucket: `oidc: true` on the step.
- CircleCI, Jenkins: put the job's token in `OPENCTEM_ID_TOKEN`
  ([other-ci.md](other-ci.md)).

A fork pull request never gets a token and runs as a scan only without this
error. To run a job as a scan only on purpose, unset `OPENCTEM_TENANT_ID`,
pass `--no-push`, or set `OPENCTEM_ENFORCE=false` (`enforce: false` in the
GitHub action). A missing `OPENCTEM_API_URL` fails the same way. The status
file records `upload: not_uploaded` with `upload_reason: no_oidc`.

## trivy cache inside the checkout

`the trivy cache directory is inside the checkout` (exit 2): `TRIVY_CACHE_DIR`
(or `$XDG_CACHE_HOME/trivy`, or `$HOME/.cache/trivy`) points into the scanned
tree. A cache there can be committed by the change under review and would be
trusted as trivy's database, so sca, iac and container scans refuse it.
Remove the variable to use the image's cache directory, or point it outside
the checkout. A pipeline copied from an earlier GitLab template sets
`TRIVY_CACHE_DIR: $CI_PROJECT_DIR/.openctem-trivy-cache` and a `cache:` for it:
drop both ([gitlab.md](gitlab.md#cache)).

## Large reports

A report over 24 MiB or 10 000 findings goes up in parts (`the report was
large and went up in N parts`). `OpenCTEM stored the report, but its full list
of already-decided results could not be read` is a warning, not a failure:
the platform has the results and its verdict is unaffected; the job's own
output may still show some results that are already decided.

## The token exchange

The platform answers a refused token with `401` and a code.

| Code | Meaning | Fix |
|---|---|---|
| `CI_TOKEN_NOT_TRUSTED` | No trust configuration of the organization admitted the token. The reason is not told to the job: on a shared issuer anyone can mint a token, so the configuration is not shown to them | Check `OPENCTEM_TENANT_ID`, that the job's `id_tokens` audience is `openctem:tenant:<that id>` (GitHub: the action sets it), and that a trust configuration admits this issuer, project or repository and ref. An administrator sees the exact rule in **CI/CD > Trust and gate > Recent refused pipelines** and in the audit log (`ci_run.token_refused`) |
| `CI_TOKEN_REPLAY_LIMIT` | The job's token was already exchanged five times (the message gives the first time and the run) | Rerun the job: it gets a new token |
| `CI_TOKEN_REPLAY_RUN_CLOSED` | The token's run already has its verdict, ended or is older than six hours | Rerun the pipeline |
| `CI_TOKEN_REPLAY` | A different token under a token id already used, or a token presented to another organization | Audited at high severity; check who else uses the token |
| `CI_TOKEN_RUN_MISMATCH` | The token asked to continue a run it does not belong to | Do not share run ids between pipelines |
| `CI_TOKEN_PIPELINE_RATE` | The pipeline started 300 or more runs in the last hour | Wait and rerun |
| `CI_TOKEN_PIPELINE_CAP` | The organization or the trust configuration has the most CI pipelines it may have | An administrator retires an unused pipeline |
| `CI_TOKEN_PIPELINE_IDENTITY` | The token carries no repository or project id, or no usable workflow path | Use a provider token that carries them (see [other-ci.md](other-ci.md)) |
| `CI_TOKEN_REPOSITORY_BINDING` | The repository name already reports under another repository id | An administrator retires the old pipeline |
| `CI_TOKEN_OWNER_ID_MISMATCH` | The group or organization name is pinned to another id | An administrator updates the trust configuration |
| `CI_TOKEN_LEGACY_AUDIENCE` | The pipeline already moved to `openctem:tenant:<id>` | Set that audience |
| `RUNNER_OUTDATED` (403) | The pinned `openctemio/ci` release is older than the platform accepts | Change the pin to the release the message names |
| `the platform does not support aggregate runs` | The platform is older than aggregate runs | Update OpenCTEM, or drop `--aggregate` |

`the gitlab OIDC token was already exchanged` comes from openctem-ci v0.3.0
and older: the first exchange of the job failed and the CLI hid why. Update
the pinned release; the log then shows the reason above.

## One run per job

Every `openctem-ci` step of one job shares one run token (stored, private
to the job's user, in the job's temp dir, never in the workspace; see
[architecture](architecture.md)). A job therefore opens one run however
many steps it has. `OPENCTEM_TOKEN_CACHE=off` turns this off.

## Uploads

A failed upload is retried (network errors, 429 with `Retry-After`, 5xx).
When it still fails:

- a scan job with `--aggregate` passes with `THE RESULTS WERE NOT UPLOADED`
  in its log, and the `gate` job uploads its kept report with its own token
  (`Uploaded the <capability> results its job could not upload`);
- a job that is its own gate fails (exit 2) unless `--fail-on` lets the
  local gate decide, or `--on-upload-error warn` is set.
