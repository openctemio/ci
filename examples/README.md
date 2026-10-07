# Examples for other CI systems

| CI system | File | How it runs |
|---|---|---|
| Jenkins | [`jenkins/Jenkinsfile`](jenkins/Jenkinsfile) | `docker run` per capability (agent with Docker), parallel stages |
| Azure Pipelines | [`azure-devops/azure-pipelines.yml`](azure-devops/azure-pipelines.yml) | `docker run` per capability, matrix job |
| Bitbucket Pipelines | [`bitbucket/bitbucket-pipelines.yml`](bitbucket/bitbucket-pipelines.yml) | the bundle image as the step image, parallel steps |
| CircleCI | [`circleci/config.yml`](circleci/config.yml) | the bundle image as the job image, matrix job |

Each runs `sast`, `sca`, `secrets` and `iac` in parallel and then one
`openctem-ci gate` over the status files of all of them: a capability that
failed or did not report fails the gate.

## Scan only, for now

These examples run in **scan-only mode**: SARIF files as artifacts and the
local gate (`--fail-on`, here `high`). They do not upload to OpenCTEM.

OpenCTEM accepts CI results only from a job that proves its identity with an
OIDC token from an issuer the organization trusts; today that is GitHub
Actions and GitLab CI (see `docs/github.md`, `docs/gitlab.md`). No
long-lived API key is used or needed. Bitbucket Pipelines, CircleCI, Azure
Pipelines (workload identity federation) and Jenkins (OIDC provider plugin)
can all issue OIDC tokens; reporting from them needs the platform to trust
those issuers, which is not built yet.

## Repository information

Outside GitHub and GitLab, `openctem-ci` reads the job from `OPENCTEM_*`
variables (the examples set them from the CI system's own variables):

| Variable | Meaning |
|---|---|
| `OPENCTEM_WORKSPACE` | the checkout directory |
| `OPENCTEM_REPOSITORY` | `host/owner/name`, e.g. `bitbucket.org/acme/app` |
| `OPENCTEM_COMMIT`, `OPENCTEM_BRANCH`, `OPENCTEM_DEFAULT_BRANCH` | the revision |
| `OPENCTEM_PULL_REQUEST`, `OPENCTEM_TARGET_BRANCH` | the pull request, if any |
| `OPENCTEM_FORK` | `true` for a change from a fork |

## Hardening used

`docker run --read-only --cap-drop ALL --security-opt no-new-privileges`,
the agent's own user, a tmpfs `/tmp` and `$HOME`, and the checkout mounted
at `/src`. Images are pinned by digest on each release
(`scripts/pin-images.sh`); verify a digest yourself as shown in
`docs/images.md`.
