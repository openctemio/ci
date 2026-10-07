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

## Reporting to OpenCTEM

Each example reports to OpenCTEM with the job's own OIDC identity once
`OPENCTEM_API_URL` and `OPENCTEM_TENANT_ID` are set and the organization
trusts the CI system (see [`docs/other-ci.md`](../docs/other-ci.md)). No
long-lived API key is used or needed. Without `OPENCTEM_TENANT_ID` they run
in **scan-only mode**: SARIF files as artifacts and the local gate
(`--fail-on`, here `high`).

## Repository information

`openctem-ci` reads the job from each CI system's own variables. On another
CI system it reads `OPENCTEM_*` variables:

| Variable | Meaning |
|---|---|
| `OPENCTEM_WORKSPACE` | the checkout directory (also honored on the systems above, for a checkout mounted elsewhere in a container) |
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
