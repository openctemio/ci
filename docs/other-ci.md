# Azure Pipelines, Bitbucket Pipelines, CircleCI and Jenkins

`openctem-ci` reports to OpenCTEM from these CI systems the same way it does
from GitHub Actions and GitLab CI: the job proves who it is with an OIDC token
its CI system issues, the platform checks it against the organization's CI
trust and returns a run token that lives at most 15 minutes. No API key or
other secret is stored in CI. Ready-to-use pipelines: [`examples/`](../examples/).

Every pipeline needs two variables, neither of them a secret:

| Variable | Value |
|---|---|
| `OPENCTEM_API_URL` | the OpenCTEM URL (https) |
| `OPENCTEM_TENANT_ID` | your OpenCTEM organization id; without it the job scans only |

and a **CI trust** in OpenCTEM (CI/CD > Trust and gate > Add trust) for the
CI organization, workspace or Jenkins issuer. The trust dialog can check a
sample token from a job before you save it.

| CI system | Where the token comes from | What the job reports itself |
|---|---|---|
| Azure Pipelines | `openctem-ci` asks `$(System.OidcRequestUri)` with the job's `$(System.AccessToken)` (map it into the step as `SYSTEM_ACCESSTOKEN`). No service connection. | nothing |
| Bitbucket Pipelines | `BITBUCKET_STEP_OIDC_TOKEN` (`oidc: true` on the step, the audience under `options.oidc.audiences`) | the repository name and the commit |
| CircleCI | `OPENCTEM_ID_TOKEN`, minted in the job with `circleci run oidc get --claims '{"aud":"openctem:tenant:<id>"}'` | the commit (`CIRCLE_SHA1`) |
| Jenkins | `OPENCTEM_ID_TOKEN`, bound from an "OpenID Connect id token" credential of the OpenID Connect Provider plugin | the commit, unless the `sha` claim template is set |

## What to know per system

**Azure Pipelines.** The token's audience is always
`api://AzureADTokenExchange`; the platform pins it to your organization id
and accepts each token once. Azure mints a token on request, so a long job
renews its run token. Every pull request build is refused unless the trust
admits pull request builds: the token cannot tell a fork's pull request from
your own.

**Bitbucket Pipelines.** The audience must contain your OpenCTEM organization
id (the workspace's own audience is shared by every service that trusts the
workspace). The token signs the repository's UUID, not its name: the trust
lists repositories by UUID, and the name the job reports stays bound to the
UUID that first used it. The trust also pins the workspace UUID.

**CircleCI.** The ready-made `CIRCLE_OIDC_TOKEN` and `CIRCLE_OIDC_TOKEN_V2`
carry the CircleCI organization id as their audience and are refused; mint
one for OpenCTEM as in the example. The token signs no commit: the run's
commit is the job's report, shown as unverified, and a break-glass never
applies to it. A job re-run with SSH is refused.

**Jenkins.** Install the OpenID Connect Provider plugin and add its claim
templates (Manage Jenkins > Security > OpenID Connect):
`repository` = `${GIT_URL}`, `branch` = `${BRANCH_NAME}` (or `${GIT_BRANCH}`),
`sha` = `${GIT_COMMIT}`. Create the credential with the audience
`openctem:tenant:<your organization id>`, scoped to the folders whose jobs
may report. A controller OpenCTEM cannot reach sets the credential's issuer
URI to a static https location and publishes the two files Jenkins shows
there. Multibranch pull request builds (`PR-<n>`) are refused unless the
trust admits them.

## Security

- No stored secret. The CI system's token is good for one exchange and is
  never printed: `openctem-ci` keeps it and the run token out of logs and
  errors (the Azure access token too).
- The platform takes the repository, ref and commit from the verified token;
  what a job reports fills only what its token does not sign, and is marked.
- A change from a fork (Azure `SYSTEM_PULLREQUEST_ISFORK`, CircleCI
  `CIRCLE_PR_NUMBER`, Jenkins `CHANGE_FORK`) scans without uploading or
  using a token.

## Why there is no API key fallback for Jenkins

A credential stored in Jenkins and exchanged for a run token would be an API
key by another name: anyone who can read it can report as any of its
pipelines until it is rotated. The plugin's tokens are short-lived, minted
per build and signed by a key Jenkins never shares; a Jenkins that cannot
run the plugin uses scan-only mode.
