# Images

| Image | Tools | Capabilities |
|---|---|---|
| `ghcr.io/openctemio/ci-opengrep` | opengrep | `sast` (default) |
| `ghcr.io/openctemio/ci-semgrep` | semgrep | `sast` |
| `ghcr.io/openctemio/ci-trivy` | trivy | `sca`, `iac`, `container` |
| `ghcr.io/openctemio/ci-betterleaks` | betterleaks | `secrets` |
| `ghcr.io/openctemio/ci` | opengrep (with the OpenCTEM rules pack), trivy, betterleaks | all |

Each image is the tool plus the same `openctem-ci` binary, with
`ENTRYPOINT ["openctem-ci"]`. No nuclei, no recon tools.

## Tags

- `edge`, `sha-<commit>`: built from `main` (and rebuilt weekly for base-image
  fixes). The binary reports `<VERSION>+<commit>`, the release named in
  `VERSION` with the commit as build metadata; the platform compares it as
  that release.
- `vX.Y.Z`, `vX`: releases (`v0` for the 0.x releases). A release tag is not
  a new build: it points at the signed `main` digests the tagged commit pins
  (`images.lock`), whose binary reports that release.

## Releasing

The GitLab templates and the examples pin image digests, and a pipeline
that includes a template from a release tag runs the digests pinned in that
tag's commit. So the pins are refreshed before the tag, never after:

1. Merge the changes for the release into `main`, with `VERSION` set to the
   new `vX.Y.Z` and every usage reference (`openctemio/ci@vX.Y.Z`,
   `.../ci/vX.Y.Z/gitlab/...`) changed to it; wait for the image build of
   that commit.
2. `scripts/pin-images.sh sha-<that commit>`: verifies each signature and
   that each binary reports `vX.Y.Z`, rewrites every image reference to
   `ghcr.io/openctemio/<image>:vX.Y.Z@sha256:<digest>` and writes
   `images.lock`. `scripts/check-release-refs.sh` (CI runs it) checks that
   `VERSION`, the usage references, the image tags and `images.lock` agree.
   Merge.
3. Tag that commit `vX.Y.Z`. The image workflow checks the references again
   (`images.lock` must name `vX.Y.Z`), verifies each pinned digest's
   signature and version, signs it again under the tag's own identity (the
   GitHub Action accepts a `vX.Y.Z` image only with that signature), and
   points `vX.Y.Z` and `vX` at exactly those digests: the templates, the
   examples and the GitHub Action run one binary.

Between steps 1 and 2 the usage references already name the new release
while the templates still pin the previous one (`images.lock` says which);
nobody runs `main`'s templates, and the tag is refused until they agree.

Pin a digest in your pipeline (`ghcr.io/openctemio/ci-opengrep@sha256:...`).
The GitHub Action and the reusable workflow resolve the tag to its digest,
verify the signature and run exactly that digest.

## Supply chain

- **Pinned inputs.** Every base and tool image is pinned by digest
  (`scripts/check-image-pins.sh` refuses a tag-only `FROM` and keeps one pin
  per image across the Dockerfiles). trivy and betterleaks come from their
  official images; semgrep and its dependencies are installed with
  `pip --require-hashes` from `images/semgrep/requirements.txt`. opengrep is
  the release's binary, pinned by version and SHA-256 per architecture, and
  its keyless signature is verified with cosign against the opengrep
  release workflow of that version at build time (no Python, no installer).
  `ci-opengrep` and `ci` carry the same opengrep and rules pack pins: the
  pin check also keeps every `*_VERSION` and `*_SHA256*` build argument
  identical across the Dockerfiles that set it.
  The OpenCTEM rules pack (`/opt/openctem/sast-rules`) is a release of
  openctemio/sast-rules whose signature bundle is verified at build time
  against that repository's release workflow at the exact tag.
- **Automatic bumps.** Dependabot proposes tool, base-image, Python, Go and
  action updates weekly; each PR builds and smoke-tests every image.
- **Signed.** Every published index and platform image is signed with cosign
  (verify with cosign v3; older versions report no signatures),
  keyless: the certificate names `.github/workflows/images.yml` of
  `openctemio/ci` at `refs/heads/main` or a `v*` tag.

  ```sh
  cosign verify ghcr.io/openctemio/ci-trivy@sha256:<digest> \
    --certificate-oidc-issuer https://token.actions.githubusercontent.com \
    --certificate-identity-regexp '^https://github\.com/openctemio/ci/\.github/workflows/images\.yml@refs/(heads/main|tags/v[0-9.]+)$'
  ```

- **SBOM and provenance.** Each platform image carries a BuildKit SBOM and a
  max-mode provenance attestation (`docker buildx imagetools inspect
  <image> --format '{{ json .SBOM }}'`).
- **Multi-arch.** `linux/amd64` and `linux/arm64`, each built natively.

## Runtime hardening

- Non-root (uid 1001, the GitHub-hosted runner user, so the checkout is
  writable without chown). Run with `--user "$(id -u):$(id -g)"` elsewhere.
- Works with a read-only root filesystem: give it a tmpfs for `/tmp` and
  `$HOME` (`/home/openctem`), as the smoke test and the GitHub Action do.
- No package installer in the semgrep images (pip removed after install);
  none in the opengrep image at all. The opengrep runtime is unpacked at
  build time (`XDG_CACHE_HOME=/opt/opengrep/cache`) and runs read-only.
- Network: the platform (`OPENCTEM_API_URL`), the rule registry (sast, only
  when `--sast-rules` names a registry pack such as `p/default`; the default
  OpenCTEM rules pack is in the image
  does; rules in the repository need no network), the trivy
  vulnerability and check databases (sca, iac, container; cache them), and
  the image registry for `container`. Nothing else.
