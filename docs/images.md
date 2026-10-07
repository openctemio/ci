# Images

| Image | Tools | Capabilities |
|---|---|---|
| `ghcr.io/openctemio/ci-semgrep` | semgrep | `sast` |
| `ghcr.io/openctemio/ci-trivy` | trivy | `sca`, `iac`, `container` |
| `ghcr.io/openctemio/ci-betterleaks` | betterleaks | `secrets` |
| `ghcr.io/openctemio/ci` | all of them | all |

Each image is the tool plus the same `openctem-ci` binary, with
`ENTRYPOINT ["openctem-ci"]`. No nuclei, no recon tools.

## Tags

- `edge`, `sha-<commit>`: built from `main` (and rebuilt weekly for base-image fixes);
- `vX.Y.Z`, `vX`: releases.

Pin a digest in your pipeline (`ghcr.io/openctemio/ci-semgrep@sha256:...`).
The GitHub Action and the reusable workflow resolve the tag to its digest,
verify the signature and run exactly that digest.

## Supply chain

- **Pinned inputs.** Every base and tool image is pinned by digest
  (`scripts/check-image-pins.sh` refuses a tag-only `FROM` and keeps one pin
  per image across the Dockerfiles). trivy and betterleaks come from their
  official images; semgrep and its dependencies are installed with
  `pip --require-hashes` from `images/semgrep/requirements.txt`.
- **Automatic bumps.** Dependabot proposes tool, base-image, Python, Go and
  action updates weekly; each PR builds and smoke-tests every image.
- **Signed.** Every published index and platform image is signed with cosign,
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
- No package installer in the semgrep images (pip removed after install).
- Network: the platform (`OPENCTEM_API_URL`), the semgrep rule registry
  (sast, unless `--semgrep-config` names rules in the repository), the trivy
  vulnerability and check databases (sca, iac, container; cache them), and
  the image registry for `container`. Nothing else.
