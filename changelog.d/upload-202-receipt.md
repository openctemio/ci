### Changed: uploads wait for the platform to apply them

- When the platform answers an upload with `202 Accepted`, `scan` and `upload` poll the upload (`GET /api/v1/ci/runs/{id}/results/{upload_id}?wait=10`, bounded by `OPENCTEM_UPLOAD_TIMEOUT`) and report the counts and decided results as before. A failed upload names the platform's reason code; a poll that cannot finish leaves the upload stored with an incomplete list of decided results.
- The verdict request retries `503 INGEST_PENDING` honouring `Retry-After` until `OPENCTEM_GATE_WAIT` (default 10 minutes, `0` to `60m`) is used up.

### Upgrade notes

- Works with platforms that answer `201` and with those that answer `202`; no pipeline change.
