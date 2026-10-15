package main

import (
	"errors"
	"fmt"
	"strings"

	"github.com/openctemio/ci/internal/platform"
)

// envEnforce is the explicit opt-out of failing closed: OPENCTEM_ENFORCE=false
// lets a job that is configured to report (OPENCTEM_TENANT_ID is set) but
// cannot (no OIDC token, no API URL) run as a scan only, with a warning.
const envEnforce = "OPENCTEM_ENFORCE"

// enforced reports whether a reporting misconfiguration fails the job. Only
// the exact value "false" (any case) turns it off; anything else, including
// a typo, keeps the safe default.
func enforced(getenv func(string) string) bool {
	return !strings.EqualFold(strings.TrimSpace(getenv(envEnforce)), "false")
}

// cannotReportError is a job that names a tenant but cannot report. Short
// is what the status file keeps; Error is the full explanation with the fix.
type cannotReportError struct {
	short string
	long  string
}

func (e *cannotReportError) Error() string { return e.long }

// reportingError explains why a job that has a tenant id cannot report to
// OpenCTEM, with the fix for each CI system.
func reportingError(err error, idTokenVar string) error {
	if errors.Is(err, platform.ErrNoOIDC) {
		return &cannotReportError{short: "not uploaded: the job has no OIDC token", long: fmt.Sprintf("%s is set but this job has no OIDC token, so nothing can be reported to OpenCTEM. "+
			"Fix: GitHub Actions: grant 'permissions: id-token: write' to the job; "+
			"GitLab CI: add 'id_tokens: %s: aud: <the trust configuration's audience>' to the job; "+
			"Azure Pipelines: map SYSTEM_ACCESSTOKEN: $(System.AccessToken); Bitbucket: 'oidc: true' on the step; "+
			"CircleCI, Jenkins: put the job's token in %s (docs/other-ci.md). "+
			"To run as a scan only, unset %s, pass --no-push, or set %s=false",
			platform.EnvTenantID, idTokenVar, idTokenVar, platform.EnvTenantID, envEnforce)}
	}
	return &cannotReportError{short: "not uploaded: reporting to OpenCTEM is not configured", long: fmt.Sprintf("%s is set but reporting to OpenCTEM is not available: %v. "+
		"To run as a scan only, unset %s, pass --no-push, or set %s=false",
		platform.EnvTenantID, err, platform.EnvTenantID, envEnforce)}
}
