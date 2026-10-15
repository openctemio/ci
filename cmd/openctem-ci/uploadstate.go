package main

import (
	"context"
	"errors"
	"fmt"
	"regexp"

	"github.com/openctemio/ctis"

	"github.com/openctemio/ci/internal/platform"
	"github.com/openctemio/ci/internal/redact"
	"github.com/openctemio/ci/internal/scanner"
)

// Upload states of a status file.
const (
	uploadDone    = "uploaded"
	uploadFailed  = "not_uploaded"
	uploadSkipped = "skipped"
)

// classRe is the shape of an upload reason or error class: a short fixed
// word, never free text (it travels to the platform with the verdict).
var classRe = regexp.MustCompile(`^([a-z][a-z0-9_]{0,31})?$`)

func validUploadState(s string) bool {
	switch s {
	case "", uploadDone, uploadFailed, uploadSkipped:
		return true
	}
	return false
}

// uploadClass is why an upload failed, as a fixed word: http_<status>,
// refused, timeout or network.
func uploadClass(err error) string {
	var se *platform.StatusError
	switch {
	case errors.As(err, &se):
		return fmt.Sprintf("http_%d", se.Status)
	case errors.Is(err, platform.ErrRefused):
		return "refused"
	case errors.Is(err, context.DeadlineExceeded):
		return "timeout"
	}
	return "network"
}

// errorClass is the kind of a scan failure, as a fixed word. The full
// message stays in the job log and the status file's error.
func errorClass(err error) string {
	var cre *cannotReportError
	switch {
	case errors.As(err, &cre):
		return cre.class
	case errors.Is(err, redact.ErrSecretInOutput):
		return "redaction_failed"
	case errors.Is(err, scanner.ErrTimeout):
		return "timeout"
	case errors.Is(err, scanner.ErrCacheInCheckout):
		return "cache_in_checkout"
	}
	return "scan_failed"
}

// capabilityState is how the capability of a status ended, for the verdict
// request.
func (st status) capabilityState() platform.CapabilityState {
	cs := platform.CapabilityState{Name: st.Capability, Tool: st.Tool}
	switch {
	case !st.OK && st.Partial:
		cs.State, cs.Reason = "partial", st.ErrorClass
	case !st.OK:
		cs.State, cs.Reason = "failed", st.ErrorClass
	case st.Upload == uploadDone || st.Pushed:
		cs.State = "uploaded"
	default:
		cs.State, cs.Reason = uploadFailed, st.UploadReason
	}
	return cs
}

// markPartial labels a report as what a failed tool found before failing:
// partial coverage (the platform never resolves anything from it) and the
// failure, so it can never be read as a clean scan.
func markPartial(r *ctis.Report, class string) {
	r.Metadata.CoverageType = "partial"
	if r.Metadata.Properties == nil {
		r.Metadata.Properties = ctis.Properties{}
	}
	r.Metadata.Properties["openctem_scan_state"] = "failed"
	r.Metadata.Properties["openctem_scan_error"] = class
}

// failPartial uploads what a failed tool found, marked partial, and fails
// the scan. The results are not written to the job's reports: they are
// incomplete, and the job fails anyway.
func (s *scanJob) failPartial(ctx context.Context, report *ctis.Report, toolErr error) int {
	if s.pr != nil {
		if _, err := s.pr.Upload(ctx, report); err != nil {
			s.warnf("the partial results could not be uploaded to OpenCTEM: %v", err)
			s.status.Upload, s.status.UploadReason = uploadFailed, uploadClass(err)
		} else {
			s.status.Upload, s.status.Partial = uploadDone, true
			s.logf("[%s] %d result(s) found before the failure were uploaded, marked partial", s.c.Name, len(report.Findings))
		}
	}
	return s.fail(ctx, toolErr)
}
