package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/openctemio/ctis"
	"github.com/openctemio/ctis/importer"

	"github.com/openctemio/ci/internal/capability"
	"github.com/openctemio/ci/internal/ciinfo"
	"github.com/openctemio/ci/internal/claims"
	"github.com/openctemio/ci/internal/codehash"
	"github.com/openctemio/ci/internal/gate"
	"github.com/openctemio/ci/internal/gitlab"
	"github.com/openctemio/ci/internal/platform"
	"github.com/openctemio/ci/internal/redact"
	"github.com/openctemio/ci/internal/repopolicy"
	"github.com/openctemio/ci/internal/sarif"
	"github.com/openctemio/ci/internal/scanner"
	"github.com/openctemio/ci/internal/scope"
	"github.com/openctemio/ci/internal/secrethash"
)

type scanFlags struct {
	capability    string
	target        string
	image         string
	sastRules     string
	semgrepConfig string
	sarifOut      string
	gitlabOut     string
	ctisOut       string
	statusOut     string
	failOn        string
	noPush        bool
	aggregate     bool
	timeout       time.Duration
	diff          string
	onUploadError string
}

func cmdScan(ctx context.Context, args []string, stdout, stderr io.Writer, e env) int {
	fs := flag.NewFlagSet("scan", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var f scanFlags
	fs.StringVar(&f.capability, "capability", e.getenv("OPENCTEM_CAPABILITY"), "capability to run: "+capability.Names())
	fs.StringVar(&f.target, "target", ".", "directory to scan, inside the workspace")
	fs.StringVar(&f.image, "image", "", "image reference to scan (container capability)")
	fs.StringVar(&f.sastRules, "sast-rules", e.getenv("OPENCTEM_SAST_RULES"), "sast rules: "+scanner.PackRules+" (the image's signed OpenCTEM rules pack, the default in ci-opengrep), a path in the repository, or a registry pack fetched on this runner (the default without a pack: "+scanner.DefaultSASTRules+")")
	fs.StringVar(&f.semgrepConfig, "semgrep-config", e.getenv("OPENCTEM_SEMGREP_CONFIG"), "deprecated: use -sast-rules")
	fs.StringVar(&f.sarifOut, "sarif", "", "write the findings as SARIF to this file")
	fs.StringVar(&f.gitlabOut, "gitlab-report", "", "write the findings as a GitLab security report to this file")
	fs.StringVar(&f.ctisOut, "ctis", "", "write the CTIS report to this file")
	fs.StringVar(&f.statusOut, "status", "", "write the job status for a later 'gate' job to this file")
	fs.StringVar(&f.failOn, "fail-on", e.getenv("OPENCTEM_FAIL_ON"), "local gate threshold (critical, high, medium, low, info), used when the platform gate cannot decide")
	fs.BoolVar(&f.noPush, "no-push", false, "do not upload to OpenCTEM (scan and write files only)")
	fs.BoolVar(&f.aggregate, "aggregate", false, "report into the run shared by all capability jobs of this pipeline; a final 'gate' job decides")
	fs.DurationVar(&f.timeout, "timeout", 30*time.Minute, "tool timeout")
	fs.StringVar(&f.diff, "diff", nonEmptyEnv(e.getenv("OPENCTEM_DIFF"), "auto"), "on a pull or merge request: auto (sast: only findings new since the merge base; secrets: only the change's commits) or off (full scan)")
	fs.StringVar(&f.onUploadError, "on-upload-error", e.getenv("OPENCTEM_ON_UPLOAD_ERROR"), "warn or fail when the results cannot be uploaded (default: warn with --aggregate, where the gate job uploads what is pending, else fail)")
	if err := fs.Parse(args); err != nil {
		return gate.ExitError
	}
	if fs.NArg() > 0 {
		_, _ = fmt.Fprintf(stderr, "unexpected argument %q\n", fs.Arg(0))
		return gate.ExitError
	}
	caps, err := capability.Parse(f.capability)
	if err != nil || len(caps) != 1 {
		if err == nil {
			err = errors.New("scan runs exactly one capability; run one job per capability")
		}
		_, _ = fmt.Fprintf(stderr, "Error: %v\n", err)
		return gate.ExitError
	}
	if f.diff != "auto" && f.diff != "off" {
		_, _ = fmt.Fprintf(stderr, "Error: --diff must be auto or off\n")
		return gate.ExitError
	}
	if f.failOn != "" && !gate.ValidThreshold(f.failOn) {
		_, _ = fmt.Fprintf(stderr, "Error: invalid --fail-on %q\n", f.failOn)
		return gate.ExitError
	}
	switch f.onUploadError = strings.ToLower(strings.TrimSpace(f.onUploadError)); f.onUploadError {
	case "":
		f.onUploadError = "fail"
		if f.aggregate {
			f.onUploadError = "warn"
		}
	case "warn", "fail":
	default:
		_, _ = fmt.Fprintf(stderr, "Error: --on-upload-error must be warn or fail\n")
		return gate.ExitError
	}
	s := &scanJob{f: f, c: caps[0], stdout: stdout, stderr: stderr, e: e}
	return s.run(ctx)
}

type scanJob struct {
	f      scanFlags
	c      capability.Capability
	stdout io.Writer
	stderr io.Writer
	e      env

	info   ciinfo.Info
	pr     *platform.Run
	status status
	gitFn  gitRunner
}

// git is the git runner (tests replace scanJob.gitFn).
func (s *scanJob) git() gitRunner {
	if s.gitFn != nil {
		return s.gitFn
	}
	return runGit
}

func (s *scanJob) logf(format string, a ...any) { _, _ = fmt.Fprintf(s.stdout, format+"\n", a...) }
func (s *scanJob) warnf(format string, a ...any) {
	_, _ = fmt.Fprintf(s.stderr, "Warning: "+format+"\n", a...)
}

func (s *scanJob) run(ctx context.Context) int {
	s.info = ciinfo.Detect(s.e.getenv)
	s.c = scanner.Resolve(s.c, s.e.environ)
	s.status = status{Capability: s.c.Name, Tool: s.c.Tool}
	s.logf("openctem-ci %s: %s (%s) with %s", Version, s.c.Name, s.c.ID, s.c.Tool)

	targetAbs, targetRel, err := scope.ResolveTarget(s.info.Workspace, s.f.target)
	if err != nil {
		return s.fail(ctx, fmt.Errorf("target: %w", err))
	}
	if s.c.Target == capability.TargetImage {
		if err := scanner.CheckImageRef(strings.TrimSpace(s.f.image)); err != nil {
			return s.fail(ctx, err)
		}
	}
	if err := s.openRun(); err != nil {
		return s.fail(ctx, err)
	}
	if s.pr != nil {
		raw, name, err := repopolicy.Load(s.info.Workspace)
		if err != nil {
			return s.fail(ctx, err)
		}
		if raw != nil {
			s.pr.SetRepoPolicy(raw)
			s.logf("Gate settings from %s are sent with the verdict request (they can only tighten the gate).", name)
		}
	}

	baseline := ""
	// sast reports what the change adds compared with the merge base;
	// secrets scans only the change's commits (repository root only: the
	// commit range covers the whole repository, not a subdirectory).
	if s.c.Name == "sast" || (s.c.Name == "secrets" && targetRel == ".") {
		var note string
		baseline, note = baselineCommit(ctx, s.f.diff, s.info, s.e.getenv, s.git())
		s.logf("[%s] %s", s.c.Tool, note)
	}

	rules := strings.TrimSpace(s.f.sastRules)
	if rules == "" && strings.TrimSpace(s.f.semgrepConfig) != "" {
		rules = strings.TrimSpace(s.f.semgrepConfig)
		s.warnf("semgrep-config (OPENCTEM_SEMGREP_CONFIG) is deprecated: use sast-rules (OPENCTEM_SAST_RULES)")
	}
	start := time.Now()
	res, err := scanner.Run(ctx, s.c, scanner.Options{Target: targetAbs, Root: s.info.Workspace, Image: strings.TrimSpace(s.f.image),
		SASTRules: rules, BaselineCommit: baseline, Timeout: s.f.timeout, Environ: s.e.environ, Stderr: s.stderr})
	// toolErr: the tool failed but wrote a report. What it found is kept,
	// marked partial, and the scan still fails: a crash is never "clean".
	toolErr := err
	if err != nil && (res == nil || !res.Partial) {
		return s.fail(ctx, err)
	}
	s.status.Version = res.Version
	if toolErr != nil {
		s.warnf("%s failed; the results it wrote before failing are kept, marked partial, and the scan counts as failed", s.c.Tool)
	} else {
		s.logf("[%s] finished in %s", s.c.Tool, res.Duration.Round(time.Millisecond))
	}

	known := redact.RawSecrets(res.Format, res.Output)
	report, err := s.convert(ctx, res, known, targetAbs, targetRel)
	if err == nil && s.pr != nil && secrethash.Applies(res.Format) {
		// Each secret goes up as a keyed hash of its raw value (the key comes
		// with the run); the value itself never does.
		if n := secrethash.Apply(report, res.Format, res.Output, s.pr.SecretKey(ctx)); n > 0 {
			s.logf("[%s] %d secret(s) identified by a keyed hash; no secret value is sent", s.c.Name, n)
		}
	}
	res.Output = nil // the raw output may hold secrets: drop it now
	if err != nil {
		if toolErr != nil {
			return s.fail(ctx, toolErr) // the partial report is unreadable: the tool's error is what counts
		}
		return s.fail(ctx, err)
	}
	if toolErr != nil {
		markPartial(report, errorClass(toolErr))
	}
	ctisJSON, err := json.Marshal(report)
	if err != nil {
		return s.fail(ctx, err)
	}
	if err := redact.Check(ctisJSON, known); err != nil {
		return s.fail(ctx, err)
	}
	if toolErr != nil {
		return s.failPartial(ctx, report, toolErr)
	}
	shown := report
	if s.pr != nil {
		up, err := s.pr.Upload(ctx, report)
		if err != nil {
			s.warnf("the results could not be uploaded to OpenCTEM: %v", err)
			s.status.Tally = gate.TallyReport(report)
			s.printSummary(report)
			if err := s.writeOutputs(report, ctisJSON, known, start); err != nil {
				return s.fail(ctx, err)
			}
			s.status.Error = "upload failed"
			s.status.Upload, s.status.UploadReason = uploadFailed, uploadClass(err)
			s.status.OK = true
			s.savePending(ctisJSON)
			s.saveStatus()
			if s.f.onUploadError == "warn" {
				s.warnf("THE RESULTS WERE NOT UPLOADED TO OPENCTEM. The local reports are written%s; the job passes (--on-upload-error warn).",
					pendingNote(s.status.Pending))
				return s.localGate("")
			}
			return s.localGate("the upload failed")
		}
		s.status.Pushed = true
		s.status.Upload = uploadDone
		info := s.pr.Info()
		s.logf("Uploaded to OpenCTEM run %s (%s @ %s): %d finding(s) new, %d updated",
			info.RunID, platform.Sanitize(info.Repository), short(info.CommitSHA), up.FindingsCreated, up.FindingsUpdated)
		if up.Parts > 1 {
			s.logf("[%s] the report was large and went up in %d parts", s.c.Name, up.Parts)
		}
		if up.KnownIncomplete {
			s.warnf("OpenCTEM stored the report, but its full list of already-decided results could not be read; " +
				"this output may still show some of them (the platform's verdict is not affected)")
		}
		var hidden map[string]int
		shown, hidden = withoutKnown(report, up.Known)
		if n := len(report.Findings) - len(shown.Findings); n > 0 {
			s.logf("[%s] %d result(s) already decided on OpenCTEM are left out of this output (%s); the platform still records them",
				s.c.Name, n, decisionCounts(hidden))
		}
	}
	// The local tally, the summary, SARIF and the merge request report show
	// what still needs a decision. The CTIS file keeps every result.
	s.status.Tally = gate.TallyReport(shown)
	s.printSummary(shown)
	if err := s.writeOutputs(shown, ctisJSON, known, start); err != nil {
		return s.fail(ctx, err)
	}
	s.status.OK = true
	s.saveStatus()

	if s.pr != nil && !s.f.aggregate {
		return s.platformGate(ctx, 0)
	}
	if s.f.aggregate {
		s.logf("Aggregate mode: the final gate job decides.")
		return gate.ExitPass
	}
	return s.localGate("")
}

// openRun decides whether the results go to the platform: only with an
// OIDC identity, never from a fork and never when --no-push is set. A job
// that names a tenant but cannot report fails closed (an error), unless
// OPENCTEM_ENFORCE=false: a forgotten id-token permission must not turn into
// a green pipeline that reported nothing.
func (s *scanJob) openRun() error {
	if s.f.noPush {
		s.status.Upload, s.status.UploadReason = uploadSkipped, "no_push"
		return nil
	}
	tenant := strings.TrimSpace(s.e.getenv(platform.EnvTenantID))
	if s.info.Fork {
		if tenant != "" {
			s.warnf("this change comes from a fork: results are not uploaded and no credential is used (scan only)")
		}
		s.status.Upload, s.status.UploadReason = uploadSkipped, "fork"
		return nil
	}
	if s.info.PullRequestTarget {
		s.warnf("pull_request_target runs with the base repository's credentials; prefer pull_request")
	}
	cfg := platform.ConfigFromEnv(s.e.getenv)
	cfg.Aggregate = s.f.aggregate
	cfg.UserAgent = "openctem-ci/" + Version
	pr, err := platform.New(cfg)
	if err != nil {
		if tenant == "" {
			s.status.Upload, s.status.UploadReason = uploadSkipped, "no_tenant"
			return nil // local use: no tenant, nothing to report
		}
		rerr := reportingError(err, nonEmpty(cfg.IDTokenVar, platform.DefaultIDTokenVar))
		if enforced(s.e.getenv) {
			return rerr
		}
		s.status.Upload, s.status.UploadReason = uploadSkipped, errorClass(rerr)
		s.warnf("%s; scan only (%s=false)", platform.Sanitize(rerr.Error()), envEnforce)
		return nil
	}
	s.pr = pr
	return nil
}

func (s *scanJob) convert(ctx context.Context, res *scanner.Result, known []string, targetAbs, targetRel string) (*ctis.Report, error) {
	out, err := importer.Parse(ctx, bytes.NewReader(res.Output), importer.Options{
		Format: res.Format, ToolName: res.Tool, SourceType: "ci",
		Repository: s.info.Repository, Branch: s.info.Branch, CommitSHA: s.info.Commit,
	})
	if err != nil {
		return nil, fmt.Errorf("read the %s report: %w", res.Tool, err)
	}
	for _, is := range out.Issues {
		s.warnf("[%s] %s", res.Tool, platform.Sanitize(is.String()))
	}
	r := out.Report
	imageOS, imageDigest := "", ""
	for _, a := range r.Assets {
		if v, ok := a.Properties["os"].(string); ok && v != "" && imageOS == "" {
			imageOS = v
		}
		if v, ok := a.Properties["repo_digest"].(string); ok && imageDigest == "" {
			imageDigest = ImageDigest(v)
		}
	}
	if res.Format == importer.FormatTrivy && s.c.Target == capability.TargetRepository {
		locateTrivyTargets(r)
	}
	st := scope.Apply(r, scope.Options{Repository: s.info.Repository, TargetRel: targetRel, TargetAbs: targetAbs,
		RepositoryPaths: s.c.Target == capability.TargetRepository})
	if st.PathsCleared > 0 {
		s.warnf("%d file path(s) pointed outside the repository and were removed", st.PathsCleared)
	}
	redact.Report(r, known)
	// SAST: the hash of the flagged lines, so the platform keys the finding
	// on its code (a line shift keeps its triage); the code itself stays here.
	if s.c.Name == "sast" && s.info.Workspace != "" {
		codehash.Fill(r, s.info.Workspace)
		// Inline ignore comments and the ignore file are claims: marked and
		// listed for OpenCTEM, which asks the security team (internal/claims).
		if n := claims.MarkInline(r, s.info.Workspace); n > 0 {
			s.logf("[%s] %d result(s) carry an inline ignore comment: reported anyway; OpenCTEM asks for a review", s.c.Name, n)
		}
		if pats := claims.IgnorePatterns(s.info.Workspace); len(pats) > 0 {
			list := make([]any, 0, len(pats))
			for _, p := range pats {
				list = append(list, p)
			}
			if r.Metadata.Properties == nil {
				r.Metadata.Properties = ctis.Properties{}
			}
			r.Metadata.Properties[claims.Property] = list
			s.logf("[%s] %s is not applied: its %d pattern(s) go to OpenCTEM as requests", s.c.Name, claims.IgnoreFile, len(pats))
		}
	}

	if r.Tool == nil {
		r.Tool = &ctis.Tool{Name: res.Tool}
	}
	if r.Tool.Version == "" {
		r.Tool.Version = res.Version
	}
	// The capability goes in metadata.properties: a receiver still on CTIS
	// 1.4 refuses the metadata.capability member (unknown fields are
	// refused), while properties are open.
	r.Metadata.Capability = ""
	if r.Metadata.Properties == nil {
		r.Metadata.Properties = ctis.Properties{}
	}
	r.Metadata.Properties["capability"] = s.c.ID
	r.Metadata.SourceType = "ci"
	r.Metadata.DurationMs = int(res.Duration.Milliseconds())
	if s.info.Branch != "" {
		r.Metadata.Branch = &ctis.BranchInfo{Name: s.info.Branch, CommitSHA: s.info.Commit, BaseBranch: s.info.TargetBranch,
			IsDefaultBranch: s.info.PullRequest == "" && s.info.DefaultBranch != "" && s.info.Branch == s.info.DefaultBranch}
	}
	// Full coverage (which lets the platform resolve findings no longer
	// reported) only for a whole-repository scan of the default branch;
	// anything else is partial (fail safe).
	r.Metadata.CoverageType = "partial"
	if r.Metadata.Branch != nil && r.Metadata.Branch.IsDefaultBranch && targetRel == "." && s.c.Target == capability.TargetRepository {
		r.Metadata.CoverageType = "full"
	}
	if s.c.Target == capability.TargetImage {
		r.Metadata.Properties["container_image"] = strings.TrimSpace(s.f.image)
		if imageOS != "" {
			r.Metadata.Properties["image_os"] = imageOS
		}
		// The image's content digest lets OpenCTEM link the repository to
		// the workloads that run this exact image.
		if imageDigest != "" {
			r.Metadata.Properties["image_digest"] = imageDigest
		}
	}
	return r, nil
}

func (s *scanJob) writeOutputs(report *ctis.Report, ctisJSON []byte, known []string, start time.Time) error {
	write := func(path string, data []byte) error {
		if err := redact.Check(data, known); err != nil {
			return err
		}
		if dir := filepath.Dir(path); dir != "" {
			if err := os.MkdirAll(dir, 0o750); err != nil {
				return err
			}
		}
		if err := os.WriteFile(path, data, 0o644); err != nil { // #nosec G306 -- a CI report artifact, secrets masked and checked
			return err
		}
		s.logf("Wrote %s", path)
		return nil
	}
	if s.f.ctisOut != "" {
		if err := write(s.f.ctisOut, ctisJSON); err != nil {
			return err
		}
	}
	if s.f.sarifOut != "" {
		log, st := sarif.FromReports([]*ctis.Report{report}, sarif.Options{Category: s.c.Name})
		data, err := log.Marshal()
		if err != nil {
			return err
		}
		if err := write(s.f.sarifOut, data); err != nil {
			return err
		}
		if st.NoLocation > 0 || st.Truncated > 0 {
			s.logf("  SARIF: %d result(s); %d without a file and %d over the limit are only in OpenCTEM", st.Written, st.NoLocation, st.Truncated)
		}
	}
	if s.f.gitlabOut != "" {
		gr, _, err := gitlab.FromReport(report, gitlab.Options{Type: s.c.GitLabReport, AnalyzerVersion: Version,
			Commit: s.info.Commit, Image: strings.TrimSpace(s.f.image), OperatingSystem: operatingSystem(report),
			Start: start, End: time.Now()})
		if err != nil {
			return err
		}
		data, err := gr.Marshal()
		if err != nil {
			return err
		}
		if err := write(s.f.gitlabOut, data); err != nil {
			return err
		}
	}
	return nil
}

// locateTrivyTargets gives a trivy file-system finding the file it was
// found in (the manifest, lock file or configuration file trivy names as
// the result target) when the finding has no location: code hosts and
// GitLab place every finding on a file. The path is normalized and kept
// inside the repository by scope.Apply afterwards.
// withoutKnown returns report without the results OpenCTEM says are already
// decided, and how many of each decision it left out. Indexes outside the
// report are ignored. The report itself is not changed.
func withoutKnown(report *ctis.Report, known []platform.Known) (*ctis.Report, map[string]int) {
	if len(known) == 0 || report == nil {
		return report, nil
	}
	skip := make(map[int]string, len(known))
	for _, k := range known {
		if k.Index >= 0 && k.Index < len(report.Findings) {
			skip[k.Index] = k.Decision
		}
	}
	if len(skip) == 0 {
		return report, nil
	}
	shown := *report
	shown.Findings = make([]ctis.Finding, 0, len(report.Findings)-len(skip))
	counts := map[string]int{}
	for i, f := range report.Findings {
		if d, ok := skip[i]; ok {
			counts[d]++
			continue
		}
		shown.Findings = append(shown.Findings, f)
	}
	return &shown, counts
}

// decisionCounts renders {"false_positive": 2, "accepted": 1} as
// "2 false positive, 1 accepted", in a stable order.
func decisionCounts(c map[string]int) string {
	keys := make([]string, 0, len(c))
	for k := range c {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, fmt.Sprintf("%d %s", c[k], strings.ReplaceAll(platform.Sanitize(k), "_", " ")))
	}
	return strings.Join(parts, ", ")
}

func locateTrivyTargets(r *ctis.Report) {
	for i := range r.Findings {
		f := &r.Findings[i]
		if f.Location != nil && f.Location.Path != "" {
			continue
		}
		t := strings.TrimSpace(f.SourceExtra["target"])
		if t == "" || t == "." {
			continue
		}
		if f.Location == nil {
			f.Location = &ctis.FindingLocation{}
		}
		f.Location.Path = t
	}
}

// operatingSystem is the image's operating system as the scanner reported it.
func operatingSystem(r *ctis.Report) string {
	if r == nil {
		return ""
	}
	if v, ok := r.Metadata.Properties["image_os"].(string); ok {
		return v
	}
	return ""
}

func (s *scanJob) printSummary(r *ctis.Report) {
	t := s.status.Tally
	keys := make([]string, 0, len(t.Severity))
	for k := range t.Severity {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, fmt.Sprintf("%s %d", k, t.Severity[k]))
	}
	s.logf("[%s] %d finding(s)%s", s.c.Name, len(r.Findings), parenthesize(strings.Join(parts, ", ")))
	if p := s.e.getenv("GITHUB_STEP_SUMMARY"); p != "" {
		appendStepSummary(p, s.c, t)
	}
}

// fail records a failed scan. In aggregate mode the final gate job counts
// it; otherwise the platform run (when there is one) records the failure,
// and the job exits 2: a failed scan never passes.
func (s *scanJob) fail(ctx context.Context, err error) int {
	_, _ = fmt.Fprintf(s.stderr, "Error: %s\n", platform.Sanitize(err.Error()))
	s.status.OK = false
	s.status.Error = truncate(platform.Sanitize(err.Error()), 300)
	if errors.Is(err, redact.ErrSecretInOutput) {
		s.status.Error = "secret redaction check failed"
	}
	var cre *cannotReportError
	if errors.As(err, &cre) {
		s.status.Error = cre.short
	}
	s.status.ErrorClass = errorClass(err)
	if s.status.Upload == "" {
		// Nothing went up for this capability: the scan failed before the
		// upload, or the job cannot report.
		s.status.Upload, s.status.UploadReason = uploadFailed, "scan_failed"
		if cre != nil {
			s.status.UploadReason = cre.class
		}
	}
	s.saveStatus()
	if s.pr != nil && !s.f.aggregate {
		if v, perr := s.pr.Evaluate(ctx, 1, s.status.capabilityState()); perr == nil {
			platform.WriteVerdict(s.stdout, v)
		}
	}
	return gate.ExitError
}

// savePending keeps the CTIS report next to the status file, so the gate
// job uploads it with its own token into the same run. The report already
// passed the raw-secret check (redact.Check) and holds what the SARIF and
// GitLab reports hold.
func (s *scanJob) savePending(ctisJSON []byte) {
	if s.f.statusOut == "" || !s.f.aggregate {
		return
	}
	name := s.c.Name + pendingSuffix
	dir := filepath.Dir(s.f.statusOut)
	path := filepath.Join(dir, name)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		s.warnf("could not keep the report for the gate job: %v", err)
		return
	}
	if err := os.WriteFile(path, ctisJSON, 0o644); err != nil { // #nosec G306 -- a CI artifact like the SARIF report
		s.warnf("could not keep the report for the gate job: %v", err)
		return
	}
	s.status.Pending = name
}

func pendingNote(pending string) string {
	if pending == "" {
		return ""
	}
	return " and the gate job will upload them with its own token"
}

func (s *scanJob) saveStatus() {
	if s.f.statusOut == "" {
		return
	}
	if err := writeStatus(s.f.statusOut, s.status); err != nil {
		s.warnf("could not write the status file: %v", err)
	}
}

// platformGate asks the platform for the verdict; the local gate decides
// only when the platform cannot be reached.
func (s *scanJob) platformGate(ctx context.Context, failures int) int {
	v, err := s.pr.Evaluate(ctx, failures, s.status.capabilityState())
	if err != nil {
		s.warnf("the OpenCTEM gate could not be reached: %v", err)
		return s.localGate("the platform gate is unreachable")
	}
	platform.WriteVerdict(s.stdout, v)
	if v.Failed() {
		return gate.ExitFail
	}
	return gate.ExitPass
}

// localGate applies --fail-on. Without a threshold there is no gate: a
// scan-only run passes, and a run that wanted the platform's verdict and
// could not get it is an error.
func (s *scanJob) localGate(why string) int {
	if s.f.failOn == "" {
		if why != "" {
			_, _ = fmt.Fprintf(s.stderr, "Error: %s and no --fail-on threshold is set\n", why)
			return gate.ExitError
		}
		return gate.ExitPass
	}
	if why != "" {
		s.logf("Falling back to the local gate (--fail-on %s): %s", s.f.failOn, why)
	}
	r, err := gate.Decide(s.status.Tally, s.f.failOn)
	if err != nil {
		_, _ = fmt.Fprintf(s.stderr, "Error: %v\n", err)
		return gate.ExitError
	}
	return gate.Print(s.stdout, r)
}

func appendStepSummary(path string, c capability.Capability, t gate.Tally) {
	f, err := os.OpenFile(filepath.Clean(path), os.O_APPEND|os.O_WRONLY, 0) // #nosec G304 -- the runner's summary file
	if err != nil {
		return
	}
	defer func() { _ = f.Close() }()
	var b strings.Builder
	fmt.Fprintf(&b, "### OpenCTEM %s (%s)\n\n| Severity | Findings |\n|---|---|\n", c.Name, c.Tool)
	for _, k := range []string{"critical", "high", "medium", "low", "info", "unknown"} {
		if n := t.Severity[k]; n > 0 {
			fmt.Fprintf(&b, "| %s | %d |\n", k, n)
		}
	}
	fmt.Fprintf(&b, "| **total** | **%d** |\n\n", t.Total())
	_, _ = f.WriteString(b.String())
}

func parenthesize(s string) string {
	if s == "" {
		return ""
	}
	return " (" + s + ")"
}

func short(sha string) string {
	if len(sha) > 12 {
		return sha[:12]
	}
	return sha
}

func nonEmpty(s, fallback string) string {
	if strings.TrimSpace(s) == "" {
		return fallback
	}
	return s
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

var imageDigestRE = regexp.MustCompile(`sha256:[0-9a-f]{64}$`)

// ImageDigest returns the "sha256:<hex>" digest at the end of a repository
// digest ("registry/name@sha256:..."), or "".
func ImageDigest(repoDigest string) string {
	return imageDigestRE.FindString(strings.ToLower(strings.TrimSpace(repoDigest)))
}

func nonEmptyEnv(v, fallback string) string {
	if strings.TrimSpace(v) == "" {
		return fallback
	}
	return strings.TrimSpace(v)
}
