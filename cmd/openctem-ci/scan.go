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
	"sort"
	"strings"
	"time"

	"github.com/openctemio/ctis"
	"github.com/openctemio/ctis/importer"

	"github.com/openctemio/ci/internal/capability"
	"github.com/openctemio/ci/internal/ciinfo"
	"github.com/openctemio/ci/internal/gate"
	"github.com/openctemio/ci/internal/gitlab"
	"github.com/openctemio/ci/internal/platform"
	"github.com/openctemio/ci/internal/redact"
	"github.com/openctemio/ci/internal/sarif"
	"github.com/openctemio/ci/internal/scanner"
	"github.com/openctemio/ci/internal/scope"
)

type scanFlags struct {
	capability    string
	target        string
	image         string
	semgrepConfig string
	sarifOut      string
	gitlabOut     string
	ctisOut       string
	statusOut     string
	failOn        string
	noPush        bool
	aggregate     bool
	timeout       time.Duration
}

func cmdScan(ctx context.Context, args []string, stdout, stderr io.Writer, e env) int {
	fs := flag.NewFlagSet("scan", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var f scanFlags
	fs.StringVar(&f.capability, "capability", e.getenv("OPENCTEM_CAPABILITY"), "capability to run: "+capability.Names())
	fs.StringVar(&f.target, "target", ".", "directory to scan, inside the workspace")
	fs.StringVar(&f.image, "image", "", "image reference to scan (container capability)")
	fs.StringVar(&f.semgrepConfig, "semgrep-config", e.getenv("OPENCTEM_SEMGREP_CONFIG"), "semgrep rules: a registry pack or a path in the repository (default "+scanner.DefaultSemgrepConfig+")")
	fs.StringVar(&f.sarifOut, "sarif", "", "write the findings as SARIF to this file")
	fs.StringVar(&f.gitlabOut, "gitlab-report", "", "write the findings as a GitLab security report to this file")
	fs.StringVar(&f.ctisOut, "ctis", "", "write the CTIS report to this file")
	fs.StringVar(&f.statusOut, "status", "", "write the job status for a later 'gate' job to this file")
	fs.StringVar(&f.failOn, "fail-on", e.getenv("OPENCTEM_FAIL_ON"), "local gate threshold (critical, high, medium, low, info), used when the platform gate cannot decide")
	fs.BoolVar(&f.noPush, "no-push", false, "do not upload to OpenCTEM (scan and write files only)")
	fs.BoolVar(&f.aggregate, "aggregate", false, "report into the run shared by all capability jobs of this pipeline; a final 'gate' job decides")
	fs.DurationVar(&f.timeout, "timeout", 30*time.Minute, "tool timeout")
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
	if f.failOn != "" && !gate.ValidThreshold(f.failOn) {
		_, _ = fmt.Fprintf(stderr, "Error: invalid --fail-on %q\n", f.failOn)
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
}

func (s *scanJob) logf(format string, a ...any) { _, _ = fmt.Fprintf(s.stdout, format+"\n", a...) }
func (s *scanJob) warnf(format string, a ...any) {
	_, _ = fmt.Fprintf(s.stderr, "Warning: "+format+"\n", a...)
}

func (s *scanJob) run(ctx context.Context) int {
	s.info = ciinfo.Detect(s.e.getenv)
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
	s.openRun()

	start := time.Now()
	res, err := scanner.Run(ctx, s.c, scanner.Options{Target: targetAbs, Image: strings.TrimSpace(s.f.image),
		SemgrepConfig: s.f.semgrepConfig, Timeout: s.f.timeout, Environ: s.e.environ, Stderr: s.stderr})
	if err != nil {
		return s.fail(ctx, err)
	}
	s.status.Version = res.Version
	s.logf("[%s] finished in %s", s.c.Tool, res.Duration.Round(time.Millisecond))

	known := redact.RawSecrets(res.Format, res.Output)
	report, err := s.convert(ctx, res, known, targetAbs, targetRel)
	res.Output = nil // the raw output may hold secrets: drop it now
	if err != nil {
		return s.fail(ctx, err)
	}
	ctisJSON, err := json.Marshal(report)
	if err != nil {
		return s.fail(ctx, err)
	}
	if err := redact.Check(ctisJSON, known); err != nil {
		return s.fail(ctx, err)
	}
	s.status.Tally = gate.TallyReport(report)
	s.printSummary(report)

	if err := s.writeOutputs(report, ctisJSON, known, start); err != nil {
		return s.fail(ctx, err)
	}

	if s.pr != nil {
		up, err := s.pr.Upload(ctx, report)
		if err != nil {
			s.warnf("the results could not be uploaded to OpenCTEM: %v", err)
			s.status.Error = "upload failed"
			s.status.OK = true
			s.saveStatus()
			return s.localGate("the upload failed")
		}
		s.status.Pushed = true
		info := s.pr.Info()
		s.logf("Uploaded to OpenCTEM run %s (%s @ %s): %d finding(s) new, %d updated",
			info.RunID, platform.Sanitize(info.Repository), short(info.CommitSHA), up.FindingsCreated, up.FindingsUpdated)
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
// OIDC identity, never from a fork and never when --no-push is set.
func (s *scanJob) openRun() {
	if s.f.noPush {
		return
	}
	tenant := strings.TrimSpace(s.e.getenv(platform.EnvTenantID))
	if s.info.Fork {
		if tenant != "" {
			s.warnf("this change comes from a fork: results are not uploaded and no credential is used (scan only)")
		}
		return
	}
	if s.info.PullRequestTarget {
		s.warnf("pull_request_target runs with the base repository's credentials; prefer pull_request")
	}
	cfg := platform.ConfigFromEnv(s.e.getenv)
	cfg.Aggregate = s.f.aggregate
	cfg.UserAgent = "openctem-ci/" + Version
	pr, err := platform.New(cfg)
	if err != nil {
		if tenant != "" {
			if errors.Is(err, platform.ErrNoOIDC) {
				s.warnf("%s is set but this job has no OIDC token (GitHub Actions: grant 'permissions: id-token: write'; "+
					"GitLab CI: define 'id_tokens: %[2]s' with the trust configuration's audience; Azure Pipelines: map "+
					"SYSTEM_ACCESSTOKEN: $(System.AccessToken); Bitbucket: 'oidc: true' on the step; CircleCI, Jenkins: "+
					"put the job's token in %[2]s, see docs/other-ci.md); scan only",
					platform.EnvTenantID, nonEmpty(cfg.IDTokenVar, platform.DefaultIDTokenVar))
			} else {
				s.warnf("reporting to OpenCTEM is not available: %v; scan only", err)
			}
		}
		return
	}
	s.pr = pr
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
	imageOS := ""
	for _, a := range r.Assets {
		if v, ok := a.Properties["os"].(string); ok && v != "" {
			imageOS = v
			break
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
	s.saveStatus()
	if s.pr != nil && !s.f.aggregate {
		if v, perr := s.pr.Evaluate(ctx, 1); perr == nil {
			platform.WriteVerdict(s.stdout, v)
		}
	}
	return gate.ExitError
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
	v, err := s.pr.Evaluate(ctx, failures)
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
