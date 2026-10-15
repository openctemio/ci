// Package scanner runs the tool of a capability and returns its native
// output. Each tool runs with a fixed argument list (no shell), a timeout,
// a filtered environment and its output in a private temporary directory
// that is removed afterwards: the raw output of a secret scanner holds the
// secrets themselves and must never land in the workspace, where a CI job
// could publish it as an artifact.
package scanner

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/openctemio/ctis/importer"

	"github.com/openctemio/ci/internal/capability"
)

// maxOutput bounds the native output read back (the importer caps it again).
const maxOutput = 512 << 20

// maxStderr bounds the tool's error output kept for the log.
const maxStderr = 16 << 10

// Options configure a scan.
type Options struct {
	// Target is the directory to scan (repository capabilities).
	Target string
	// Root is the repository root (the workspace) when Target is a
	// directory inside it; git (semgrep's file list, the baseline commit)
	// works on the root, so the root is trusted as well.
	Root string
	// Image is the image reference to scan (the container capability).
	Image string
	// SASTRules replaces the default sast rules (a registry pack such as
	// p/default, fetched by the engine on this runner, or a path in the
	// repository).
	SASTRules string
	// BaselineCommit is a pull request's merge base: sast reports only
	// findings that are not already in that commit (semgrep
	// --baseline-commit), secrets scans only the commits after it
	// (betterleaks git --log-opts=<base>..HEAD). Anything but a commit id
	// is ignored and the scan is full.
	BaselineCommit string
	// Timeout of the tool (default 30 minutes).
	Timeout time.Duration
	// Getenv reads the environment passed on (filtered) to the tool.
	Getenv func(string) string
	// Environ lists the environment (os.Environ by default).
	Environ func() []string
	// Stderr receives the tool's progress output.
	Stderr io.Writer
}

// Result is a tool's native output.
type Result struct {
	Tool    string
	Version string
	// Output is the tool's native report.
	Output []byte
	// Format tells the importer how to read Output.
	Format importer.Format
	// Duration of the tool run.
	Duration time.Duration
	// Partial: the tool failed (Run also returns its error), but it had
	// written a report. The results in it are what the tool found before it
	// failed, never a complete scan.
	Partial bool
}

// ErrTimeout: the tool did not finish within its time limit.
var ErrTimeout = errors.New("the tool did not finish in time")

// PackDir is where the ci-opengrep image installs the OpenCTEM rules pack
// (github.com/openctemio/sast-rules, a signed release verified at build).
// The rules "openctem" name it.
var PackDir = "/opt/openctem/sast-rules/rules"

// PackRules names the OpenCTEM rules pack as sast rules.
const PackRules = "openctem"

// DefaultSASTRules is the registry pack used when no sast rules are set and
// the image has no rules pack (the ci-semgrep image).
// The engine fetches it on the CI runner at scan time; the image does not
// redistribute registry rules.
const DefaultSASTRules = "p/default"

// SASTEngines are the sast engines, in order of preference: an image runs
// the first one it has (ci-opengrep: opengrep; ci-semgrep: semgrep).
var SASTEngines = []string{"opengrep", "semgrep"}

// Resolve returns the capability with the tool this environment runs: for
// sast, the first engine of SASTEngines on PATH (the catalog's when none
// is, so the error names it).
func Resolve(c capability.Capability, environ func() []string) capability.Capability {
	if c.Name != "sast" {
		return c
	}
	if environ == nil {
		environ = os.Environ
	}
	env := FilterEnv(environ())
	for _, t := range SASTEngines {
		if _, err := lookPath(t, env); err == nil {
			c.Tool = t
			return c
		}
	}
	return c
}

// Run runs the capability's tool.
func Run(ctx context.Context, c capability.Capability, opts Options) (*Result, error) {
	if opts.Timeout <= 0 {
		opts.Timeout = 30 * time.Minute
	}
	if opts.Stderr == nil {
		opts.Stderr = io.Discard
	}
	if opts.Environ == nil {
		opts.Environ = os.Environ
	}
	dir, err := os.MkdirTemp("", "openctem-ci-")
	if err != nil {
		return nil, fmt.Errorf("create a private output directory: %w", err)
	}
	defer func() { _ = os.RemoveAll(dir) }()
	if err := os.Chmod(dir, 0o700); err != nil { // #nosec G302 -- a directory: 0700 is owner-only
		return nil, err
	}
	out := filepath.Join(dir, "report.json")

	c = Resolve(c, opts.Environ)
	argv, format, err := Command(c, opts, out)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, opts.Timeout)
	defer cancel()

	env := FilterEnv(opts.Environ())
	if c.Tool == "trivy" {
		runDir := opts.Target
		if runDir == "" {
			runDir, _ = os.Getwd()
		}
		if err := checkTrivyCache(env, runDir, opts.Target, opts.Root); err != nil {
			return nil, err
		}
	}
	bin, err := lookPath(argv[0], env)
	if err != nil {
		return nil, err
	}
	version := Version(ctx, c.Tool, opts.Environ)
	start := time.Now()
	cmd := exec.CommandContext(ctx, bin, argv[1:]...) // #nosec G204 -- fixed argv from Command, no shell
	cmd.Env = env
	cmd.Env = append(cmd.Env, toolEnv(c.Tool, dir, opts.Target, opts.Root)...)
	cmd.Env = append(cmd.Env, defaultConfigEnv(c.Tool, env)...)
	if opts.Target != "" {
		cmd.Dir = opts.Target
	}
	var stderr bytes.Buffer
	cmd.Stdout = io.Discard
	cmd.Stderr = &limitWriter{w: &stderr, n: maxStderr}
	runErr := cmd.Run()
	dur := time.Since(start)
	// A failed tool may still have written a report: it is returned marked
	// partial, with the error, and the caller decides what to do with it.
	partial := func() *Result {
		data, err := readBounded(out)
		if err != nil || len(bytes.TrimSpace(data)) == 0 {
			return nil
		}
		return &Result{Tool: c.Tool, Version: version, Output: data, Format: format, Duration: dur, Partial: true}
	}
	if ctx.Err() == context.DeadlineExceeded {
		return partial(), fmt.Errorf("%w: %s did not finish within %s", ErrTimeout, c.Tool, opts.Timeout)
	}
	if runErr != nil && !acceptedExit(c.Tool, runErr) {
		return partial(), fmt.Errorf("%s failed: %w: %s", c.Tool, runErr, lastLines(stderr.String(), 8))
	}
	data, err := readBounded(out)
	if err != nil {
		return nil, fmt.Errorf("%s wrote no report: %w: %s", c.Tool, err, lastLines(stderr.String(), 8))
	}
	return &Result{Tool: c.Tool, Version: version, Output: data, Format: format, Duration: dur}, nil
}

// DefaultSASTExcludes are the paths a SAST scan skips: dependencies, build
// output and tests, the list an absent ignore file would apply.
var DefaultSASTExcludes = []string{"node_modules", "build", "dist", "vendor", ".env", ".venv", ".tox",
	"*.min.js", ".npm", ".yarn", "test", "tests", "*_test.go"}

// Command returns the argument list of a capability's tool, writing its
// report to out, and the importer format of that report.
func Command(c capability.Capability, opts Options, out string) ([]string, importer.Format, error) {
	// The tool runs in the target directory (Run sets it) and scans ".",
	// so the paths it reports are relative to the target.
	const target = "."
	switch c.Name {
	case "sast":
		cfg, err := sastRules(opts.SASTRules)
		if err != nil {
			return nil, "", err
		}
		if strings.HasPrefix(cfg, "-") {
			return nil, "", fmt.Errorf("sast rules %q must not start with '-'", cfg)
		}
		// Rule ids as the rules write them (the finding identity holds the
		// rule id). opengrep has no metrics and refuses --metrics; its
		// version check is off unless asked for. --dataflow-traces: a taint
		// finding carries the path from the source to the sink
		// (dataflow_trace, the finding's data_flow); both engines take it.
		// --disable-nosem and --x-ignore-semgrepignore-files: an inline
		// ignore comment or a .semgrepignore in the scanned tree is the
		// author's claim, not a decision; the results are reported and the
		// claims go to OpenCTEM as requests (internal/claims). The paths a
		// default ignore file would skip are excluded here instead, from the
		// pipeline, not the repository.
		argv := []string{c.Tool, "scan", "--json", "--output", out, "--config", cfg,
			"--disable-version-check", "--no-rewrite-rule-ids", "--dataflow-traces", "--quiet",
			"--disable-nosem", "--x-ignore-semgrepignore-files"}
		for _, x := range DefaultSASTExcludes {
			argv = append(argv, "--exclude", x)
		}
		format := importer.FormatOpengrep
		switch c.Tool {
		case "opengrep":
		case "semgrep":
			argv = append(argv, "--metrics=off")
			format = importer.FormatSemgrep
		default:
			return nil, "", fmt.Errorf("no sast engine %q", c.Tool)
		}
		if CommitID(opts.BaselineCommit) {
			argv = append(argv, "--baseline-commit", opts.BaselineCommit)
		}
		return append(argv, target), format, nil
	case "secrets":
		// --exit-code 0: findings are not an error; the gate decides.
		// Never --verbose: it prints every raw secret to the log.
		// --gitleaks-ignore-path points at the private output directory, so
		// an ignore file committed in the scanned tree is not read
		// (repoFilesIgnored).
		mode := []string{"betterleaks", "dir", target}
		if CommitID(opts.BaselineCommit) {
			// A pull or merge request: only the commits the change adds,
			// every one of them (a secret added then removed in the same
			// change is still leaked in its history).
			mode = []string{"betterleaks", "git", target, "--log-opts=" + opts.BaselineCommit + "..HEAD"}
		}
		return append(mode, "--report-format", "json", "--report-path", out,
			"--exit-code", "0", "--no-banner", "--ignore-gitleaks-allow",
			"--gitleaks-ignore-path", filepath.Dir(out)), importer.FormatBetterleaks, nil
	case "sca":
		// --list-all-pkgs: the package graph tells each finding whether its
		// dependency is direct, the path that brings it in and its lockfile
		// line; the report then keeps only the packages the findings need
		// (keepFindingDependencies).
		return []string{"trivy", "fs", "--scanners", "vuln", "--list-all-pkgs", "--format", "json", "--output", out,
			"--exit-code", "0", "--quiet", "--config", "", "--ignorefile", "", target}, importer.FormatTrivy, nil
	case "iac":
		return []string{"trivy", "config", "--format", "json", "--output", out,
			"--exit-code", "0", "--quiet", "--config", "", "--ignorefile", "", target}, importer.FormatTrivy, nil
	case "container":
		img := strings.TrimSpace(opts.Image)
		if err := CheckImageRef(img); err != nil {
			return nil, "", err
		}
		return []string{"trivy", "image", "--scanners", "vuln", "--format", "json", "--output", out,
			"--exit-code", "0", "--quiet", img}, importer.FormatTrivy, nil
	}
	return nil, "", fmt.Errorf("no tool for capability %q", c.Name)
}

// sastRules resolves the rules a sast scan runs: the ones set, else the
// image's rules pack, else the registry pack.
func sastRules(set string) (string, error) {
	cfg := strings.TrimSpace(set)
	packed := false
	if fi, err := os.Stat(PackDir); err == nil && fi.IsDir() {
		packed = true
	}
	switch {
	case cfg == PackRules && !packed:
		return "", fmt.Errorf("sast rules %q: this image has no rules pack (use the ci-opengrep image)", cfg)
	case cfg == PackRules, cfg == "" && packed:
		return PackDir, nil
	case cfg == "":
		return DefaultSASTRules, nil
	}
	return cfg, nil
}

// imageRef is a container image reference: [registry[:port]/]path[:tag][@digest].
var imageRef = regexp.MustCompile(`^[a-z0-9]+([._-][a-z0-9]+)*(:[0-9]+)?(/[a-z0-9]+([._-][a-z0-9]+)*)*(:[A-Za-z0-9_][A-Za-z0-9_.-]{0,127})?(@sha256:[a-f0-9]{64})?$`)

// CheckImageRef refuses anything but a plain image reference (no option,
// no scheme, no local path).
func CheckImageRef(ref string) error {
	if ref == "" {
		return errors.New("the container capability needs an image reference (--image)")
	}
	if len(ref) > 512 || !imageRef.MatchString(ref) {
		return fmt.Errorf("%q is not a container image reference", ref)
	}
	return nil
}

// acceptedExit reports whether a non-zero exit still produced a usable
// report. semgrep and opengrep exit 1 when they found something (with
// --error) and 2+ on errors; the report is read either way and its
// absence is the error.
func acceptedExit(tool string, err error) bool {
	var ee *exec.ExitError
	if !errors.As(err, &ee) {
		return false
	}
	return (tool == "semgrep" || tool == "opengrep") && ee.ExitCode() == 1
}

// Version asks a tool for its version ("" when it cannot say).
func Version(ctx context.Context, tool string, environ func() []string) string {
	var args []string
	switch tool {
	case "semgrep", "opengrep", "trivy":
		args = []string{"--version"}
	case "betterleaks":
		args = []string{"version"}
	default:
		return ""
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	env := FilterEnv(environ())
	bin, err := lookPath(tool, env)
	if err != nil {
		return ""
	}
	cmd := exec.CommandContext(ctx, bin, args...) // #nosec G204 -- fixed tool names
	cmd.Env = env
	b, err := cmd.Output()
	if err != nil {
		return ""
	}
	return parseVersion(string(b))
}

var versionRe = regexp.MustCompile(`v?(\d+\.\d+\.\d+[0-9A-Za-z.+-]*)`)

func parseVersion(s string) string {
	if m := versionRe.FindStringSubmatch(s); m != nil {
		return m[1]
	}
	return ""
}

// Repository files the scanners would read from the scanned tree by
// default (trivy.yaml, .trivyignore, .trivyignore.yaml, .gitleaks.toml,
// .betterleaks.toml, .gitleaksignore, .betterleaksignore) are not read: the
// tree is the change under review, so a pull request could otherwise raise
// a severity threshold, skip a manifest or allowlist its own secret and
// pass the gate. Configuration comes from the pipeline (flags and
// environment the workflow sets), and exceptions go to the platform
// (.openctem.yml exception requests, approved there).
//
// defaultConfigEnv selects betterleaks' built-in rules unless the pipeline
// configured betterleaks through its environment: without one of those
// variables betterleaks reads .betterleaks.toml or .gitleaks.toml from the
// scanned tree.
func defaultConfigEnv(tool string, env []string) []string {
	if tool != "betterleaks" {
		return nil
	}
	for _, kv := range env {
		k, _, _ := strings.Cut(kv, "=")
		switch k {
		case "BETTERLEAKS_CONFIG", "GITLEAKS_CONFIG", "BETTERLEAKS_CONFIG_TOML", "GITLEAKS_CONFIG_TOML":
			return nil
		}
	}
	return []string{"BETTERLEAKS_CONFIG_TOML=" + builtinBetterleaksConfig}
}

// builtinBetterleaksConfig is betterleaks' default rule set and nothing else.
const builtinBetterleaksConfig = "[extend]\nuseDefault = true\n"

// toolEnv is the environment each tool needs on top of the filtered one.
// The checkout usually belongs to another user than the scanner (a
// container): git then refuses it as a dubious-ownership repository and
// semgrep loses its file list. Exactly the scanned directory is trusted,
// for this process only (command-scope configuration), never every
// directory.
func toolEnv(tool, dir, target, root string) []string {
	env := []string{"TMPDIR=" + dir}
	trusted := []string{}
	for _, d := range []string{target, root} {
		if d != "" && !slices.Contains(trusted, d) {
			trusted = append(trusted, d)
		}
	}
	if len(trusted) > 0 {
		env = append(env, fmt.Sprintf("GIT_CONFIG_COUNT=%d", len(trusted)))
		for i, d := range trusted {
			env = append(env, fmt.Sprintf("GIT_CONFIG_KEY_%d=safe.directory", i), fmt.Sprintf("GIT_CONFIG_VALUE_%d=%s", i, d))
		}
	}
	switch tool {
	case "semgrep":
		env = append(env, "SEMGREP_SEND_METRICS=off", "SEMGREP_ENABLE_VERSION_CHECK=0")
	case "opengrep":
		// Its log and settings ($XDG_CONFIG_HOME/.opengrep) go to the
		// private output directory, not the job's home.
		env = append(env, "XDG_CONFIG_HOME="+dir)
	case "trivy":
		env = append(env, "TRIVY_NO_PROGRESS=true")
	}
	return env
}

// passEnv are the variables a tool may see: what it needs to run, reach
// the network through a proxy, trust a private CA, find its cache and
// pull an image. The CI job's credentials (OIDC request token, ID tokens,
// job tokens, platform and API keys) are not passed.
var passEnv = map[string]bool{
	"PATH": true, "HOME": true, "USER": true, "LANG": true, "LC_ALL": true, "TZ": true,
	"HTTP_PROXY": true, "HTTPS_PROXY": true, "NO_PROXY": true,
	"http_proxy": true, "https_proxy": true, "no_proxy": true,
	"SSL_CERT_FILE": true, "SSL_CERT_DIR": true, "REQUESTS_CA_BUNDLE": true,
	"XDG_CACHE_HOME": true, "XDG_CONFIG_HOME": true,
	"DOCKER_HOST": true, "DOCKER_CONFIG": true, "DOCKER_CERT_PATH": true, "DOCKER_TLS_VERIFY": true,
}

// passPrefix are tool configuration prefixes passed through, minus the
// ones that carry a credential (deniedEnv).
var passPrefix = []string{"TRIVY_", "SEMGREP_", "BETTERLEAKS_"}

// deniedEnv are credential variables under a passed prefix.
var deniedEnv = map[string]bool{
	"SEMGREP_APP_TOKEN": true,
}

// FilterEnv keeps only the variables a tool may see.
func FilterEnv(environ []string) []string {
	var out []string
	for _, kv := range environ {
		k, _, ok := strings.Cut(kv, "=")
		if !ok || deniedEnv[k] {
			continue
		}
		if passEnv[k] {
			out = append(out, kv)
			continue
		}
		for _, p := range passPrefix {
			if strings.HasPrefix(k, p) {
				out = append(out, kv)
				break
			}
		}
	}
	return out
}

// lookPath finds a tool on the PATH of the environment the tool runs with
// (not the parent's), so what is checked is what runs.
func lookPath(name string, env []string) (string, error) {
	pathEnv := ""
	for _, kv := range env {
		if strings.HasPrefix(kv, "PATH=") {
			pathEnv = strings.TrimPrefix(kv, "PATH=")
		}
	}
	for _, dir := range filepath.SplitList(pathEnv) {
		if dir == "" || !filepath.IsAbs(dir) {
			continue // a relative PATH entry would run a file from the scanned repository
		}
		p := filepath.Join(dir, name)
		if fi, err := os.Stat(p); err == nil && fi.Mode().IsRegular() && fi.Mode().Perm()&0o111 != 0 {
			return p, nil
		}
	}
	return "", fmt.Errorf("%s is not installed (not found on PATH); use the ghcr.io/openctemio/ci-%s image", name, name)
}

func readBounded(path string) ([]byte, error) {
	f, err := os.Open(path) // #nosec G304 -- our own private temp file
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	data, err := io.ReadAll(io.LimitReader(f, maxOutput+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maxOutput {
		return nil, fmt.Errorf("the report is larger than %d MB", maxOutput>>20)
	}
	return data, nil
}

// limitWriter keeps the first n bytes.
type limitWriter struct {
	w io.Writer
	n int
}

func (l *limitWriter) Write(p []byte) (int, error) {
	if l.n > 0 {
		k := len(p)
		if k > l.n {
			k = l.n
		}
		_, _ = l.w.Write(p[:k])
		l.n -= k
	}
	return len(p), nil
}

// lastLines keeps the last n lines of s.
func lastLines(s string, n int) string {
	lines := strings.Split(strings.TrimSpace(s), "\n")
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return strings.Join(lines, " | ")
}

var commitIDRE = regexp.MustCompile(`^[0-9a-f]{7,64}$`)

// CommitID reports whether s is a lower-case hexadecimal commit id.
func CommitID(s string) bool { return commitIDRE.MatchString(s) }
