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
	// Image is the image reference to scan (the container capability).
	Image string
	// SemgrepConfig replaces the default semgrep rules (a registry pack
	// such as p/default, or a path in the repository).
	SemgrepConfig string
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
}

// DefaultSemgrepConfig is the semgrep registry pack used when none is set.
// It is fetched by semgrep at scan time; the image does not redistribute
// registry rules.
const DefaultSemgrepConfig = "p/default"

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

	argv, format, err := Command(c, opts, out)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, opts.Timeout)
	defer cancel()

	env := FilterEnv(opts.Environ())
	bin, err := lookPath(argv[0], env)
	if err != nil {
		return nil, err
	}
	version := Version(ctx, c.Tool, opts.Environ)
	start := time.Now()
	cmd := exec.CommandContext(ctx, bin, argv[1:]...) // #nosec G204 -- fixed argv from Command, no shell
	cmd.Env = env
	cmd.Env = append(cmd.Env, toolEnv(c.Tool, dir)...)
	if opts.Target != "" {
		cmd.Dir = opts.Target
	}
	var stderr bytes.Buffer
	cmd.Stdout = io.Discard
	cmd.Stderr = &limitWriter{w: &stderr, n: maxStderr}
	runErr := cmd.Run()
	dur := time.Since(start)
	if ctx.Err() == context.DeadlineExceeded {
		return nil, fmt.Errorf("%s did not finish within %s", c.Tool, opts.Timeout)
	}
	if runErr != nil && !acceptedExit(c.Tool, runErr) {
		return nil, fmt.Errorf("%s failed: %w: %s", c.Tool, runErr, lastLines(stderr.String(), 8))
	}
	data, err := readBounded(out)
	if err != nil {
		return nil, fmt.Errorf("%s wrote no report: %w: %s", c.Tool, err, lastLines(stderr.String(), 8))
	}
	return &Result{Tool: c.Tool, Version: version, Output: data, Format: format, Duration: dur}, nil
}

// Command returns the argument list of a capability's tool, writing its
// report to out, and the importer format of that report.
func Command(c capability.Capability, opts Options, out string) ([]string, importer.Format, error) {
	// The tool runs in the target directory (Run sets it) and scans ".",
	// so the paths it reports are relative to the target.
	const target = "."
	switch c.Name {
	case "sast":
		cfg := strings.TrimSpace(opts.SemgrepConfig)
		if cfg == "" {
			cfg = DefaultSemgrepConfig
		}
		if strings.HasPrefix(cfg, "-") {
			return nil, "", fmt.Errorf("semgrep config %q must not start with '-'", cfg)
		}
		return []string{"semgrep", "scan", "--json", "--output", out, "--config", cfg,
			"--metrics=off", "--disable-version-check", "--no-rewrite-rule-ids", "--quiet", target}, importer.FormatSemgrep, nil
	case "secrets":
		// --exit-code 0: findings are not an error; the gate decides.
		// Never --verbose: it prints every raw secret to the log.
		return []string{"betterleaks", "dir", target, "--report-format", "json", "--report-path", out,
			"--exit-code", "0", "--no-banner", "--ignore-gitleaks-allow"}, importer.FormatBetterleaks, nil
	case "sca":
		return []string{"trivy", "fs", "--scanners", "vuln", "--format", "json", "--output", out,
			"--exit-code", "0", "--quiet", target}, importer.FormatTrivy, nil
	case "iac":
		return []string{"trivy", "config", "--format", "json", "--output", out,
			"--exit-code", "0", "--quiet", target}, importer.FormatTrivy, nil
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
// report. semgrep exits 1 when it found something and 2+ on errors; the
// report is read either way and its absence is the error.
func acceptedExit(tool string, err error) bool {
	var ee *exec.ExitError
	if !errors.As(err, &ee) {
		return false
	}
	return tool == "semgrep" && ee.ExitCode() == 1
}

// Version asks a tool for its version ("" when it cannot say).
func Version(ctx context.Context, tool string, environ func() []string) string {
	var args []string
	switch tool {
	case "semgrep", "trivy":
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

// toolEnv is the environment each tool needs on top of the filtered one.
func toolEnv(tool, dir string) []string {
	env := []string{"TMPDIR=" + dir}
	switch tool {
	case "semgrep":
		env = append(env, "SEMGREP_SEND_METRICS=off", "SEMGREP_ENABLE_VERSION_CHECK=0")
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
