package scanner

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/openctemio/ci/internal/capability"
)

func capOf(t *testing.T, name string) capability.Capability {
	t.Helper()
	c, ok := capability.Lookup(name)
	if !ok {
		t.Fatal(name)
	}
	return c
}

func TestCommand(t *testing.T) {
	for _, c := range capability.All() {
		argv, format, err := Command(c, Options{Image: "alpine:3.20"}, "/tmp/x/report.json")
		if err != nil {
			t.Fatalf("%s: %v", c.Name, err)
		}
		if argv[0] != c.Tool || format == "" {
			t.Errorf("%s: %v %s", c.Name, argv, format)
		}
		joined := strings.Join(argv, " ")
		if strings.Contains(joined, "--verbose") {
			t.Errorf("%s: --verbose prints raw secrets: %s", c.Name, joined)
		}
		if !strings.Contains(joined, "/tmp/x/report.json") {
			t.Errorf("%s: the report does not go to the private file: %s", c.Name, joined)
		}
	}
	argv, _, _ := Command(capOf(t, "sast"), Options{}, "o")
	if !strings.Contains(strings.Join(argv, " "), "--metrics=off") || !strings.Contains(strings.Join(argv, " "), DefaultSemgrepConfig) {
		t.Errorf("semgrep: %v", argv)
	}
	if _, _, err := Command(capOf(t, "sast"), Options{SemgrepConfig: "--dangerous"}, "o"); err == nil {
		t.Error("a semgrep config that is an option was accepted")
	}
}

func TestCheckImageRef(t *testing.T) {
	good := []string{"alpine", "alpine:3.20", "ghcr.io/openctemio/ci:v1", "localhost:5000/a/b:tag",
		"registry.example.com/app@sha256:" + strings.Repeat("a", 64)}
	for _, g := range good {
		if err := CheckImageRef(g); err != nil {
			t.Errorf("%q: %v", g, err)
		}
	}
	bad := []string{"", "--input=/etc/passwd", "-x", "../app", "/abs/path", "file:///x", "a b", "Alpine",
		"docker://x", "x;rm -rf /", strings.Repeat("a", 600)}
	for _, b := range bad {
		if CheckImageRef(b) == nil {
			t.Errorf("%q accepted", b)
		}
	}
	if _, _, err := Command(capOf(t, "container"), Options{Image: "-x"}, "o"); err == nil {
		t.Error("container with an option as image was accepted")
	}
}

// The CI job's credentials never reach a tool.
func TestFilterEnv(t *testing.T) {
	in := []string{
		"PATH=/bin", "HOME=/h", "HTTPS_PROXY=http://p", "TRIVY_CACHE_DIR=/c", "SEMGREP_RULES=x",
		"ACTIONS_ID_TOKEN_REQUEST_TOKEN=secret", "ACTIONS_ID_TOKEN_REQUEST_URL=https://x", "ACTIONS_RUNTIME_TOKEN=s",
		"OPENCTEM_ID_TOKEN=jwt", "OPENCTEM_TENANT_ID=t", "CI_JOB_TOKEN=glcbt", "CI_JOB_JWT_V2=jwt", "GITHUB_TOKEN=ghs",
		"SEMGREP_APP_TOKEN=s", "AWS_SECRET_ACCESS_KEY=s", "MALFORMED",
	}
	out := strings.Join(FilterEnv(in), "\n")
	for _, keep := range []string{"PATH=", "HOME=", "HTTPS_PROXY=", "TRIVY_CACHE_DIR=", "SEMGREP_RULES="} {
		if !strings.Contains(out, keep) {
			t.Errorf("%s dropped", keep)
		}
	}
	for _, drop := range []string{"ACTIONS_", "OPENCTEM_", "CI_JOB", "GITHUB_TOKEN", "SEMGREP_APP_TOKEN", "AWS_", "MALFORMED"} {
		if strings.Contains(out, drop) {
			t.Errorf("%s passed to the tool", drop)
		}
	}
}

// Run uses a stand-in tool that writes its environment as its report: the
// tool sees no credential of the CI job, its temporary directory is the
// private one, and that directory is gone afterwards.
func TestRunWithStandInTool(t *testing.T) {
	bin := t.TempDir()
	script := `#!/bin/sh
out=""
while [ $# -gt 0 ]; do
  if [ "$1" = "--report-path" ]; then out="$2"; fi
  if [ "$1" = "version" ]; then echo "betterleaks version 1.9.0"; exit 0; fi
  shift
done
env > "$out"
`
	if err := os.WriteFile(filepath.Join(bin, "betterleaks"), []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	environ := func() []string {
		return []string{"PATH=" + bin + ":/usr/bin:/bin", "ACTIONS_ID_TOKEN_REQUEST_TOKEN=leak1", "OPENCTEM_ID_TOKEN=leak2",
			"BETTERLEAKS_CONFIG=/x"}
	}
	res, err := Run(context.Background(), capOf(t, "secrets"), Options{Target: t.TempDir(), Timeout: time.Minute, Environ: environ})
	if err != nil {
		t.Fatal(err)
	}
	out := string(res.Output)
	if strings.Contains(out, "leak1") || strings.Contains(out, "leak2") {
		t.Fatalf("a credential reached the tool:\n%s", out)
	}
	if !strings.Contains(out, "BETTERLEAKS_CONFIG=/x") {
		t.Fatalf("tool configuration dropped:\n%s", out)
	}
	var tmp string
	for _, l := range strings.Split(out, "\n") {
		if strings.HasPrefix(l, "TMPDIR=") {
			tmp = strings.TrimPrefix(l, "TMPDIR=")
		}
	}
	if tmp == "" || !strings.HasPrefix(filepath.Base(tmp), "openctem-ci-") {
		t.Fatalf("TMPDIR %q is not the private directory", tmp)
	}
	if _, err := os.Stat(tmp); !os.IsNotExist(err) {
		t.Fatalf("the private directory %s was not removed: %v", tmp, err)
	}
	if !strings.Contains(out, "GIT_CONFIG_KEY_0=safe.directory") {
		t.Errorf("the checkout is not trusted for git:\n%s", out)
	}
	if res.Version != "1.9.0" {
		t.Errorf("version %q", res.Version)
	}
}

func TestRunFailsWithoutReport(t *testing.T) {
	bin := t.TempDir()
	if err := os.WriteFile(filepath.Join(bin, "trivy"), []byte("#!/bin/sh\necho boom >&2\nexit 3\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	_, err := Run(context.Background(), capOf(t, "sca"), Options{Target: t.TempDir(),
		Environ: func() []string { return []string{"PATH=" + bin + ":/usr/bin:/bin"} }})
	if err == nil || !strings.Contains(err.Error(), "boom") {
		t.Fatalf("%v", err)
	}
}

func TestParseVersion(t *testing.T) {
	for in, want := range map[string]string{"Version: 0.75.0\n": "0.75.0", "1.179.0": "1.179.0", "betterleaks version v1.9.0": "1.9.0", "x": ""} {
		if got := parseVersion(in); got != want {
			t.Errorf("%q: %q", in, got)
		}
	}
}
