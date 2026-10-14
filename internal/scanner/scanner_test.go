package scanner

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/openctemio/ctis/importer"

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
	// opengrep (the default engine) refuses --metrics; semgrep gets it.
	argv, format, _ := Command(capOf(t, "sast"), Options{}, "o")
	if j := strings.Join(argv, " "); argv[0] != "opengrep" || strings.Contains(j, "--metrics") || !strings.Contains(j, DefaultSASTRules) ||
		!strings.Contains(j, "--no-rewrite-rule-ids") || !strings.Contains(j, "--dataflow-traces") || format != importer.FormatOpengrep {
		t.Errorf("opengrep: %v %s", argv, format)
	}
	sg := capOf(t, "sast")
	sg.Tool = "semgrep"
	argv, format, _ = Command(sg, Options{SASTRules: "rules/"}, "o")
	if j := strings.Join(argv, " "); argv[0] != "semgrep" || !strings.Contains(j, "--metrics=off") || !strings.Contains(j, "--config rules/") ||
		!strings.Contains(j, "--dataflow-traces") || format != importer.FormatSemgrep {
		t.Errorf("semgrep: %v %s", argv, format)
	}
	if _, _, err := Command(capOf(t, "sast"), Options{SASTRules: "--dangerous"}, "o"); err == nil {
		t.Error("sast rules that are an option were accepted")
	}
	sg.Tool = "other"
	if _, _, err := Command(sg, Options{}, "o"); err == nil {
		t.Error("an unknown sast engine was accepted")
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
	if strings.Contains(out, "BETTERLEAKS_CONFIG_TOML=") {
		t.Fatalf("the pipeline's betterleaks configuration was overridden:\n%s", out)
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

// A diff-aware sast scan passes the merge base to semgrep; anything but a
// commit id is dropped.
func TestCommandBaselineCommit(t *testing.T) {
	sast := capOf(t, "sast")
	base := strings.Repeat("b", 40)
	argv, _, err := Command(sast, Options{BaselineCommit: base}, "out.json")
	if err != nil || !strings.Contains(strings.Join(argv, " "), "--baseline-commit "+base+" .") {
		t.Fatalf("argv = %v %v", argv, err)
	}
	for _, bad := range []string{"--help", "HEAD", "abc", strings.Repeat("g", 40)} {
		argv, _, _ = Command(sast, Options{BaselineCommit: bad}, "out.json")
		if strings.Contains(strings.Join(argv, " "), "--baseline-commit") {
			t.Fatalf("baseline %q used: %v", bad, argv)
		}
	}
}

// A file committed in the scanned tree (the change under review) must not
// configure the scanners: a pull request could raise trivy's severity
// threshold, add a .trivyignore, or allowlist its own secret in
// .gitleaks.toml and pass the gate.
func TestRepositoryFilesDoNotConfigureScanners(t *testing.T) {
	for _, name := range []string{"sca", "iac"} {
		argv, _, err := Command(capOf(t, name), Options{}, "/tmp/x/report.json")
		if err != nil {
			t.Fatal(err)
		}
		if !hasFlagValue(argv, "--config", "") || !hasFlagValue(argv, "--ignorefile", "") {
			t.Errorf("%s: trivy would read trivy.yaml or .trivyignore from the tree: %v", name, argv)
		}
	}
	argv, _, err := Command(capOf(t, "secrets"), Options{}, "/tmp/x/report.json")
	if err != nil {
		t.Fatal(err)
	}
	if !hasFlagValue(argv, "--gitleaks-ignore-path", "/tmp/x") {
		t.Errorf("betterleaks would read an ignore file from the tree: %v", argv)
	}

	got := defaultConfigEnv("betterleaks", []string{"PATH=/bin"})
	if len(got) != 1 || got[0] != "BETTERLEAKS_CONFIG_TOML=[extend]\nuseDefault = true\n" {
		t.Errorf("betterleaks would read .gitleaks.toml from the tree: %q", got)
	}
	for _, k := range []string{"BETTERLEAKS_CONFIG", "GITLEAKS_CONFIG", "BETTERLEAKS_CONFIG_TOML", "GITLEAKS_CONFIG_TOML"} {
		if got := defaultConfigEnv("betterleaks", []string{k + "=x"}); got != nil {
			t.Errorf("the pipeline's %s was overridden: %q", k, got)
		}
	}
	if got := defaultConfigEnv("trivy", nil); got != nil {
		t.Errorf("trivy: %q", got)
	}
}

func hasFlagValue(argv []string, flag, value string) bool {
	for i := 0; i+1 < len(argv); i++ {
		if argv[i] == flag && argv[i+1] == value {
			return true
		}
	}
	return false
}

// A target inside the repository: git works on the repository root (the
// file list, the baseline commit), so the root is trusted too; no other
// directory is.
func TestToolEnvTrustsTargetAndRoot(t *testing.T) {
	env := strings.Join(toolEnv("semgrep", "/tmp/o", "/src/svc", "/src"), "\n")
	for _, want := range []string{"GIT_CONFIG_COUNT=2", "GIT_CONFIG_VALUE_0=/src/svc", "GIT_CONFIG_VALUE_1=/src"} {
		if !strings.Contains(env, want) {
			t.Errorf("missing %s in\n%s", want, env)
		}
	}
	env = strings.Join(toolEnv("semgrep", "/tmp/o", "/src", "/src"), "\n")
	if !strings.Contains(env, "GIT_CONFIG_COUNT=1") || strings.Contains(env, "GIT_CONFIG_KEY_1") {
		t.Errorf("the root listed twice:\n%s", env)
	}
}

// On a pull request the secret scan covers only the change's commits (git
// mode over merge-base..HEAD), with the same hardening as a full scan;
// without a valid merge base it scans the whole tree.
func TestSecretsDiffAware(t *testing.T) {
	secrets := capOf(t, "secrets")
	base := strings.Repeat("c", 40)
	argv, _, err := Command(secrets, Options{BaselineCommit: base}, "/tmp/x/report.json")
	if err != nil {
		t.Fatal(err)
	}
	if argv[1] != "git" || !slicesContains(argv, "--log-opts="+base+"..HEAD") {
		t.Fatalf("diff-aware argv = %v", argv)
	}
	if !hasFlagValue(argv, "--gitleaks-ignore-path", "/tmp/x") || !slicesContains(argv, "--ignore-gitleaks-allow") || slicesContains(argv, "--verbose") {
		t.Fatalf("hardening lost in git mode: %v", argv)
	}
	for _, bad := range []string{"", "HEAD~1", "--all", strings.Repeat("g", 40), base + " --all"} {
		argv, _, _ = Command(secrets, Options{BaselineCommit: bad}, "/tmp/x/report.json")
		if argv[1] != "dir" || strings.Contains(strings.Join(argv, " "), "--log-opts") {
			t.Fatalf("baseline %q: %v", bad, argv)
		}
	}
}

func slicesContains(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}

// The sast engine is the first of opengrep, semgrep the image has: the
// ci-opengrep image runs opengrep, the ci-semgrep image keeps semgrep.
func TestResolveSASTEngine(t *testing.T) {
	bin := func(names ...string) string {
		d := t.TempDir()
		for _, n := range names {
			if err := os.WriteFile(filepath.Join(d, n), []byte("#!/bin/sh\n"), 0o700); err != nil { //nolint:gosec // test script
				t.Fatal(err)
			}
		}
		return d
	}
	for _, c := range []struct {
		have []string
		want string
	}{{[]string{"opengrep", "semgrep"}, "opengrep"}, {[]string{"semgrep"}, "semgrep"}, {nil, "opengrep"}} {
		dir := bin(c.have...)
		got := Resolve(capOf(t, "sast"), func() []string { return []string{"PATH=" + dir} })
		if got.Tool != c.want {
			t.Errorf("with %v: %s, want %s", c.have, got.Tool, c.want)
		}
	}
	if got := Resolve(capOf(t, "sca"), nil); got.Tool != "trivy" {
		t.Errorf("sca resolved to %s", got.Tool)
	}
}

// opengrep's log goes to the private output directory.
func TestToolEnvOpengrep(t *testing.T) {
	env := strings.Join(toolEnv("opengrep", "/tmp/o", "/src", "/src"), "\n")
	if !strings.Contains(env, "XDG_CONFIG_HOME=/tmp/o") || strings.Contains(env, "SEMGREP_") {
		t.Errorf("env %s", env)
	}
}

// Inline ignore comments and the tree's .semgrepignore never hide a result:
// both engines run with --disable-nosem and --x-ignore-semgrepignore-files,
// and the default excludes come from the pipeline.
func TestSASTIgnoresRepositoryClaims(t *testing.T) {
	for _, tool := range []string{"opengrep", "semgrep"} {
		c := capOf(t, "sast")
		c.Tool = tool
		argv, _, err := Command(c, Options{Target: "."}, "/tmp/out.json")
		if err != nil {
			t.Fatal(err)
		}
		j := strings.Join(argv, " ")
		if !strings.Contains(j, "--disable-nosem") || !strings.Contains(j, "--x-ignore-semgrepignore-files") ||
			!strings.Contains(j, "--exclude node_modules") {
			t.Errorf("%s: %s", tool, j)
		}
	}
}

// The image's rules pack is the default when the image has one; "openctem"
// names it, and is refused in an image without it.
func TestSASTRulesPack(t *testing.T) {
	old := PackDir
	t.Cleanup(func() { PackDir = old })
	PackDir = filepath.Join(t.TempDir(), "absent")
	if got, err := sastRules(""); err != nil || got != DefaultSASTRules {
		t.Fatalf("no pack: %q %v", got, err)
	}
	if _, err := sastRules(PackRules); err == nil {
		t.Fatal("openctem accepted without a pack")
	}
	PackDir = t.TempDir()
	for in, want := range map[string]string{"": PackDir, PackRules: PackDir, "rules/": "rules/", "p/default": "p/default"} {
		if got, err := sastRules(in); err != nil || got != want {
			t.Errorf("%q: %q %v, want %q", in, got, err, want)
		}
	}
	argv, _, err := Command(capOf(t, "sast"), Options{}, "o")
	if err != nil || !strings.Contains(strings.Join(argv, " "), "--config "+PackDir) {
		t.Fatalf("argv %v %v", argv, err)
	}
}
