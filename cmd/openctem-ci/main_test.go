package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

const rawSecret = "Zq8vT3xK9mB2nR7wL4pY6sD1fH5jC0gA"

// fakePlatform is a stand-in OpenCTEM CI run API.
type fakePlatform struct {
	mu        sync.Mutex
	exchanges []map[string]any
	uploads   [][]byte
	evaluates []map[string]int
	verdict   string
}

func (f *fakePlatform) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	body, _ := io.ReadAll(r.Body)
	switch {
	case r.URL.Path == "/api/v1/ci/oidc/exchange":
		var m map[string]any
		_ = json.Unmarshal(body, &m)
		f.exchanges = append(f.exchanges, m)
		_ = json.NewEncoder(w).Encode(map[string]any{"run_id": "run-1", "token": "octci_test", "aggregate": m["aggregate"] == true,
			"expires_at": time.Now().Add(15 * time.Minute), "repository": "gitlab.com/acme/app", "commit_sha": "c0ffee"})
	case strings.HasSuffix(r.URL.Path, "/results"):
		if r.Header.Get("Authorization") != "Bearer octci_test" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		f.uploads = append(f.uploads, body)
		_, _ = w.Write([]byte(`{"findings_created":1}`))
	case strings.HasSuffix(r.URL.Path, "/evaluate"):
		var m map[string]int
		_ = json.Unmarshal(body, &m)
		f.evaluates = append(f.evaluates, m)
		v := f.verdict
		if v == "" {
			v = "fail"
		}
		_, _ = w.Write([]byte(`{"run_id":"run-1","verdict":"` + v + `","policy":{"source":"tenant"}}`))
	default:
		http.NotFound(w, r)
	}
}

type harness struct {
	t   *testing.T
	ws  string
	out string
	env map[string]string
	p   *fakePlatform
	url string
}

// setup builds a workspace, stand-in tools on PATH, a fake platform and a
// GitLab CI job environment with an ID token.
func setup(t *testing.T) *harness {
	t.Helper()
	h := &harness{t: t, ws: t.TempDir(), out: t.TempDir(), p: &fakePlatform{}}
	if err := os.MkdirAll(filepath.Join(h.ws, "app"), 0o755); err != nil {
		t.Fatal(err)
	}
	fixture, err := filepath.Abs("testdata/betterleaks.json")
	if err != nil {
		t.Fatal(err)
	}
	bin := t.TempDir()
	write := func(name, script string) {
		if err := os.WriteFile(filepath.Join(bin, name), []byte(script), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	write("betterleaks", `#!/bin/sh
[ "$1" = version ] && { echo "betterleaks version 1.9.0"; exit 0; }
while [ $# -gt 0 ]; do [ "$1" = "--report-path" ] && out="$2"; shift; done
cp "`+fixture+`" "$out"
`)
	write("trivy", "#!/bin/sh\necho 'trivy: database download failed' >&2\nexit 3\n")
	t.Setenv("PATH", bin+":"+os.Getenv("PATH"))
	srv := httptest.NewServer(h.p)
	t.Cleanup(srv.Close)
	h.url = srv.URL
	h.env = map[string]string{
		"PATH": bin + ":" + os.Getenv("PATH"), "HOME": t.TempDir(),
		"GITLAB_CI": "true", "CI_PROJECT_DIR": h.ws, "CI_SERVER_URL": "https://gitlab.com", "CI_PROJECT_PATH": "acme/app",
		"CI_COMMIT_SHA": "c0ffee", "CI_COMMIT_BRANCH": "main", "CI_DEFAULT_BRANCH": "main",
		"OPENCTEM_ID_TOKEN": "gl-id-token", "OPENCTEM_TENANT_ID": "t1", "OPENCTEM_API_URL": srv.URL,
	}
	return h
}

func (h *harness) run(args ...string) (int, string, string) {
	h.t.Helper()
	var stdout, stderr bytes.Buffer
	environ := func() []string {
		var out []string
		for k, v := range h.env {
			out = append(out, k+"="+v)
		}
		return out
	}
	code := run(context.Background(), args, &stdout, &stderr, func(k string) string { return h.env[k] }, environ)
	return code, stdout.String(), stderr.String()
}

func (h *harness) file(name string) string {
	b, err := os.ReadFile(filepath.Join(h.out, name))
	if err != nil {
		h.t.Fatal(err)
	}
	return string(b)
}

func TestScanUploadsMaskedReportAndAsksTheGate(t *testing.T) {
	h := setup(t)
	code, stdout, stderr := h.run("scan", "--capability", "secrets",
		"--sarif", filepath.Join(h.out, "s.sarif"), "--gitlab-report", filepath.Join(h.out, "gl.json"),
		"--ctis", filepath.Join(h.out, "r.json"), "--status", filepath.Join(h.out, "st", "secrets.status.json"))
	if code != 1 {
		t.Fatalf("exit %d (want 1: the platform verdict is fail)\n%s\n%s", code, stdout, stderr)
	}
	for _, name := range []string{"s.sarif", "gl.json", "r.json", "st/secrets.status.json"} {
		if strings.Contains(h.file(name), rawSecret) {
			t.Errorf("%s holds the raw secret", name)
		}
	}
	if strings.Contains(stdout+stderr, rawSecret) {
		t.Error("the log holds the raw secret")
	}
	if len(h.p.uploads) != 1 || strings.Contains(string(h.p.uploads[0]), rawSecret) {
		t.Fatalf("uploads: %d, raw secret uploaded: %v", len(h.p.uploads), len(h.p.uploads) == 1 && strings.Contains(string(h.p.uploads[0]), rawSecret))
	}
	var up struct {
		Report struct {
			Assets []struct {
				Type, Value string
			} `json:"assets"`
			Metadata struct {
				Properties   map[string]any `json:"properties"`
				Capability   string         `json:"capability"`
				CoverageType string         `json:"coverage_type"`
			} `json:"metadata"`
		} `json:"report"`
	}
	if err := json.Unmarshal(h.p.uploads[0], &up); err != nil {
		t.Fatal(err)
	}
	if len(up.Report.Assets) != 1 || up.Report.Assets[0].Value != "gitlab.com/acme/app" ||
		up.Report.Metadata.Properties["capability"] != "secrets.code@1" || up.Report.Metadata.Capability != "" || up.Report.Metadata.CoverageType != "full" {
		t.Fatalf("%+v", up.Report)
	}
	if len(h.p.exchanges) != 1 || h.p.exchanges[0]["id_token"] != "gl-id-token" || h.p.exchanges[0]["aggregate"] != nil {
		t.Fatalf("%+v", h.p.exchanges)
	}
	if len(h.p.evaluates) != 1 || h.p.evaluates[0]["scan_failures"] != 0 {
		t.Fatalf("%+v", h.p.evaluates)
	}
	if !strings.Contains(h.file("gl.json"), `"type": "secret_detection"`) || !strings.Contains(h.file("gl.json"), `"sha": "c0ffee"`) {
		t.Fatalf("%s", h.file("gl.json"))
	}
}

func TestScanPassVerdict(t *testing.T) {
	h := setup(t)
	h.p.verdict = "pass"
	if code, _, stderr := h.run("scan", "--capability", "secrets"); code != 0 {
		t.Fatalf("exit %d: %s", code, stderr)
	}
}

// A merge request from a fork never uploads and never uses the ID token.
func TestForkDoesNotUpload(t *testing.T) {
	h := setup(t)
	h.env["CI_MERGE_REQUEST_IID"] = "4"
	h.env["CI_MERGE_REQUEST_SOURCE_PROJECT_ID"] = "999"
	h.env["CI_MERGE_REQUEST_PROJECT_ID"] = "1"
	code, _, stderr := h.run("scan", "--capability", "secrets", "--sarif", filepath.Join(h.out, "s.sarif"))
	if code != 0 || len(h.p.exchanges) != 0 || len(h.p.uploads) != 0 {
		t.Fatalf("exit %d, %d exchanges, %d uploads: %s", code, len(h.p.exchanges), len(h.p.uploads), stderr)
	}
	if !strings.Contains(stderr, "fork") {
		t.Fatalf("no fork notice: %s", stderr)
	}
	if strings.Contains(h.file("s.sarif"), rawSecret) {
		t.Fatal("raw secret in SARIF")
	}
	// The local gate still works for a fork.
	if code, _, _ := h.run("scan", "--capability", "secrets", "--fail-on", "high"); code != 1 {
		t.Fatalf("local gate exit %d", code)
	}
}

// Aggregate: the scan job reports into the shared run and does not ask
// for a verdict; the gate job asks once, counting the jobs that did not
// report as scan failures.
func TestAggregateScanThenGate(t *testing.T) {
	h := setup(t)
	st := filepath.Join(h.out, "statuses")
	code, stdout, stderr := h.run("scan", "--capability", "secrets", "--aggregate", "--status", filepath.Join(st, "secrets", "secrets.status.json"))
	if code != 0 {
		t.Fatalf("scan exit %d\n%s\n%s", code, stdout, stderr)
	}
	if len(h.p.evaluates) != 0 || h.p.exchanges[0]["aggregate"] != true {
		t.Fatalf("evaluates %v exchanges %v", h.p.evaluates, h.p.exchanges)
	}
	code, _, stderr = h.run("scan", "--capability", "sca", "--aggregate", "--status", filepath.Join(st, "sca", "sca.status.json"))
	if code != 2 || !strings.Contains(stderr, "database download failed") {
		t.Fatalf("a failed tool must exit 2: %d\n%s", code, stderr)
	}

	h.p.verdict = "pass"
	code, stdout, stderr = h.run("gate", "--status-dir", st, "--expect", "secrets,sca,sast")
	if len(h.p.evaluates) != 1 || h.p.evaluates[0]["scan_failures"] != 2 {
		t.Fatalf("evaluates %v\n%s\n%s", h.p.evaluates, stdout, stderr)
	}
	if h.p.exchanges[len(h.p.exchanges)-1]["aggregate"] != true {
		t.Fatal("the gate job did not join the aggregate run")
	}
	if code != 0 || !strings.Contains(stdout, "missing") || !strings.Contains(stdout, "failed") {
		t.Fatalf("exit %d\n%s", code, stdout)
	}

	// Without the platform the gate fails closed on a failed scan.
	delete(h.env, "OPENCTEM_TENANT_ID")
	if code, _, _ := h.run("gate", "--status-dir", st, "--expect", "secrets,sca", "--fail-on", "critical"); code != 2 {
		t.Fatalf("local gate with a failed scan: exit %d", code)
	}
	if code, _, _ := h.run("gate", "--status-dir", st, "--expect", "secrets", "--fail-on", "high"); code != 1 {
		t.Fatalf("local gate on a high secret: exit %d", code)
	}
}

// A tool failure exits 2 and is recorded on the platform run as a scan
// failure (which fails the run there).
func TestToolFailure(t *testing.T) {
	h := setup(t)
	code, _, stderr := h.run("scan", "--capability", "sca", "--status", filepath.Join(h.out, "sca.status.json"))
	if code != 2 {
		t.Fatalf("exit %d: %s", code, stderr)
	}
	if len(h.p.evaluates) != 1 || h.p.evaluates[0]["scan_failures"] != 1 {
		t.Fatalf("%v", h.p.evaluates)
	}
	if !strings.Contains(h.file("sca.status.json"), `"ok": false`) {
		t.Fatal(h.file("sca.status.json"))
	}
}

func TestPlatformUnreachable(t *testing.T) {
	h := setup(t)
	h.env["OPENCTEM_API_URL"] = "http://127.0.0.1:1"
	if code, _, stderr := h.run("scan", "--capability", "secrets"); code != 2 {
		t.Fatalf("no fallback threshold: exit %d %s", code, stderr)
	}
	if code, stdout, _ := h.run("scan", "--capability", "secrets", "--fail-on", "high"); code != 1 || !strings.Contains(stdout, "Local gate: FAIL") {
		t.Fatalf("fallback: exit %d %s", code, stdout)
	}
}

func TestStandaloneAndErrors(t *testing.T) {
	h := setup(t)
	h.env = map[string]string{"PATH": h.env["PATH"], "OPENCTEM_WORKSPACE": h.ws}
	if code, _, stderr := h.run("scan", "--capability", "secrets", "--gitlab-report", filepath.Join(h.out, "gl.json")); code != 0 {
		t.Fatalf("standalone exit %d: %s", code, stderr)
	}
	if len(h.p.exchanges) != 0 {
		t.Fatal("standalone contacted the platform")
	}
	cases := [][]string{
		{"scan"},
		{"scan", "--capability", "sast,sca"},
		{"scan", "--capability", "secrets", "--target", "../.."},
		{"scan", "--capability", "secrets", "--fail-on", "severe"},
		{"scan", "--capability", "container"},
		{"scan", "--capability", "container", "--image", "--input=/etc/passwd"},
		{"gate", "--expect", ""},
		{"nope"},
	}
	for _, c := range cases {
		if code, _, _ := h.run(c...); code != 2 {
			t.Errorf("%v: exit %d, want 2", c, code)
		}
	}
	if code, stdout, _ := h.run("capabilities", "--json"); code != 0 || !strings.Contains(stdout, "secrets.code@1") {
		t.Errorf("capabilities: %d %s", code, stdout)
	}
	if code, stdout, _ := h.run("version"); code != 0 || !strings.Contains(stdout, "openctem-ci") {
		t.Errorf("version: %d %s", code, stdout)
	}
}

func TestReadStatusesRefusesDuplicatesAndJunk(t *testing.T) {
	dir := t.TempDir()
	w := func(p, s string) {
		if err := os.MkdirAll(filepath.Dir(filepath.Join(dir, p)), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, p), []byte(s), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	w("a/sast.status.json", `{"capability":"sast","ok":true}`)
	if _, err := readStatuses(dir); err != nil {
		t.Fatal(err)
	}
	w("b/sast.status.json", `{"capability":"sast","ok":true}`)
	if _, err := readStatuses(dir); err == nil {
		t.Error("two statuses for one capability accepted")
	}
	dir = t.TempDir()
	w("x.status.json", `{"capability":"../../etc","ok":true}`)
	if _, err := readStatuses(dir); err == nil {
		t.Error("an invalid capability name accepted")
	}
	dir = t.TempDir()
	w("x.status.json", `{"capability":"sast","ok":true,"tally":{"severity":{"high":-5}}}`)
	if _, err := readStatuses(dir); err == nil {
		t.Error("a negative tally accepted")
	}
}
