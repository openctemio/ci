package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/openctemio/ci/internal/platform"
)

func readStatusFile(t *testing.T, path string) status {
	t.Helper()
	st, err := readStatus(path)
	if err != nil {
		t.Fatal(err)
	}
	return st
}

func lastCapabilities(t *testing.T, p *fakePlatform) []platform.CapabilityState {
	t.Helper()
	if len(p.evalBodies) == 0 {
		t.Fatal("no verdict request")
	}
	var body struct {
		ScanFailures int                        `json:"scan_failures"`
		Capabilities []platform.CapabilityState `json:"capabilities"`
	}
	if err := json.Unmarshal(p.evalBodies[len(p.evalBodies)-1], &body); err != nil {
		t.Fatal(err)
	}
	return body.Capabilities
}

// Every job records whether its results reached OpenCTEM and, when not,
// why, as a fixed word.
func TestStatusRecordsUploadState(t *testing.T) {
	cases := []struct {
		name         string
		prepare      func(h *harness)
		args         []string
		state, why   string
		ok           bool
		wantExitCode int
	}{
		{"uploaded", nil, nil, uploadDone, "", true, 1},
		{"rejected", func(h *harness) { h.p.rejectUploads = true }, []string{"--aggregate"}, uploadFailed, "http_400", true, 0},
		{"no tenant", func(h *harness) { delete(h.env, "OPENCTEM_TENANT_ID") }, nil, uploadSkipped, "no_tenant", true, 0},
		{"no push", nil, []string{"--no-push"}, uploadSkipped, "no_push", true, 0},
		{"fork", func(h *harness) {
			h.env["CI_MERGE_REQUEST_IID"], h.env["CI_MERGE_REQUEST_SOURCE_PROJECT_ID"], h.env["CI_MERGE_REQUEST_PROJECT_ID"] = "4", "9", "1"
		}, nil, uploadSkipped, "fork", true, 0},
		{"no token", func(h *harness) { delete(h.env, "OPENCTEM_ID_TOKEN") }, nil, uploadFailed, "no_oidc", false, 2},
		{"no token, opted out", func(h *harness) {
			delete(h.env, "OPENCTEM_ID_TOKEN")
			h.env["OPENCTEM_ENFORCE"] = "false"
		}, nil, uploadSkipped, "no_oidc", true, 0},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			h := setup(t)
			h.p.verdict = "fail"
			if c.prepare != nil {
				c.prepare(h)
			}
			path := filepath.Join(h.out, "secrets.status.json")
			code, _, stderr := h.run(append([]string{"scan", "--capability", "secrets", "--status", path}, c.args...)...)
			if code != c.wantExitCode {
				t.Fatalf("exit %d, want %d: %s", code, c.wantExitCode, stderr)
			}
			st := readStatusFile(t, path)
			if st.Upload != c.state || st.UploadReason != c.why || st.OK != c.ok {
				t.Fatalf("upload %q (%q), ok %v; want %q (%q), %v", st.Upload, st.UploadReason, st.OK, c.state, c.why, c.ok)
			}
		})
	}
}

// A tool that crashes and wrote nothing: the status says failed and not
// uploaded, and the verdict request names the failed capability.
func TestToolCrashIsAFailedCapability(t *testing.T) {
	h := setup(t)
	path := filepath.Join(h.out, "sca.status.json")
	if code, _, _ := h.run("scan", "--capability", "sca", "--status", path); code != 2 {
		t.Fatalf("exit %d", code)
	}
	st := readStatusFile(t, path)
	if st.OK || st.Upload != uploadFailed || st.UploadReason != "scan_failed" || st.ErrorClass != "scan_failed" || st.Partial {
		t.Fatalf("%+v", st)
	}
	if len(h.p.uploads) != 0 {
		t.Fatal("a crashed tool uploaded a report (it would look clean)")
	}
	caps := lastCapabilities(t, h.p)
	if len(caps) != 1 || caps[0].Name != "sca" || caps[0].State != "failed" || caps[0].Reason != "scan_failed" {
		t.Fatalf("%+v", caps)
	}
	if h.p.evaluates[0]["scan_failures"] != 1 {
		t.Fatalf("%v", h.p.evaluates)
	}
}

const trivyPartial = `{"SchemaVersion":2,"ArtifactName":".","ArtifactType":"filesystem","Results":[{"Target":"package-lock.json",` +
	`"Class":"lang-pkgs","Type":"npm","Vulnerabilities":[{"VulnerabilityID":"CVE-2021-23337","PkgName":"lodash",` +
	`"InstalledVersion":"4.17.15","FixedVersion":"4.17.21","Severity":"HIGH","Title":"lodash: command injection"}]}]}`

// A tool that crashes after writing a report: what it found goes up marked
// partial (coverage partial, scan state failed), the scan still fails, and
// the verdict request counts it as a failure with the state "partial".
func TestToolCrashUploadsPartialResultsMarkedPartial(t *testing.T) {
	h := setup(t)
	bin := t.TempDir()
	report := filepath.Join(t.TempDir(), "trivy.json")
	if err := os.WriteFile(report, []byte(trivyPartial), 0o600); err != nil {
		t.Fatal(err)
	}
	script := "#!/bin/sh\n[ \"$1\" = --version ] && { echo 'Version: 0.70.0'; exit 0; }\nwhile [ $# -gt 0 ]; do [ \"$1\" = --output ] && out=\"$2\"; shift; done\ncp " + report + " \"$out\"\necho 'trivy: killed' >&2\nexit 3\n"
	if err := os.WriteFile(filepath.Join(bin, "trivy"), []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	h.env["PATH"] = bin + ":" + h.env["PATH"]
	path := filepath.Join(h.out, "sca.status.json")
	sarif := filepath.Join(h.out, "sca.sarif")
	code, _, stderr := h.run("scan", "--capability", "sca", "--status", path, "--sarif", sarif)
	if code != 2 || !strings.Contains(stderr, "marked partial") {
		t.Fatalf("exit %d: %s", code, stderr)
	}
	if len(h.p.uploads) != 1 {
		t.Fatalf("%d uploads", len(h.p.uploads))
	}
	var body struct {
		Report struct {
			Metadata struct {
				CoverageType string         `json:"coverage_type"`
				Properties   map[string]any `json:"properties"`
			} `json:"metadata"`
			Findings []json.RawMessage `json:"findings"`
		} `json:"report"`
	}
	if err := json.Unmarshal(h.p.uploads[0], &body); err != nil {
		t.Fatal(err)
	}
	md := body.Report.Metadata
	if md.CoverageType != "partial" || md.Properties["openctem_scan_state"] != "failed" || md.Properties["openctem_scan_error"] != "scan_failed" {
		t.Fatalf("the partial report is not marked: %+v", md)
	}
	if len(body.Report.Findings) != 1 {
		t.Fatalf("%d findings uploaded", len(body.Report.Findings))
	}
	st := readStatusFile(t, path)
	if st.OK || !st.Partial || st.Upload != uploadDone {
		t.Fatalf("%+v", st)
	}
	caps := lastCapabilities(t, h.p)
	if h.p.evaluates[0]["scan_failures"] != 1 || len(caps) != 1 || caps[0].State != "partial" {
		t.Fatalf("%v %+v", h.p.evaluates, caps)
	}
	if _, err := os.Stat(sarif); !os.IsNotExist(err) {
		t.Fatal("partial results were written as the job's SARIF")
	}
}

// The gate job sends each capability's state with the verdict request,
// re-uploads what a scan job could not, and shows why a capability is not
// uploaded.
func TestGateSendsCapabilityStates(t *testing.T) {
	h := setup(t)
	st := filepath.Join(h.out, "statuses")
	h.p.rejectUploads = true
	if code, _, stderr := h.run("scan", "--capability", "secrets", "--aggregate", "--status", filepath.Join(st, "secrets.status.json")); code != 0 {
		t.Fatalf("scan: %d %s", code, stderr)
	}
	if code, _, _ := h.run("scan", "--capability", "sca", "--aggregate", "--status", filepath.Join(st, "sca.status.json")); code != 2 {
		t.Fatal("sca must fail")
	}

	// The upload still fails in the gate job: not uploaded, with the reason.
	code, stdout, _ := h.run("gate", "--status-dir", st, "--expect", "secrets,sca,iac")
	if code == 0 || !strings.Contains(stdout, "not uploaded (http_400)") {
		t.Fatalf("exit %d\n%s", code, stdout)
	}
	want := map[string]string{"secrets": "not_uploaded/http_400", "sca": "failed/scan_failed", "iac": "missing/"}
	got := map[string]string{}
	for _, c := range lastCapabilities(t, h.p) {
		got[c.Name] = c.State + "/" + c.Reason
	}
	for k, v := range want {
		if got[k] != v {
			t.Fatalf("%s: %q, want %q (%v)", k, got[k], v, got)
		}
	}

	// The platform takes uploads again: the gate uploads the kept report.
	h.p.rejectUploads = false
	h.p.verdict = "pass"
	if _, stdout, _ := h.run("gate", "--status-dir", st, "--expect", "secrets"); !strings.Contains(stdout, "could not upload") {
		t.Fatalf("no catch-up:\n%s", stdout)
	}
	if caps := lastCapabilities(t, h.p); len(caps) != 1 || caps[0].State != "uploaded" {
		t.Fatalf("%+v", caps)
	}
}

func TestReadStatusRefusesOddUploadStates(t *testing.T) {
	dir := t.TempDir()
	for _, body := range []string{
		`{"capability":"sca","upload":"maybe"}`,
		`{"capability":"sca","upload":"not_uploaded","upload_reason":"Server said: <script>"}`,
		`{"capability":"sca","ok":false,"error_class":"` + strings.Repeat("x", 40) + `"}`,
	} {
		p := filepath.Join(dir, "sca.status.json")
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := readStatus(p); err == nil {
			t.Errorf("accepted %s", body)
		}
	}
}
