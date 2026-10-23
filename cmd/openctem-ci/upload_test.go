package main

import (
	"archive/zip"
	"crypto/sha256"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/openctemio/ci/internal/platform"
)

const (
	sarifReport = `{"$schema":"https://json.schemastore.org/sarif-2.1.0.json","version":"2.1.0","runs":[{"tool":{"driver":{"name":"scanner"}},"results":[]}]}`
	zapReport   = `<?xml version="1.0"?><OWASPZAPReport version="2.14.0" generated="now"><site name="https://app.example" host="app.example" port="443" ssl="true"><alerts></alerts></site></OWASPZAPReport>`
)

func (h *harness) report(name, content string) string {
	h.t.Helper()
	p := filepath.Join(h.out, name)
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		h.t.Fatal(err)
	}
	return p
}

func TestUploadSendsEachFileAsIsAndPrintsTheReceipt(t *testing.T) {
	h := setup(t)
	sarifPath := h.report("scan.sarif", sarifReport)
	zapPath := h.report("zap.xml", zapReport)
	receiptPath := filepath.Join(h.out, "out", "receipt.json")
	code, stdout, stderr := h.run("upload", "--receipt", receiptPath, sarifPath, zapPath)
	if code != 0 {
		t.Fatalf("exit %d\n%s\n%s", code, stdout, stderr)
	}
	if len(h.p.uploads) != 2 || string(h.p.uploads[0]) != sarifReport || string(h.p.uploads[1]) != zapReport {
		t.Fatalf("uploads: %q", h.p.uploads)
	}
	for i, content := range []string{sarifReport, zapReport} {
		if want := platform.IdempotencyKey("run-1", sha256.Sum256([]byte(content))); h.p.uploadKeys[i] != want {
			t.Errorf("file %d key %q, want %q (run id + file digest)", i, h.p.uploadKeys[i], want)
		}
	}
	if len(h.p.evaluates) != 0 {
		t.Error("no gate without --gate")
	}
	for _, want := range []string{"STILL DETECTED", "RESOLVED", "REOPENED", "TOTAL", "partial: an upload never closes findings", "gitlab.com/acme/app"} {
		if !strings.Contains(stdout, want) {
			t.Errorf("stdout lacks %q:\n%s", want, stdout)
		}
	}
	var rec receipt
	b, err := os.ReadFile(receiptPath)
	if err != nil || json.Unmarshal(b, &rec) != nil {
		t.Fatalf("receipt file: %v %s", err, b)
	}
	if rec.RunID != "run-1" || len(rec.Files) != 2 || rec.Files[0].Format != "sarif" || rec.Files[1].Format != "zap" || rec.Total.New != 2 {
		t.Errorf("receipt %+v", rec)
	}
	if rec.Total.Resolved != nil {
		t.Error("resolved must stay unknown: the platform did not report it")
	}
}

func TestUploadRetriedJobSendsTheSameKey(t *testing.T) {
	h := setup(t)
	p := h.report("scan.sarif", sarifReport)
	h.env["OPENCTEM_TOKEN_CACHE"] = "off"
	for i := 0; i < 2; i++ {
		if code, stdout, stderr := h.run("upload", p); code != 0 {
			t.Fatalf("run %d: exit %d\n%s\n%s", i+1, code, stdout, stderr)
		}
	}
	if len(h.p.uploadKeys) != 2 || h.p.uploadKeys[0] != h.p.uploadKeys[1] || h.p.uploadKeys[0] == "" {
		t.Fatalf("keys %q: a repeated upload of the same file to the same run carries the same key, so the platform replays instead of importing again", h.p.uploadKeys)
	}
}

func TestUploadSameContentTwiceIsSentOnce(t *testing.T) {
	h := setup(t)
	a := h.report("a.sarif", sarifReport)
	b := h.report("b.sarif", sarifReport)
	code, stdout, stderr := h.run("upload", a, b)
	if code != 0 || len(h.p.uploads) != 1 {
		t.Fatalf("exit %d, %d uploads\n%s\n%s", code, len(h.p.uploads), stdout, stderr)
	}
	if !strings.Contains(stdout, "not sent again") {
		t.Errorf("stdout:\n%s", stdout)
	}
}

func TestUploadAuthFailureFailsWithoutSending(t *testing.T) {
	h := setup(t)
	h.p.refuseExchange = true
	p := h.report("scan.sarif", sarifReport)
	code, stdout, stderr := h.run("upload", "--gate", p, h.report("zap.xml", zapReport))
	if code != 2 {
		t.Fatalf("exit %d (want 2)\n%s\n%s", code, stdout, stderr)
	}
	if len(h.p.uploads) != 0 || len(h.p.evaluates) != 0 || len(h.p.exchanges) != 1 {
		t.Errorf("uploads %d, evaluates %d, exchanges %d: one refused exchange, nothing else", len(h.p.uploads), len(h.p.evaluates), len(h.p.exchanges))
	}
	if !strings.Contains(stderr, "no trust configuration admits this job") || strings.Contains(stderr+stdout, "gl-id-token") {
		t.Errorf("stderr:\n%s", stderr)
	}
}

func TestUploadRejectsLargeFileBeforeAnyRequest(t *testing.T) {
	h := setup(t)
	big := filepath.Join(h.out, "big.json")
	f, err := os.Create(big)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Truncate(platform.MaxFileBytes + 1); err != nil { // sparse: no disk use
		t.Fatal(err)
	}
	_ = f.Close()
	code, _, stderr := h.run("upload", h.report("scan.sarif", sarifReport), big)
	if code != 2 || !strings.Contains(stderr, "larger than the 50.0 MiB") {
		t.Fatalf("exit %d\n%s", code, stderr)
	}
	if len(h.p.exchanges) != 0 || len(h.p.uploads) != 0 {
		t.Error("every file is checked before anything is sent")
	}
}

func TestUploadRejectsUnknownFormat(t *testing.T) {
	h := setup(t)
	code, _, stderr := h.run("upload", h.report("notes.txt", "just some text\n"))
	if code != 2 || !strings.Contains(stderr, "unknown format") || !strings.Contains(stderr, "sarif") {
		t.Fatalf("exit %d\n%s", code, stderr)
	}
	if len(h.p.exchanges) != 0 {
		t.Error("no exchange for a file that cannot be uploaded")
	}
	code, _, stderr = h.run("upload", "--format", "nope", h.report("scan.sarif", sarifReport))
	if code != 2 || !strings.Contains(stderr, "unknown --format") {
		t.Fatalf("exit %d\n%s", code, stderr)
	}
}

func TestUploadFormatHintMustMatch(t *testing.T) {
	h := setup(t)
	code, _, stderr := h.run("upload", "--format", "trivy", h.report("scan.sarif", sarifReport))
	if code != 2 || !strings.Contains(stderr, "the file is sarif, not trivy") {
		t.Fatalf("exit %d\n%s", code, stderr)
	}
	if code, _, stderr := h.run("upload", "--format", "sarif", h.report("scan2.sarif", sarifReport)); code != 0 {
		t.Fatalf("exit %d\n%s", code, stderr)
	}
}

func TestUploadRefusesRawSecretReports(t *testing.T) {
	h := setup(t)
	leaks, err := os.ReadFile("testdata/betterleaks.json")
	if err != nil {
		t.Fatal(err)
	}
	p := h.report("leaks.json", string(leaks))
	code, _, stderr := h.run("upload", p)
	if code != 2 || !strings.Contains(stderr, "raw value of every secret") {
		t.Fatalf("exit %d\n%s", code, stderr)
	}
	// Inside an archive too.
	zp := filepath.Join(h.out, "reports.zip")
	zf, err := os.Create(zp)
	if err != nil {
		t.Fatal(err)
	}
	zw := zip.NewWriter(zf)
	for name, content := range map[string]string{"zap.xml": zapReport, "leaks.json": string(leaks)} {
		w, _ := zw.Create(name)
		_, _ = w.Write([]byte(content))
	}
	_ = zw.Close()
	_ = zf.Close()
	code, _, stderr = h.run("upload", zp)
	if code != 2 || !strings.Contains(stderr, "archive file leaks.json") {
		t.Fatalf("exit %d\n%s", code, stderr)
	}
	if len(h.p.uploads) != 0 || strings.Contains(stderr, rawSecret) {
		t.Error("nothing is sent and no secret is printed")
	}
}

func TestUploadZipOfReports(t *testing.T) {
	h := setup(t)
	zp := filepath.Join(h.out, "reports.zip")
	zf, err := os.Create(zp)
	if err != nil {
		t.Fatal(err)
	}
	zw := zip.NewWriter(zf)
	for name, content := range map[string]string{"zap.xml": zapReport, "scan.sarif": sarifReport} {
		w, _ := zw.Create(name)
		_, _ = w.Write([]byte(content))
	}
	_ = zw.Close()
	_ = zf.Close()
	if code, stdout, stderr := h.run("upload", zp); code != 0 || len(h.p.uploads) != 1 {
		t.Fatalf("exit %d\n%s\n%s", code, stdout, stderr)
	}
}

func TestUploadDirectoryAndCountLimit(t *testing.T) {
	h := setup(t)
	dir := filepath.Join(h.out, "reports")
	if err := os.MkdirAll(filepath.Join(dir, "sub"), 0o755); err != nil {
		t.Fatal(err)
	}
	for _, n := range []string{"b.sarif", "a.xml"} {
		content := sarifReport
		if strings.HasSuffix(n, ".xml") {
			content = zapReport
		}
		if err := os.WriteFile(filepath.Join(dir, n), []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink("/etc/hostname", filepath.Join(dir, "link.json")); err != nil {
		t.Fatal(err)
	}
	code, stdout, stderr := h.run("upload", dir)
	if code != 0 || len(h.p.uploads) != 2 || string(h.p.uploads[0]) != zapReport {
		t.Fatalf("exit %d, uploads %d (a directory: its regular files, sorted; no links, no subdirectories)\n%s\n%s", code, len(h.p.uploads), stdout, stderr)
	}

	many := filepath.Join(h.out, "many")
	if err := os.MkdirAll(many, 0o755); err != nil {
		t.Fatal(err)
	}
	for i := 0; i <= maxUploadFiles; i++ {
		_ = os.WriteFile(filepath.Join(many, "r"+strings.Repeat("x", i)+".sarif"), []byte(sarifReport), 0o600)
	}
	code, _, stderr = h.run("upload", many)
	if code != 2 || !strings.Contains(stderr, "at most 50 per upload") {
		t.Fatalf("exit %d\n%s", code, stderr)
	}
}

func TestUploadWithGateAsksForTheVerdict(t *testing.T) {
	h := setup(t)
	h.p.verdict = "fail"
	code, stdout, stderr := h.run("upload", "--gate", h.report("scan.sarif", sarifReport))
	if code != 1 || len(h.p.evaluates) != 1 || h.p.evaluates[0]["scan_failures"] != 0 {
		t.Fatalf("exit %d, evaluates %v\n%s\n%s", code, h.p.evaluates, stdout, stderr)
	}
	if code, _, stderr := h.run("upload", "--gate", "--aggregate", h.report("x.sarif", sarifReport)); code != 2 || !strings.Contains(stderr, "final 'gate' job") {
		t.Fatalf("exit %d\n%s", code, stderr)
	}
}

func TestUploadFailedFileFailsTheJobAndTheGate(t *testing.T) {
	h := setup(t)
	h.p.rejectUploads = true
	h.p.verdict = "pass"
	code, stdout, stderr := h.run("upload", "--gate", h.report("scan.sarif", sarifReport))
	if code != 2 || len(h.p.evaluates) != 1 || h.p.evaluates[0]["scan_failures"] != 1 {
		t.Fatalf("exit %d, evaluates %v\n%s\n%s", code, h.p.evaluates, stdout, stderr)
	}
	code, _, stderr = h.run("upload", "--on-upload-error", "warn", h.report("scan2.sarif", sarifReport))
	if code != 0 || !strings.Contains(stderr, "--on-upload-error warn") {
		t.Fatalf("exit %d\n%s", code, stderr)
	}
}

func TestUploadIdentity(t *testing.T) {
	h := setup(t)
	p := h.report("scan.sarif", sarifReport)

	h.env["CI_MERGE_REQUEST_IID"], h.env["CI_MERGE_REQUEST_SOURCE_PROJECT_ID"], h.env["CI_MERGE_REQUEST_PROJECT_ID"] = "5", "2", "1"
	code, _, stderr := h.run("upload", p)
	if code != 0 || !strings.Contains(stderr, "fork") || len(h.p.exchanges) != 0 {
		t.Fatalf("fork: exit %d\n%s", code, stderr)
	}
	delete(h.env, "CI_MERGE_REQUEST_SOURCE_PROJECT_ID")
	delete(h.env, "CI_MERGE_REQUEST_PROJECT_ID")
	delete(h.env, "CI_MERGE_REQUEST_IID")

	delete(h.env, "OPENCTEM_ID_TOKEN")
	if code, _, stderr := h.run("upload", p); code != 2 || !strings.Contains(stderr, "no OIDC token") {
		t.Fatalf("no token: exit %d\n%s", code, stderr)
	}
	h.env["OPENCTEM_ENFORCE"] = "false"
	if code, _, stderr := h.run("upload", p); code != 0 || !strings.Contains(stderr, "nothing is uploaded") {
		t.Fatalf("no token, enforce off: exit %d\n%s", code, stderr)
	}
	delete(h.env, "OPENCTEM_TENANT_ID")
	if code, _, stderr := h.run("upload", p); code != 2 || !strings.Contains(stderr, "OPENCTEM_TENANT_ID is not set") {
		t.Fatalf("no tenant: exit %d\n%s", code, stderr)
	}
	if len(h.p.uploads) != 0 {
		t.Error("nothing is uploaded without an identity")
	}
}
