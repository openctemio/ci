package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A semgrep stand-in without a login: every snippet is the placeholder.
const semgrepOut = `{"version":"1.100.0","results":[
 {"check_id":"py.cmdi","path":"app/run.py","start":{"line":5,"col":5,"offset":0},"end":{"line":5,"col":20,"offset":0},
  "extra":{"message":"command injection","severity":"ERROR","lines":"requires login","fingerprint":"requires login","metadata":{}}},
 {"check_id":"py.md5","path":"app/run.py","start":{"line":7,"col":5,"offset":0},"end":{"line":7,"col":20,"offset":0},
  "extra":{"message":"weak hash","severity":"ERROR","lines":"requires login","fingerprint":"requires login","metadata":{}}}
],"errors":[],"paths":{"scanned":["app/run.py"]}}`

func setupSAST(t *testing.T) *harness {
	t.Helper()
	h := setup(t)
	src := "import os, hashlib\n\n\ndef run(cmd):\n    os.system(cmd)\n\n    return hashlib.md5(cmd).hexdigest()\n"
	if err := os.WriteFile(filepath.Join(h.ws, "app", "run.py"), []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}
	fixture := filepath.Join(t.TempDir(), "semgrep.json")
	if err := os.WriteFile(fixture, []byte(semgrepOut), 0o600); err != nil {
		t.Fatal(err)
	}
	bin := strings.SplitN(h.env["PATH"], ":", 2)[0]
	script := `#!/bin/sh
[ "$1" = --version ] && { echo "1.100.0"; exit 0; }
while [ $# -gt 0 ]; do [ "$1" = "--output" ] && out="$2"; shift; done
cp "` + fixture + `" "$out"
`
	if err := os.WriteFile(filepath.Join(bin, "semgrep"), []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	return h
}

// The platform says result 0 is a known false positive: the job leaves it out
// of its SARIF, its merge request report and its summary, keeps it in the
// CTIS record, and says how many it left out. Every SAST result goes up with
// the hash of its code, never the code.
func TestScanLeavesKnownFalsePositivesOutOfItsOutput(t *testing.T) {
	h := setupSAST(t)
	h.p.known = `[{"index":0,"decision":"false_positive","finding_id":"f-1"}]`
	h.p.verdict = "pass"
	code, stdout, stderr := h.run("scan", "--capability", "sast",
		"--sarif", filepath.Join(h.out, "s.sarif"), "--gitlab-report", filepath.Join(h.out, "gl.json"),
		"--ctis", filepath.Join(h.out, "r.json"))
	if code != 0 {
		t.Fatalf("exit %d\n%s\n%s", code, stdout, stderr)
	}
	if !strings.Contains(stdout, "1 result(s) already decided on OpenCTEM are left out of this output (1 false positive)") {
		t.Fatalf("no hidden count in the log:\n%s", stdout)
	}
	if !strings.Contains(stdout, "[sast] 1 finding(s)") {
		t.Fatalf("summary still counts the known result:\n%s", stdout)
	}
	for _, name := range []string{"s.sarif", "gl.json"} {
		body := h.file(name)
		if strings.Contains(body, "py.cmdi") || !strings.Contains(body, "py.md5") {
			t.Errorf("%s: the known false positive is shown or the open result is missing", name)
		}
	}
	if ctisFile := h.file("r.json"); !strings.Contains(ctisFile, "py.cmdi") {
		t.Error("the CTIS record dropped a result")
	}
	if len(h.p.uploads) != 1 {
		t.Fatalf("uploads: %d", len(h.p.uploads))
	}
	var up struct {
		Report struct {
			Findings []struct {
				RuleID   string            `json:"rule_id"`
				Partial  map[string]string `json:"partial_fingerprints"`
				Location struct {
					Snippet string `json:"snippet"`
				} `json:"location"`
			} `json:"findings"`
		} `json:"report"`
	}
	if err := json.Unmarshal(h.p.uploads[0], &up); err != nil {
		t.Fatal(err)
	}
	if len(up.Report.Findings) != 2 {
		t.Fatalf("the platform must receive every result, got %d", len(up.Report.Findings))
	}
	for _, f := range up.Report.Findings {
		if len(f.Partial["snippetHash/v1"]) != 32 {
			t.Errorf("%s: no code hash: %v", f.RuleID, f.Partial)
		}
		if strings.Contains(f.Location.Snippet, "os.system") || strings.Contains(f.Location.Snippet, "hashlib") {
			t.Errorf("%s: the source code was uploaded", f.RuleID)
		}
	}
}

// Without the platform nothing is hidden: the job cannot know.
func TestScanWithoutPlatformHidesNothing(t *testing.T) {
	h := setupSAST(t)
	h.env = map[string]string{"PATH": h.env["PATH"], "OPENCTEM_WORKSPACE": h.ws}
	code, stdout, stderr := h.run("scan", "--capability", "sast", "--sarif", filepath.Join(h.out, "s.sarif"))
	if code != 0 {
		t.Fatalf("exit %d\n%s\n%s", code, stdout, stderr)
	}
	if body := h.file("s.sarif"); !strings.Contains(body, "py.cmdi") || !strings.Contains(body, "py.md5") {
		t.Fatal("a standalone scan hid a result")
	}
}

// Known entries outside the report are ignored; nothing else is hidden.
func TestWithoutKnownIgnoresBadIndexes(t *testing.T) {
	h := setupSAST(t)
	h.p.known = `[{"index":7,"decision":"false_positive"},{"index":-1,"decision":"accepted"}]`
	h.p.verdict = "pass"
	if code, stdout, stderr := h.run("scan", "--capability", "sast", "--sarif", filepath.Join(h.out, "s.sarif")); code != 0 {
		t.Fatalf("exit %d\n%s\n%s", code, stdout, stderr)
	}
	if body := h.file("s.sarif"); !strings.Contains(body, "py.cmdi") || !strings.Contains(body, "py.md5") {
		t.Fatal("an out-of-range index hid a result")
	}
}
