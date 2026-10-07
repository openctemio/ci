package gitlab

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/santhosh-tekuri/jsonschema/v6"

	"github.com/openctemio/ctis"
)

// The schemas are the published GitLab security report schemas v15.2.5
// (MIT, testdata/schemas/v15.2.5/LICENSE.md), vendored so the test runs
// offline and a schema change is a deliberate bump.
func validator(t *testing.T, reportType string) *jsonschema.Schema {
	t.Helper()
	path := filepath.Join("testdata", "schemas", "v"+SchemaVersion, schemaFile[reportType])
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	doc, err := jsonschema.UnmarshalJSON(f)
	if err != nil {
		t.Fatal(err)
	}
	c := jsonschema.NewCompiler()
	if err := c.AddResource(SchemaURL(reportType), doc); err != nil {
		t.Fatal(err)
	}
	s, err := c.Compile(SchemaURL(reportType))
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func validate(t *testing.T, reportType string, data []byte) {
	t.Helper()
	inst, err := jsonschema.UnmarshalJSON(bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	if err := validator(t, reportType).Validate(inst); err != nil {
		t.Fatalf("%s report does not validate: %v\n%s", reportType, err, data)
	}
}

var when = time.Date(2026, 10, 7, 12, 0, 0, 0, time.UTC)

func sample() *ctis.Report {
	return &ctis.Report{
		Tool: &ctis.Tool{Name: "trivy", Version: "0.75.0"},
		Findings: []ctis.Finding{
			{Type: ctis.FindingTypeVulnerability, Title: "flask: DoS", Severity: "high", Fingerprint: "fp1",
				Location: &ctis.FindingLocation{Path: "app/requirements.txt"},
				Vulnerability: &ctis.VulnerabilityDetails{CVEID: "CVE-2018-1000656", Package: "flask",
					AffectedVersion: "0.12.2", FixedVersion: "0.12.3", CWEIDs: []string{"CWE-20"}},
				References: []string{"https://avd.example/cve", "javascript:alert(1)"}},
			{Type: ctis.FindingTypeVulnerability, Title: "no location", Severity: "low",
				Vulnerability: &ctis.VulnerabilityDetails{CVEID: "CVE-2020-1", Package: "openssl", AffectedVersion: "1.1"}},
			{Type: ctis.FindingTypeVulnerability, Title: "Command injection", Severity: "critical", RuleID: "py.cmdi",
				RuleName: "Subprocess injection", Location: &ctis.FindingLocation{Path: "app/app.py", StartLine: 13, EndLine: 13}},
			{Type: ctis.FindingTypeSecret, Title: "Generic API key", Severity: "bogus", RuleID: "generic-api-key",
				Location: &ctis.FindingLocation{Path: "app/settings.py", StartLine: 2, Snippet: "api_key = \"Zq8v****\""},
				Secret:   &ctis.SecretDetails{MaskedValue: "Zq8v****"}},
		},
	}
}

func TestReportsValidateAgainstSchemas(t *testing.T) {
	cases := []struct {
		typ   string
		opts  Options
		wantN int
	}{
		{TypeSAST, Options{}, 3},                                                                  // every finding with a file
		{TypeDependencyScanning, Options{}, 1},                                                    // file + package
		{TypeSecretDetection, Options{Commit: "0123abcd"}, 3},                                     // file + commit
		{TypeContainerScanning, Options{Image: "alpine:3.20", OperatingSystem: "alpine 3.20"}, 2}, // package
	}
	for _, c := range cases {
		c.opts.Type, c.opts.Start, c.opts.End, c.opts.AnalyzerVersion = c.typ, when, when.Add(time.Minute), "v0.1.0"
		r, st, err := FromReport(sample(), c.opts)
		if err != nil {
			t.Fatal(err)
		}
		data, err := r.Marshal()
		if err != nil {
			t.Fatal(err)
		}
		validate(t, c.typ, data)
		if st.Written != c.wantN || len(r.Vulnerabilities) != c.wantN {
			t.Errorf("%s: wrote %d, want %d", c.typ, st.Written, c.wantN)
		}
	}
}

func TestEmptyAndFailedReportsValidate(t *testing.T) {
	for _, typ := range []string{TypeSAST, TypeDependencyScanning, TypeSecretDetection, TypeContainerScanning} {
		r, _, err := FromReport(nil, Options{Type: typ, Failed: true, End: when})
		if err != nil {
			t.Fatal(err)
		}
		data, _ := r.Marshal()
		validate(t, typ, data)
		if r.Scan.Status != "failure" || !strings.Contains(string(data), `"vulnerabilities": []`) {
			t.Errorf("%s: %s", typ, data)
		}
	}
	if _, _, err := FromReport(nil, Options{Type: "dast"}); err == nil {
		t.Error("an unknown type was accepted")
	}
}

// A secret is located by commit: without one it cannot be reported.
func TestSecretNeedsCommit(t *testing.T) {
	r, st, _ := FromReport(sample(), Options{Type: TypeSecretDetection})
	if len(r.Vulnerabilities) != 0 || st.Skipped != 4 {
		t.Fatalf("%d written, %+v", len(r.Vulnerabilities), st)
	}
}

func TestFields(t *testing.T) {
	r, _, _ := FromReport(sample(), Options{Type: TypeDependencyScanning})
	v := r.Vulnerabilities[0]
	if v.Severity != "High" || v.Identifiers[0].Type != "cve" || v.Identifiers[0].URL == "" ||
		v.Solution != "Upgrade flask to 0.12.3" || len(v.Links) != 1 {
		t.Fatalf("%+v", v)
	}
	again, _, _ := FromReport(sample(), Options{Type: TypeDependencyScanning})
	if again.Vulnerabilities[0].ID != v.ID {
		t.Fatal("the id is not stable")
	}
	s, _, _ := FromReport(sample(), Options{Type: TypeSAST})
	var sec Vulnerability
	for _, x := range s.Vulnerabilities {
		if strings.Contains(x.Name, "API key") {
			sec = x
		}
	}
	if sec.Severity != "Unknown" {
		t.Errorf("unknown severity mapped to %q", sec.Severity)
	}
	b, _ := json.Marshal(s)
	if strings.Contains(string(b), "api_key = ") {
		t.Error("a code snippet was copied into the report")
	}
	if s.Vulnerabilities[1].Name != "Subprocess injection" {
		t.Errorf("name %q: the rule name is preferred over the finding title", s.Vulnerabilities[1].Name)
	}
}
