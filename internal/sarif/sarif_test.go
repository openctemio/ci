package sarif

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/openctemio/ctis"
)

func TestFromReports(t *testing.T) {
	r := &ctis.Report{Tool: &ctis.Tool{Name: "semgrep", Version: "1.0"}, Findings: []ctis.Finding{
		{RuleID: "r1", Title: "Command injection", Severity: "critical", Fingerprint: "fp1",
			Location:      &ctis.FindingLocation{Path: "a.py", StartLine: 3, EndLine: 2, StartColumn: 5, EndColumn: 9, Snippet: "secret-ish code"},
			Vulnerability: &ctis.VulnerabilityDetails{CWEIDs: []string{"CWE-78"}, CVSSScore: 9.1}},
		{RuleID: "r1", Title: "Command injection", Severity: "critical", Location: &ctis.FindingLocation{Path: "b.py"}},
		{RuleID: "r2", Title: "No file", Severity: "low"},
		{Title: "Only a title", Severity: "medium", Location: &ctis.FindingLocation{Path: "c.py", StartLine: 1}},
	}}
	log, st := FromReports([]*ctis.Report{r, nil}, Options{Category: "sast"})
	if st.Written != 3 || st.NoLocation != 1 || len(log.Runs) != 1 {
		t.Fatalf("%+v %d runs", st, len(log.Runs))
	}
	run := log.Runs[0]
	if run.AutomationDetails.ID != "openctem/sast/" || run.Tool.Driver.Name != "semgrep" || len(run.Tool.Driver.Rules) != 2 {
		t.Fatalf("%+v", run)
	}
	res := run.Results[0]
	if res.Level != "error" || res.PartialFingerprints[FingerprintKey] != "fp1" || res.Locations[0].PhysicalLocation.Region.EndLine != 0 {
		t.Fatalf("%+v", res)
	}
	if run.Results[1].RuleIndex != 0 || run.Results[2].RuleID != "Only a title" || run.Results[2].RuleIndex != 1 {
		t.Fatalf("rule index: %+v", run.Results)
	}
	rule := run.Tool.Driver.Rules[0]
	if rule.Properties.SecuritySeverity != "9.1" || !strings.Contains(strings.Join(rule.Properties.Tags, ","), "external/cwe/cwe-78") {
		t.Fatalf("%+v", rule.Properties)
	}
	data, err := log.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "secret-ish code") {
		t.Fatal("a snippet was copied into SARIF")
	}
	var back map[string]any
	if err := json.Unmarshal(data, &back); err != nil || back["version"] != "2.1.0" {
		t.Fatalf("%v %v", err, back["version"])
	}
}

func TestEmptyLogHasRuns(t *testing.T) {
	log, _ := FromReports(nil, Options{})
	data, _ := log.Marshal()
	if !strings.Contains(string(data), `"runs": []`) {
		t.Fatalf("%s", data)
	}
	for sev, want := range map[ctis.Severity]string{"high": "error", "medium": "warning", "info": "note", "x": "note"} {
		if Level(sev) != want {
			t.Errorf("Level(%s) = %s", sev, Level(sev))
		}
	}
}
