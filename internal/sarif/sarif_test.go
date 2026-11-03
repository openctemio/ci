package sarif

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/openctemio/ctis/v2"
)

func TestFromReports(t *testing.T) {
	cvss := 9.1
	r := &ctis.Report{Tool: &ctis.Tool{Name: "semgrep", Version: "1.100.0"}, Findings: []ctis.Finding{
		{RuleID: "r1", Title: "Command injection", Severity: "critical", Fingerprint: "fp1",
			Location:      &ctis.FindingLocation{Path: "a.py", StartLine: 3, EndLine: 2, StartColumn: 5, EndColumn: 9, Snippet: "secret-ish code"},
			Vulnerability: &ctis.VulnerabilityDetails{CWEIDs: []string{"CWE-78"}},
			Scores:        []ctis.Score{{System: ctis.ScoreSystemCVSS, Version: "3.1", Value: &cvss}}},
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

// The rule text is written once in the report's rules[] and the finding
// names it by rule_ref: SARIF reads the description and help from there, not
// from the occurrence's own title.
func TestRuleTextComesFromRules(t *testing.T) {
	r := &ctis.Report{
		Tool: &ctis.Tool{Name: "opengrep"},
		Rules: []ctis.Rule{{ID: "rule-1", RuleID: "py.cmdi", Name: "Subprocess injection",
			ShortDescription: "Untrusted input reaches a shell", FullDescription: "Long form", Help: "Pass an argument list"}},
		Findings: []ctis.Finding{{RuleID: "py.cmdi", RuleRef: "rule-1", Title: "py.cmdi at a.py:3", Severity: "high",
			Location: &ctis.FindingLocation{Path: "a.py", StartLine: 3}}},
	}
	log, _ := FromReports([]*ctis.Report{r}, Options{})
	rule := log.Runs[0].Tool.Driver.Rules[0]
	if rule.ID != "py.cmdi" || rule.Name != "Subprocess injection" || rule.ShortDescription.Text != "Untrusted input reaches a shell" ||
		rule.FullDescription == nil || rule.FullDescription.Text != "Long form" || rule.Help == nil || rule.Help.Text != "Pass an argument list" {
		t.Fatalf("%+v", rule)
	}
}
