package gate

import (
	"bytes"
	"strings"
	"testing"

	"github.com/openctemio/ctis"
)

func report(fs ...ctis.Finding) *ctis.Report { return &ctis.Report{Findings: fs} }

func TestDecide(t *testing.T) {
	r := report(
		ctis.Finding{Severity: "high"},
		ctis.Finding{Severity: "low"},
		ctis.Finding{Severity: "medium"},
	)
	tally := TallyReport(r)
	cases := map[string]bool{"critical": true, "high": false, "medium": false, "low": false, "info": false}
	for th, pass := range cases {
		res, err := Decide(tally, th)
		if err != nil || res.Passed != pass {
			t.Errorf("threshold %s: passed=%v err=%v, want %v", th, res.Passed, err, pass)
		}
	}
	if _, err := Decide(tally, "severe"); err == nil {
		t.Error("an invalid threshold was accepted")
	}
}

// A severity the gate does not know blocks (fail closed).
func TestUnknownSeverityBlocks(t *testing.T) {
	res, _ := Decide(TallyReport(report(ctis.Finding{Severity: "bogus"}, ctis.Finding{Severity: ""})), "critical")
	if res.Passed || res.Blocking["unknown"] != 2 {
		t.Fatalf("%+v", res)
	}
}

// An actively exploited finding blocks below the threshold.
func TestExploitedBlocksBelowThreshold(t *testing.T) {
	kev := ctis.Finding{Severity: "low", Vulnerability: &ctis.VulnerabilityDetails{InCISAKEV: true}}
	exp := ctis.Finding{Severity: "medium", Vulnerability: &ctis.VulnerabilityDetails{ExploitAvailable: true}}
	res, _ := Decide(TallyReport(report(kev, exp)), "critical")
	if res.Passed || res.RiskBlocking != 2 {
		t.Fatalf("%+v", res)
	}
	var b bytes.Buffer
	if code := Print(&b, res); code != ExitFail || !strings.Contains(b.String(), "actively exploited") {
		t.Fatalf("%d %s", code, b.String())
	}
}

func TestTallyAdd(t *testing.T) {
	var t1 Tally
	t1.Add(TallyReport(report(ctis.Finding{Severity: "high"})))
	t1.Add(TallyReport(report(ctis.Finding{Severity: "high"}, ctis.Finding{Severity: "critical",
		Vulnerability: &ctis.VulnerabilityDetails{InCISAKEV: true}})))
	if t1.Severity["high"] != 2 || t1.Severity["critical"] != 1 || t1.Risk["critical"] != 1 || t1.Total() != 3 {
		t.Fatalf("%+v", t1)
	}
	var b bytes.Buffer
	res, _ := Decide(Tally{}, "low")
	if Print(&b, res) != ExitPass {
		t.Fatal("an empty tally fails")
	}
}
