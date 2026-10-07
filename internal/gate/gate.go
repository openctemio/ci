// Package gate is the local security gate: the offline fallback when the
// platform's gate cannot be asked (no OIDC identity, a fork, the platform
// unreachable). The platform's verdict always wins when there is one.
//
// It fails closed: a finding with an unknown severity blocks, and a finding
// that is actively exploited (CISA KEV) or has a known exploit blocks
// whatever its severity.
package gate

import (
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/openctemio/ctis"
)

// Exit codes of openctem-ci.
const (
	ExitPass  = 0 // the gate passed
	ExitFail  = 1 // the gate failed
	ExitError = 2 // configuration or runtime error (the scan is not trusted)
)

// severityOrder ranks the CTIS severities.
var severityOrder = map[string]int{"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}

// unknown is the bucket of findings whose severity is not a CTIS severity.
const unknown = "unknown"

// ValidThreshold reports whether s is a severity threshold.
func ValidThreshold(s string) bool {
	_, ok := severityOrder[strings.ToLower(strings.TrimSpace(s))]
	return ok
}

// Tally counts findings per severity, and separately the ones that are
// actively exploited or have a known exploit. It is what a scan job hands
// to a later gate job.
type Tally struct {
	Severity map[string]int `json:"severity,omitempty"`
	Risk     map[string]int `json:"risk,omitempty"`
}

// TallyReport counts the findings of a report.
func TallyReport(r *ctis.Report) Tally {
	t := Tally{Severity: map[string]int{}, Risk: map[string]int{}}
	if r == nil {
		return t
	}
	for _, f := range r.Findings {
		sev := strings.ToLower(strings.TrimSpace(string(f.Severity)))
		if _, ok := severityOrder[sev]; !ok {
			sev = unknown
		}
		t.Severity[sev]++
		if v := f.Vulnerability; v != nil && (v.InCISAKEV || v.ExploitAvailable) {
			t.Risk[sev]++
		}
	}
	return t
}

// Add adds another tally.
func (t *Tally) Add(o Tally) {
	if t.Severity == nil {
		t.Severity = map[string]int{}
	}
	if t.Risk == nil {
		t.Risk = map[string]int{}
	}
	for k, v := range o.Severity {
		t.Severity[k] += v
	}
	for k, v := range o.Risk {
		t.Risk[k] += v
	}
}

// Total is the number of findings.
func (t Tally) Total() int {
	n := 0
	for _, v := range t.Severity {
		n += v
	}
	return n
}

// Result is a local verdict.
type Result struct {
	Passed    bool
	Threshold string
	// Blocking counts findings at or above the threshold (and of unknown
	// severity) per severity.
	Blocking map[string]int
	// RiskBlocking counts findings below the threshold that block because
	// they are actively exploited or have a known exploit.
	RiskBlocking int
}

// Decide judges a tally against a severity threshold.
func Decide(t Tally, threshold string) (Result, error) {
	threshold = strings.ToLower(strings.TrimSpace(threshold))
	level, ok := severityOrder[threshold]
	if !ok {
		return Result{}, fmt.Errorf("invalid severity threshold %q; use critical, high, medium, low or info", threshold)
	}
	res := Result{Threshold: threshold, Blocking: map[string]int{}}
	for sev, n := range t.Severity {
		if n == 0 {
			continue
		}
		if l, known := severityOrder[sev]; !known || l >= level {
			res.Blocking[sev] += n
			continue
		}
		res.RiskBlocking += t.Risk[sev]
	}
	total := 0
	for _, n := range res.Blocking {
		total += n
	}
	res.Passed = total == 0 && res.RiskBlocking == 0
	return res, nil
}

// Print writes a verdict and returns the exit code.
func Print(w io.Writer, r Result) int {
	if r.Passed {
		_, _ = fmt.Fprintf(w, "\nLocal gate: PASS (no finding at or above %s, none actively exploited)\n", r.Threshold)
		return ExitPass
	}
	_, _ = fmt.Fprintln(w, "\nLocal gate: FAIL")
	keys := make([]string, 0, len(r.Blocking))
	for k := range r.Blocking {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool { return rank(keys[i]) > rank(keys[j]) })
	for _, k := range keys {
		_, _ = fmt.Fprintf(w, "  %d %s finding(s) (threshold %s)\n", r.Blocking[k], k, r.Threshold)
	}
	if r.RiskBlocking > 0 {
		_, _ = fmt.Fprintf(w, "  %d finding(s) below the threshold block because they are actively exploited or have a known exploit\n", r.RiskBlocking)
	}
	return ExitFail
}

func rank(sev string) int {
	if l, ok := severityOrder[sev]; ok {
		return l
	}
	return 5 // unknown sorts first: it blocks as the worst case
}
