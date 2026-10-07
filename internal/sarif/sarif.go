// Package sarif writes a CTIS report as SARIF 2.1.0 for a code host's code
// scanning view (GitHub code scanning accepts it as is).
//
// Only what a code host shows is written: rule, severity, message, file
// and line. No code snippet is copied (a snippet can hold more of a
// secret than its masked form), and a result without a file is left out,
// because code scanning places every result on a file.
package sarif

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/openctemio/ctis"
)

// SchemaURI is the SARIF 2.1.0 schema.
const SchemaURI = "https://json.schemastore.org/sarif-2.1.0.json"

// MaxResults bounds the results written per run (code scanning accepts
// 25,000; fewer keeps the upload small).
const MaxResults = 5000

// Log is a SARIF log.
type Log struct {
	Schema  string `json:"$schema"`
	Version string `json:"version"`
	Runs    []Run  `json:"runs"`
}

// Run is one tool run.
type Run struct {
	Tool              Tool               `json:"tool"`
	AutomationDetails *AutomationDetails `json:"automationDetails,omitempty"`
	Results           []Result           `json:"results"`
}

// AutomationDetails names the analysis, so uploads of several capabilities
// for one commit do not replace each other.
type AutomationDetails struct {
	ID string `json:"id"`
}

// Tool is the tool of a run.
type Tool struct {
	Driver Driver `json:"driver"`
}

// Driver describes the tool and its rules.
type Driver struct {
	Name           string `json:"name"`
	Version        string `json:"version,omitempty"`
	InformationURI string `json:"informationUri,omitempty"`
	Rules          []Rule `json:"rules"`
}

// Rule is one rule.
type Rule struct {
	ID               string          `json:"id"`
	Name             string          `json:"name,omitempty"`
	ShortDescription Message         `json:"shortDescription"`
	FullDescription  *Message        `json:"fullDescription,omitempty"`
	Help             *Message        `json:"help,omitempty"`
	DefaultConfig    RuleConfig      `json:"defaultConfiguration"`
	Properties       *RuleProperties `json:"properties,omitempty"`
}

// RuleConfig is the default level of a rule.
type RuleConfig struct {
	Level string `json:"level"`
}

// RuleProperties carry the security severity code scanning sorts by.
type RuleProperties struct {
	SecuritySeverity string   `json:"security-severity,omitempty"`
	Tags             []string `json:"tags,omitempty"`
}

// Message is a text.
type Message struct {
	Text string `json:"text"`
}

// Result is one finding.
type Result struct {
	RuleID              string            `json:"ruleId"`
	RuleIndex           int               `json:"ruleIndex"`
	Level               string            `json:"level"`
	Message             Message           `json:"message"`
	Locations           []Location        `json:"locations"`
	PartialFingerprints map[string]string `json:"partialFingerprints,omitempty"`
}

// Location is a file location.
type Location struct {
	PhysicalLocation PhysicalLocation `json:"physicalLocation"`
}

// PhysicalLocation is a file and a region.
type PhysicalLocation struct {
	ArtifactLocation ArtifactLocation `json:"artifactLocation"`
	Region           *Region          `json:"region,omitempty"`
}

// ArtifactLocation is a file path relative to the repository root.
type ArtifactLocation struct {
	URI string `json:"uri"`
}

// Region is a line range.
type Region struct {
	StartLine   int `json:"startLine"`
	EndLine     int `json:"endLine,omitempty"`
	StartColumn int `json:"startColumn,omitempty"`
	EndColumn   int `json:"endColumn,omitempty"`
}

// FingerprintKey names the platform fingerprint in partialFingerprints.
const FingerprintKey = "openctem/v1"

// Options name the analysis.
type Options struct {
	// Category is the analysis category (the capability short name).
	Category string
}

// Stats count what was left out.
type Stats struct {
	Written    int
	NoLocation int
	Truncated  int
}

// FromReports converts reports to one SARIF log, one run per report.
func FromReports(reports []*ctis.Report, o Options) (*Log, Stats) {
	log := &Log{Schema: SchemaURI, Version: "2.1.0", Runs: []Run{}}
	var st Stats
	for _, r := range reports {
		if r == nil {
			continue
		}
		log.Runs = append(log.Runs, run(r, o, &st))
	}
	return log, st
}

// Marshal writes the log as indented JSON.
func (l *Log) Marshal() ([]byte, error) { return json.MarshalIndent(l, "", "  ") }

func run(r *ctis.Report, o Options, st *Stats) Run {
	name, version := "openctem-ci", ""
	if r.Tool != nil {
		if r.Tool.Name != "" {
			name = r.Tool.Name
		}
		version = r.Tool.Version
	}
	out := Run{Tool: Tool{Driver: Driver{Name: name, Version: version, InformationURI: "https://github.com/openctemio/ci", Rules: []Rule{}}},
		Results: []Result{}}
	if o.Category != "" {
		out.AutomationDetails = &AutomationDetails{ID: "openctem/" + o.Category + "/"}
	}
	index := map[string]int{}
	for i := range r.Findings {
		f := &r.Findings[i]
		loc := location(f)
		if loc == nil {
			st.NoLocation++
			continue
		}
		if len(out.Results) >= MaxResults {
			st.Truncated++
			continue
		}
		id := ruleID(f)
		ri, ok := index[id]
		if !ok {
			ri = len(out.Tool.Driver.Rules)
			index[id] = ri
			out.Tool.Driver.Rules = append(out.Tool.Driver.Rules, rule(id, f))
		}
		res := Result{RuleID: id, RuleIndex: ri, Level: Level(f.Severity), Message: Message{Text: message(f)},
			Locations: []Location{*loc}}
		if f.Fingerprint != "" {
			res.PartialFingerprints = map[string]string{FingerprintKey: f.Fingerprint}
		}
		out.Results = append(out.Results, res)
		st.Written++
	}
	return out
}

func ruleID(f *ctis.Finding) string {
	for _, s := range []string{f.RuleID, vulnID(f), f.Title} {
		if s = strings.TrimSpace(s); s != "" {
			return truncate(s, 255)
		}
	}
	return "openctem-finding"
}

func vulnID(f *ctis.Finding) string {
	if f.Vulnerability != nil {
		return f.Vulnerability.CVEID
	}
	return ""
}

func rule(id string, f *ctis.Finding) Rule {
	short := strings.TrimSpace(f.Title)
	if short == "" {
		short = id
	}
	r := Rule{ID: id, Name: truncate(f.RuleName, 255), ShortDescription: Message{Text: truncate(short, 1024)},
		DefaultConfig: RuleConfig{Level: Level(f.Severity)},
		Properties:    &RuleProperties{SecuritySeverity: securitySeverity(f), Tags: tags(f)}}
	if d := strings.TrimSpace(f.Description); d != "" {
		r.FullDescription = &Message{Text: truncate(d, 4096)}
	}
	if f.Remediation != nil && strings.TrimSpace(f.Remediation.Recommendation) != "" {
		r.Help = &Message{Text: truncate(f.Remediation.Recommendation, 4096)}
	}
	return r
}

func message(f *ctis.Finding) string {
	for _, s := range []string{f.Message, f.Title, f.Description} {
		if s = strings.TrimSpace(s); s != "" {
			return truncate(s, 2048)
		}
	}
	return "Finding"
}

func location(f *ctis.Finding) *Location {
	if f.Location == nil || strings.TrimSpace(f.Location.Path) == "" {
		return nil
	}
	l := &Location{PhysicalLocation: PhysicalLocation{ArtifactLocation: ArtifactLocation{URI: f.Location.Path}}}
	if f.Location.StartLine > 0 {
		rg := &Region{StartLine: f.Location.StartLine, StartColumn: f.Location.StartColumn}
		if f.Location.EndLine >= f.Location.StartLine {
			rg.EndLine = f.Location.EndLine
		}
		if f.Location.EndColumn > 0 && (rg.EndLine == 0 || rg.EndLine == rg.StartLine) && f.Location.EndColumn > f.Location.StartColumn {
			rg.EndColumn = f.Location.EndColumn
		}
		if rg.StartColumn <= 0 {
			rg.StartColumn, rg.EndColumn = 0, 0
		}
		l.PhysicalLocation.Region = rg
	}
	return l
}

// Level maps a CTIS severity to a SARIF level.
func Level(s ctis.Severity) string {
	switch strings.ToLower(string(s)) {
	case "critical", "high":
		return "error"
	case "medium":
		return "warning"
	default:
		return "note"
	}
}

// securitySeverity is the CVSS-like score code scanning uses for its
// severity: the finding's CVSS score when it has one, else the middle of
// the severity's band.
func securitySeverity(f *ctis.Finding) string {
	if v := f.Vulnerability; v != nil && v.CVSSScore > 0 && v.CVSSScore <= 10 {
		return fmt.Sprintf("%.1f", v.CVSSScore)
	}
	switch strings.ToLower(string(f.Severity)) {
	case "critical":
		return "9.5"
	case "high":
		return "8.0"
	case "medium":
		return "5.5"
	case "low":
		return "2.0"
	}
	return ""
}

func tags(f *ctis.Finding) []string {
	set := map[string]bool{"security": true}
	if f.Type != "" {
		set[string(f.Type)] = true
	}
	if v := f.Vulnerability; v != nil {
		for _, c := range append([]string{v.CWEID}, v.CWEIDs...) {
			if c = strings.TrimSpace(c); c != "" {
				set["external/cwe/"+strings.ToLower(c)] = true
			}
		}
	}
	out := make([]string, 0, len(set))
	for t := range set {
		out = append(out, t)
	}
	sort.Strings(out)
	return out
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	// Cut on a rune boundary.
	for n > 0 && n < len(s) && (s[n]&0xC0) == 0x80 {
		n--
	}
	return s[:n]
}
