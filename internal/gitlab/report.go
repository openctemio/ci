// Package gitlab writes a CTIS report as a GitLab security report
// (gl-*-report.json, schema 15.2.5), so a merge request's security widget
// and the pipeline's security tab show the findings.
//
// One report type per capability: sast (also infrastructure as code),
// dependency_scanning, secret_detection and container_scanning. Secret
// findings carry only the masked value; no code snippet is copied.
package gitlab

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/openctemio/ctis"
)

// SchemaVersion is the security report schema version written.
const SchemaVersion = "15.2.5"

// Report types (artifacts:reports keys and scan.type values).
const (
	TypeSAST               = "sast"
	TypeDependencyScanning = "dependency_scanning"
	TypeSecretDetection    = "secret_detection"
	TypeContainerScanning  = "container_scanning"
)

// MaxVulnerabilities bounds the vulnerabilities written.
const MaxVulnerabilities = 10000

// schemaFile names each type's schema file.
var schemaFile = map[string]string{
	TypeSAST:               "sast-report-format.json",
	TypeDependencyScanning: "dependency-scanning-report-format.json",
	TypeSecretDetection:    "secret-detection-report-format.json",
	TypeContainerScanning:  "container-scanning-report-format.json",
}

// SchemaURL is the published schema of a report type.
func SchemaURL(reportType string) string {
	return "https://gitlab.com/gitlab-org/security-products/security-report-schemas/-/raw/v" +
		SchemaVersion + "/dist/" + schemaFile[reportType]
}

// Report is a GitLab security report.
type Report struct {
	Version         string          `json:"version"`
	Schema          string          `json:"schema"`
	Scan            Scan            `json:"scan"`
	Vulnerabilities []Vulnerability `json:"vulnerabilities"`
}

// Scan describes the scan.
type Scan struct {
	Analyzer  Component `json:"analyzer"`
	Scanner   Component `json:"scanner"`
	Type      string    `json:"type"`
	StartTime string    `json:"start_time"`
	EndTime   string    `json:"end_time"`
	Status    string    `json:"status"`
	Messages  []Msg     `json:"messages,omitempty"`
}

// Component is an analyzer or a scanner.
type Component struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	URL     string `json:"url,omitempty"`
	Version string `json:"version"`
	Vendor  Vendor `json:"vendor"`
}

// Vendor names a component's maintainer.
type Vendor struct {
	Name string `json:"name"`
}

// Msg is a scan message.
type Msg struct {
	Level string `json:"level"`
	Value string `json:"value"`
}

// Vulnerability is one finding.
type Vulnerability struct {
	ID          string       `json:"id"`
	Name        string       `json:"name,omitempty"`
	Description string       `json:"description,omitempty"`
	Severity    string       `json:"severity,omitempty"`
	Solution    string       `json:"solution,omitempty"`
	Identifiers []Identifier `json:"identifiers"`
	Links       []Link       `json:"links,omitempty"`
	Location    any          `json:"location"`
}

// Identifier references the vulnerability in a database or rule set.
type Identifier struct {
	Type  string `json:"type"`
	Name  string `json:"name"`
	Value string `json:"value"`
	URL   string `json:"url,omitempty"`
}

// Link is a reference URL.
type Link struct {
	URL string `json:"url"`
}

// FileLocation is the location of a SAST finding.
type FileLocation struct {
	File      string `json:"file,omitempty"`
	StartLine int    `json:"start_line,omitempty"`
	EndLine   int    `json:"end_line,omitempty"`
}

// SecretLocation is the location of a secret.
type SecretLocation struct {
	File      string `json:"file,omitempty"`
	StartLine int    `json:"start_line,omitempty"`
	EndLine   int    `json:"end_line,omitempty"`
	Commit    Commit `json:"commit"`
}

// Commit is the commit a secret was found in.
type Commit struct {
	SHA string `json:"sha"`
}

// DependencyLocation is the location of a vulnerable dependency.
type DependencyLocation struct {
	File       string     `json:"file"`
	Dependency Dependency `json:"dependency"`
}

// ContainerLocation is the location of a vulnerable image package.
type ContainerLocation struct {
	Dependency      Dependency `json:"dependency"`
	OperatingSystem string     `json:"operating_system"`
	Image           string     `json:"image"`
}

// Dependency is a package and its version.
type Dependency struct {
	Package Package `json:"package"`
	Version string  `json:"version"`
}

// Package is a package name.
type Package struct {
	Name string `json:"name"`
}

// Options describe the scan.
type Options struct {
	// Type is the report type.
	Type string
	// AnalyzerVersion is the openctem-ci version.
	AnalyzerVersion string
	// Commit is the scanned commit (secret detection requires it).
	Commit string
	// Image is the scanned image (container scanning).
	Image string
	// OperatingSystem of the scanned image, when known.
	OperatingSystem string
	Start, End      time.Time
	// Failed marks a scan that did not complete.
	Failed bool
}

// Stats count what was left out.
type Stats struct {
	Written   int
	Skipped   int
	Truncated int
}

// FromReport converts a CTIS report to a GitLab security report.
func FromReport(r *ctis.Report, o Options) (*Report, Stats, error) {
	if _, ok := schemaFile[o.Type]; !ok {
		return nil, Stats{}, fmt.Errorf("unknown GitLab report type %q", o.Type)
	}
	tool, toolVersion := "unknown", ""
	if r != nil && r.Tool != nil {
		if r.Tool.Name != "" {
			tool = r.Tool.Name
		}
		toolVersion = r.Tool.Version
	}
	if o.End.IsZero() {
		o.End = time.Now()
	}
	if o.Start.IsZero() || o.Start.After(o.End) {
		o.Start = o.End
	}
	status := "success"
	if o.Failed {
		status = "failure"
	}
	out := &Report{
		Version: SchemaVersion,
		Schema:  SchemaURL(o.Type),
		Scan: Scan{
			Analyzer: Component{ID: "openctem-ci", Name: "OpenCTEM CI", URL: "https://github.com/openctemio/ci",
				Version: nonEmpty(o.AnalyzerVersion, "dev"), Vendor: Vendor{Name: "OpenCTEM"}},
			Scanner:   Component{ID: tool, Name: tool, Version: nonEmpty(toolVersion, "unknown"), Vendor: Vendor{Name: toolVendor(tool)}},
			Type:      o.Type,
			StartTime: o.Start.UTC().Format("2006-01-02T15:04:05"),
			EndTime:   o.End.UTC().Format("2006-01-02T15:04:05"),
			Status:    status,
		},
		Vulnerabilities: []Vulnerability{},
	}
	var st Stats
	if r == nil {
		return out, st, nil
	}
	for i := range r.Findings {
		f := &r.Findings[i]
		loc, ok := location(f, o)
		if !ok {
			st.Skipped++
			continue
		}
		if len(out.Vulnerabilities) >= MaxVulnerabilities {
			st.Truncated++
			continue
		}
		v := Vulnerability{
			ID: stableID(o.Type, f),
			// The name is the vulnerability, not this occurrence: the rule
			// name when the tool gives one, else the title.
			Name:        truncate(nonEmpty(strings.TrimSpace(f.RuleName), nonEmpty(strings.TrimSpace(f.Title), ruleOrCVE(f))), 255),
			Description: truncate(strings.TrimSpace(f.Description), 64<<10),
			Severity:    Severity(f.Severity),
			Identifiers: identifiers(tool, f),
			Links:       links(f),
			Location:    loc,
		}
		if f.Remediation != nil {
			v.Solution = truncate(strings.TrimSpace(f.Remediation.Recommendation), 16<<10)
		}
		if v.Solution == "" && f.Vulnerability != nil && f.Vulnerability.FixedVersion != "" {
			v.Solution = "Upgrade " + f.Vulnerability.Package + " to " + f.Vulnerability.FixedVersion
		}
		out.Vulnerabilities = append(out.Vulnerabilities, v)
		st.Written++
	}
	if st.Skipped > 0 {
		out.Scan.Messages = append(out.Scan.Messages, Msg{Level: "info",
			Value: fmt.Sprintf("%d finding(s) without the location this report type needs are only in OpenCTEM", st.Skipped)})
	}
	if st.Truncated > 0 {
		out.Scan.Messages = append(out.Scan.Messages, Msg{Level: "warn",
			Value: fmt.Sprintf("%d finding(s) over the limit of %d are only in OpenCTEM", st.Truncated, MaxVulnerabilities)})
	}
	return out, st, nil
}

// Marshal writes the report as indented JSON.
func (r *Report) Marshal() ([]byte, error) { return json.MarshalIndent(r, "", "  ") }

func location(f *ctis.Finding, o Options) (any, bool) {
	path, start, end := "", 0, 0
	if l := f.Location; l != nil {
		path, start, end = strings.TrimSpace(l.Path), l.StartLine, l.EndLine
		if end < start {
			end = 0
		}
	}
	switch o.Type {
	case TypeSAST:
		if path == "" {
			return nil, false
		}
		return FileLocation{File: path, StartLine: start, EndLine: end}, true
	case TypeSecretDetection:
		sha := strings.TrimSpace(o.Commit)
		if sha == "" && f.Location != nil {
			sha = f.Location.CommitSHA
		}
		if path == "" || sha == "" {
			return nil, false
		}
		return SecretLocation{File: path, StartLine: start, EndLine: end, Commit: Commit{SHA: sha}}, true
	case TypeDependencyScanning:
		pkg, ver := pkgVersion(f)
		if path == "" || pkg == "" {
			return nil, false
		}
		return DependencyLocation{File: path, Dependency: Dependency{Package: Package{Name: pkg}, Version: ver}}, true
	case TypeContainerScanning:
		pkg, ver := pkgVersion(f)
		if pkg == "" || strings.TrimSpace(o.Image) == "" {
			return nil, false
		}
		return ContainerLocation{Dependency: Dependency{Package: Package{Name: pkg}, Version: ver},
			OperatingSystem: nonEmpty(o.OperatingSystem, "unknown"), Image: o.Image}, true
	}
	return nil, false
}

func pkgVersion(f *ctis.Finding) (string, string) {
	if v := f.Vulnerability; v != nil {
		return strings.TrimSpace(v.Package), strings.TrimSpace(v.AffectedVersion)
	}
	return "", ""
}

func identifiers(tool string, f *ctis.Finding) []Identifier {
	var ids []Identifier
	add := func(i Identifier) {
		if i.Type != "" && i.Name != "" && i.Value != "" {
			ids = append(ids, i)
		}
	}
	if v := f.Vulnerability; v != nil {
		seen := map[string]bool{}
		for _, c := range append([]string{v.CVEID}, v.CVEIDs...) {
			c = strings.TrimSpace(c)
			if c == "" || seen[c] {
				continue
			}
			seen[c] = true
			id := Identifier{Type: "cve", Name: c, Value: c}
			if strings.HasPrefix(strings.ToUpper(c), "CVE-") {
				id.URL = "https://nvd.nist.gov/vuln/detail/" + strings.ToUpper(c)
			}
			add(id)
		}
	}
	if rid := strings.TrimSpace(f.RuleID); rid != "" {
		add(Identifier{Type: identType(tool), Name: truncate(nonEmpty(f.RuleName, rid), 255), Value: truncate(rid, 255)})
	}
	if v := f.Vulnerability; v != nil {
		seen := map[string]bool{}
		for _, c := range append([]string{v.CWEID}, v.CWEIDs...) {
			n := strings.TrimPrefix(strings.ToUpper(strings.TrimSpace(c)), "CWE-")
			if n == "" || seen[n] || !digits(n) {
				continue
			}
			seen[n] = true
			add(Identifier{Type: "cwe", Name: "CWE-" + n, Value: n, URL: "https://cwe.mitre.org/data/definitions/" + n + ".html"})
		}
	}
	if len(ids) == 0 {
		// The schema needs at least one identifier: the finding's own.
		v := nonEmpty(f.Fingerprint, stableID("", f))
		ids = append(ids, Identifier{Type: "openctem_finding", Name: truncate(nonEmpty(f.Title, v), 255), Value: v})
	}
	return ids
}

// identType is the identifier type of a tool's rule ids.
func identType(tool string) string {
	t := strings.Map(func(r rune) rune {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			return r
		}
		return '_'
	}, strings.ToLower(tool))
	return nonEmpty(t, "tool") + "_rule_id"
}

func links(f *ctis.Finding) []Link {
	var out []Link
	seen := map[string]bool{}
	for _, u := range f.References {
		u = strings.TrimSpace(u)
		if (strings.HasPrefix(u, "https://") || strings.HasPrefix(u, "http://")) && !seen[u] && len(out) < 20 {
			seen[u] = true
			out = append(out, Link{URL: u})
		}
	}
	return out
}

// stableID is a UUID-shaped id derived from the finding's fingerprint, so
// the same finding keeps its id across pipelines.
func stableID(kind string, f *ctis.Finding) string {
	key := f.Fingerprint
	if key == "" {
		p := ""
		if f.Location != nil {
			p = fmt.Sprintf("%s:%d", f.Location.Path, f.Location.StartLine)
		}
		key = strings.Join([]string{f.RuleID, f.Title, p, vulnKey(f)}, "|")
	}
	sum := sha256.Sum256([]byte(kind + "|" + key))
	h := hex.EncodeToString(sum[:16])
	return h[0:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:32]
}

func vulnKey(f *ctis.Finding) string {
	if v := f.Vulnerability; v != nil {
		return v.CVEID + "@" + v.Package + "@" + v.AffectedVersion
	}
	return ""
}

// Severity maps a CTIS severity to a GitLab severity.
func Severity(s ctis.Severity) string {
	switch strings.ToLower(string(s)) {
	case "critical":
		return "Critical"
	case "high":
		return "High"
	case "medium":
		return "Medium"
	case "low":
		return "Low"
	case "info":
		return "Info"
	}
	return "Unknown"
}

func ruleOrCVE(f *ctis.Finding) string {
	if f.RuleID != "" {
		return f.RuleID
	}
	if f.Vulnerability != nil && f.Vulnerability.CVEID != "" {
		return f.Vulnerability.CVEID
	}
	return "Finding"
}

// toolVendor names the scanner's maintainer: the tool's own project name.
func toolVendor(tool string) string {
	if tool == "" || tool == "unknown" {
		return "OpenCTEM"
	}
	return tool
}

func digits(s string) bool {
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return s != ""
}

func nonEmpty(s, fallback string) string {
	if strings.TrimSpace(s) == "" {
		return fallback
	}
	return s
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	for n > 0 && n < len(s) && (s[n]&0xC0) == 0x80 {
		n--
	}
	return s[:n]
}
