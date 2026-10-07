// Package capability is the one place that maps the capabilities a CI user
// chooses to the tool and image that implement them. Users pick
// capabilities (sast, sca, secrets, iac, container), never images or tools.
// The ids are the platform's capability taxonomy ids (ctis/capability):
// a report names the capability it implements, so the platform files it
// the same way whichever tool produced it.
package capability

import (
	"fmt"
	"sort"
	"strings"
)

// Capability is one scan a CI job can run.
type Capability struct {
	// Name is the short name users write: sast, sca, secrets, iac, container.
	Name string
	// ID is the capability taxonomy id with its major version.
	ID string
	// Tool is the scanner that implements it by default.
	Tool string
	// Image is the default image (repository under ghcr.io/openctemio) that
	// carries the tool and openctem-ci.
	Image string
	// GitLabReport is the GitLab security report type (the key under
	// artifacts:reports) and GitLabFile the file name of that report.
	GitLabReport string
	GitLabFile   string
	// Target says what the capability scans: the repository checkout or a
	// container image reference.
	Target Target
}

// Target is what a capability scans.
type Target string

const (
	// TargetRepository scans the checked-out repository.
	TargetRepository Target = "repository"
	// TargetImage scans a container image reference.
	TargetImage Target = "image"
)

// Registry is the image registry namespace of every default image.
const Registry = "ghcr.io/openctemio"

// BundleImage carries every tool.
const BundleImage = "ci"

var catalog = []Capability{
	{Name: "sast", ID: "sast.code@1", Tool: "semgrep", Image: "ci-semgrep",
		GitLabReport: "sast", GitLabFile: "gl-sast-report.json", Target: TargetRepository},
	{Name: "sca", ID: "sca.deps@1", Tool: "trivy", Image: "ci-trivy",
		GitLabReport: "dependency_scanning", GitLabFile: "gl-dependency-scanning-report.json", Target: TargetRepository},
	{Name: "secrets", ID: "secrets.code@1", Tool: "betterleaks", Image: "ci-betterleaks",
		GitLabReport: "secret_detection", GitLabFile: "gl-secret-detection-report.json", Target: TargetRepository},
	// GitLab files infrastructure-as-code results as SAST reports.
	{Name: "iac", ID: "iac.misconfig@1", Tool: "trivy", Image: "ci-trivy",
		GitLabReport: "sast", GitLabFile: "gl-iac-report.json", Target: TargetRepository},
	{Name: "container", ID: "container.image@1", Tool: "trivy", Image: "ci-trivy",
		GitLabReport: "container_scanning", GitLabFile: "gl-container-scanning-report.json", Target: TargetImage},
}

// All returns every capability in catalog order.
func All() []Capability {
	out := make([]Capability, len(catalog))
	copy(out, catalog)
	return out
}

// Lookup finds a capability by its short name or its taxonomy id (with or
// without the major version), case-insensitively.
func Lookup(s string) (Capability, bool) {
	s = strings.ToLower(strings.TrimSpace(s))
	for _, c := range catalog {
		if s == c.Name || s == c.ID || s == strings.SplitN(c.ID, "@", 2)[0] {
			return c, true
		}
	}
	return Capability{}, false
}

// Parse reads a comma- or space-separated list of capabilities. "all"
// selects every capability that scans the repository (container needs an
// image reference and is never implied). Duplicates are dropped; the order
// is the catalog order. An unknown name is an error that lists the valid
// ones.
func Parse(list string) ([]Capability, error) {
	fields := strings.FieldsFunc(list, func(r rune) bool { return r == ',' || r == ' ' || r == '\n' || r == '\t' })
	if len(fields) == 0 {
		return nil, fmt.Errorf("no capability given; choose from %s", Names())
	}
	want := map[string]bool{}
	for _, f := range fields {
		if strings.EqualFold(f, "all") {
			for _, c := range catalog {
				if c.Target == TargetRepository {
					want[c.Name] = true
				}
			}
			continue
		}
		c, ok := Lookup(f)
		if !ok {
			return nil, fmt.Errorf("unknown capability %q; choose from %s", f, Names())
		}
		want[c.Name] = true
	}
	var out []Capability
	for _, c := range catalog {
		if want[c.Name] {
			out = append(out, c)
		}
	}
	return out, nil
}

// Names lists the short names, comma-separated, in catalog order.
func Names() string {
	n := make([]string, 0, len(catalog)+1)
	for _, c := range catalog {
		n = append(n, c.Name)
	}
	return strings.Join(append(n, "all"), ", ")
}

// Tools lists the distinct tools, sorted.
func Tools() []string {
	seen := map[string]bool{}
	var out []string
	for _, c := range catalog {
		if !seen[c.Tool] {
			seen[c.Tool] = true
			out = append(out, c.Tool)
		}
	}
	sort.Strings(out)
	return out
}

// ImageRef is the default image reference of a capability, at a tag.
func (c Capability) ImageRef(tag string) string {
	return Registry + "/" + c.Image + ":" + tag
}
