package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strconv"
	"testing"

	"github.com/openctemio/ctis"
	"github.com/openctemio/ctis/importer"

	"github.com/openctemio/ci/internal/capability"
	"github.com/openctemio/ci/internal/ciinfo"
	"github.com/openctemio/ci/internal/scanner"
)

// convertTrivy converts a real trivy --list-all-pkgs report the way an sca
// job does.
func convertTrivy(t *testing.T, fixture string) (*ctis.Report, string) {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "..", "testdata", "trivy", fixture))
	if err != nil {
		t.Fatal(err)
	}
	c, _ := capability.Lookup("sca")
	var out bytes.Buffer
	s := &scanJob{c: c, stdout: &out, stderr: &out, info: ciinfo.Info{Repository: "github.com/acme/shop", Branch: "main", Commit: "3f1c2a9e"}}
	r, err := s.convert(context.Background(), &scanner.Result{Tool: "trivy", Output: data, Format: importer.FormatTrivy}, nil, t.TempDir(), ".")
	if err != nil {
		t.Fatal(err)
	}
	return r, out.String()
}

func findingOf(t *testing.T, r *ctis.Report, pkg string) *ctis.Finding {
	t.Helper()
	for i := range r.Findings {
		if v := r.Findings[i].Vulnerability; v != nil && v.Package == pkg {
			return &r.Findings[i]
		}
	}
	t.Fatalf("no finding for %s", pkg)
	return nil
}

func depIDs(r *ctis.Report) []string {
	out := make([]string, 0, len(r.Dependencies))
	for _, d := range r.Dependencies {
		out = append(out, d.ID)
	}
	slices.Sort(out)
	return out
}

func TestSCA_Node_DirectAndTransitive(t *testing.T) {
	r, log := convertTrivy(t, "npm-lockfile.json")
	express := findingOf(t, r, "express")
	if v := express.Vulnerability; !v.IsDirect || !reflect.DeepEqual(v.DependencyPath, []string{"express@4.17.1"}) || v.PURL != "pkg:npm/express@4.17.1" {
		t.Fatalf("express: %+v", v)
	}
	if l := express.Location; l == nil || l.Path != "package-lock.json" || l.StartLine != 154 {
		t.Fatalf("express location: %+v", l)
	}
	qs := findingOf(t, r, "qs")
	if v := qs.Vulnerability; v.IsDirect || !reflect.DeepEqual(v.DependencyPath, []string{"express@4.17.1", "qs@6.7.0"}) || v.PURL != "pkg:npm/qs@6.7.0" {
		t.Fatalf("qs: %+v", v)
	}
	if l := qs.Location; l == nil || l.Path != "package-lock.json" || l.StartLine != 396 || l.EndLine != 404 {
		t.Fatalf("qs location: %+v", l)
	}
	// 51 packages in the lockfile; the report keeps the 8 the findings name.
	want := []string{"body-parser@1.19.0", "cookie@0.4.0", "express@4.17.1", "lodash@4.17.20", "path-to-regexp@0.1.7", "qs@6.7.0", "send@0.17.1", "serve-static@1.14.1"}
	if got := depIDs(r); !reflect.DeepEqual(got, want) {
		t.Fatalf("dependencies = %v", got)
	}
	for _, d := range r.Dependencies {
		if d.ID == "express@4.17.1" && !reflect.DeepEqual(d.DependsOn, []string{"body-parser@1.19.0", "cookie@0.4.0", "path-to-regexp@0.1.7", "qs@6.7.0", "send@0.17.1", "serve-static@1.14.1"}) {
			t.Fatalf("express depends_on keeps packages not uploaded: %v", d.DependsOn)
		}
		if d.Path != "package-lock.json" {
			t.Fatalf("dependency %s path %q", d.ID, d.Path)
		}
	}
	if !bytes.Contains([]byte(log), []byte("43 package(s) without a finding are not uploaded")) {
		t.Fatalf("log: %s", log)
	}
}

func TestSCA_Python_DirectAndTransitive(t *testing.T) {
	r, _ := convertTrivy(t, "poetry-lock.json")
	if v := findingOf(t, r, "requests").Vulnerability; !v.IsDirect || !reflect.DeepEqual(v.DependencyPath, []string{"requests@2.19.1"}) {
		t.Fatalf("requests: %+v", v)
	}
	u := findingOf(t, r, "urllib3")
	if v := u.Vulnerability; v.IsDirect || !reflect.DeepEqual(v.DependencyPath, []string{"requests@2.19.1", "urllib3@1.23"}) || v.PURL != "pkg:pypi/urllib3@1.23" {
		t.Fatalf("urllib3: %+v", v)
	}
	// poetry.lock has no package lines: the lockfile alone.
	if l := u.Location; l == nil || l.Path != "poetry.lock" || l.StartLine != 0 {
		t.Fatalf("urllib3 location: %+v", l)
	}
	if got, want := depIDs(r), []string{"idna@2.7", "jinja2@2.10", "requests@2.19.1", "urllib3@1.23"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("dependencies = %v", got)
	}
	for _, d := range r.Dependencies {
		if d.ID == "jinja2@2.10" && d.DependsOn != nil {
			t.Fatalf("jinja2 depends_on names markupsafe, which is not uploaded: %v", d.DependsOn)
		}
	}
}

func TestKeepFindingDependencies(t *testing.T) {
	r := &ctis.Report{
		Findings: []ctis.Finding{
			{Vulnerability: &ctis.VulnerabilityDetails{DependencyPath: []string{"app", "a@1", "b@1"}}, SourceExtra: map[string]string{"pkg_id": "b@1"}},
			{Type: ctis.FindingTypeSecret, SourceExtra: map[string]string{"pkg_id": "secret-only@1"}},
		},
		Dependencies: []ctis.Dependency{
			{ID: "app", Relationship: "root", DependsOn: []string{"a@1", "z@1"}},
			{ID: "a@1", Relationship: "direct", DependsOn: []string{"b@1", "c@1"}},
			{ID: "b@1"}, {ID: "c@1"}, {ID: "z@1"}, {ID: "secret-only@1"},
		},
	}
	if n := keepFindingDependencies(r); n != 3 {
		t.Fatalf("removed %d", n)
	}
	if got := depIDs(r); !reflect.DeepEqual(got, []string{"a@1", "app", "b@1"}) {
		t.Fatalf("kept %v", got)
	}
	if !reflect.DeepEqual(r.Dependencies[0].DependsOn, []string{"a@1"}) || !reflect.DeepEqual(r.Dependencies[1].DependsOn, []string{"b@1"}) {
		t.Fatalf("depends_on %+v", r.Dependencies)
	}

	// The count is bounded however many findings there are.
	big := &ctis.Report{}
	for i := range maxReportDependencies + 5 {
		id := "p" + strconv.Itoa(i)
		big.Dependencies = append(big.Dependencies, ctis.Dependency{ID: id})
		big.Findings = append(big.Findings, ctis.Finding{Vulnerability: &ctis.VulnerabilityDetails{}, SourceExtra: map[string]string{"pkg_id": id}})
	}
	if n := keepFindingDependencies(big); n != 5 || len(big.Dependencies) != maxReportDependencies {
		t.Fatalf("removed %d, kept %d", n, len(big.Dependencies))
	}
	if keepFindingDependencies(nil) != 0 || keepFindingDependencies(&ctis.Report{}) != 0 {
		t.Fatal("empty report")
	}
}
