package capability

import (
	"strings"
	"testing"

	taxonomy "github.com/openctemio/ctis/capability"
)

func TestParse(t *testing.T) {
	cases := map[string][]string{
		"sast":                   {"sast"},
		"sast,sca,secrets":       {"sast", "sca", "secrets"},
		"secrets sast":           {"sast", "secrets"},
		"SAST, sast":             {"sast"},
		"all":                    {"sast", "sca", "secrets", "iac"},
		"all,container":          {"sast", "sca", "secrets", "iac", "container"},
		"sast.code@1,sca.deps":   {"sast", "sca"},
		"container.image@1, iac": {"iac", "container"},
	}
	for in, want := range cases {
		got, err := Parse(in)
		if err != nil {
			t.Fatalf("Parse(%q): %v", in, err)
		}
		var names []string
		for _, c := range got {
			names = append(names, c.Name)
		}
		if strings.Join(names, ",") != strings.Join(want, ",") {
			t.Errorf("Parse(%q) = %v, want %v", in, names, want)
		}
	}
	for _, bad := range []string{"", " , ", "dast", "sast,nuclei", "sast.code@2"} {
		if _, err := Parse(bad); err == nil {
			t.Errorf("Parse(%q) accepted", bad)
		}
	}
}

// Every capability id is a routed id of the platform taxonomy at major 1:
// a report that names it is filed by the platform the same way whatever
// tool produced it.
func TestIDsAreTaxonomyIDs(t *testing.T) {
	for _, c := range All() {
		id, major, ok := taxonomy.ParseRef(c.ID)
		if !ok || major != 1 {
			t.Fatalf("%s: %q is not an id@1 reference", c.Name, c.ID)
		}
		tc, ok := taxonomy.Lookup(c.ID)
		if !ok {
			t.Fatalf("%s: %q is not in the taxonomy", c.Name, c.ID)
		}
		if tc.ID != id {
			t.Errorf("%s: taxonomy returned %q for %q", c.Name, tc.ID, c.ID)
		}
	}
}

func TestCatalogIsComplete(t *testing.T) {
	seen := map[string]bool{}
	for _, c := range All() {
		if c.Name == "" || c.Tool == "" || c.Image == "" || c.GitLabReport == "" || c.GitLabFile == "" || c.Target == "" {
			t.Errorf("incomplete entry %+v", c)
		}
		if seen[c.GitLabFile] {
			t.Errorf("two capabilities write %s: one would overwrite the other in a bundle job", c.GitLabFile)
		}
		seen[c.GitLabFile] = true
		if !strings.HasPrefix(c.Image, "ci-") {
			t.Errorf("%s: image %q is not a ci-<tool> image", c.Name, c.Image)
		}
	}
	if got := Tools(); strings.Join(got, ",") != "betterleaks,semgrep,trivy" {
		t.Errorf("Tools() = %v", got)
	}
	if c, _ := Lookup("sast"); c.ImageRef("v1") != "ghcr.io/openctemio/ci-semgrep:v1" {
		t.Errorf("ImageRef = %s", c.ImageRef("v1"))
	}
}
