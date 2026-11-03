package claims

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
	"unicode"

	"github.com/openctemio/ctis/v2"
)

func tree(t *testing.T, files map[string]string) string {
	t.Helper()
	root := t.TempDir()
	for p, c := range files {
		full := filepath.Join(root, p)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(c), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

func at(p string, line int) ctis.Finding {
	return ctis.Finding{RuleID: "r", Location: &ctis.FindingLocation{Path: p, StartLine: line}}
}

func TestMarkInline(t *testing.T) {
	root := tree(t, map[string]string{"a.py": "import os\nos.system(a)  # nosemgrep\nos.system(z)\n# nosemgrep: r\nos.system(b)\nos.system(c)\n"})
	r := &ctis.Report{Findings: []ctis.Finding{at("a.py", 2), at("a.py", 5), at("a.py", 6), at("a.py", 3), at("../x.py", 1), at("missing.py", 1)}}
	if n := MarkInline(r, root); n != 2 {
		t.Fatalf("marked %d, want 2 (same line, comment line above)", n)
	}
	if r.Findings[0].Suppression == nil || r.Findings[1].Suppression == nil || r.Findings[2].Suppression != nil || r.Findings[3].Suppression != nil {
		t.Fatal("a trailing comment on the line above marked the next line, or a marker was missed")
	}
	if r.Findings[0].Suppression.Kind != "in_source" {
		t.Fatal("not an in-source claim")
	}
}

func TestIgnorePatterns(t *testing.T) {
	root := tree(t, map[string]string{IgnoreFile: "# comment\n\ngenerated/**\n!keep.py\n:include .gitignore\nlegacy/\n"})
	got := IgnorePatterns(root)
	if len(got) != 2 || got[0] != "generated/**" || got[1] != "legacy/" {
		t.Fatalf("patterns %v", got)
	}
	if IgnorePatterns(t.TempDir()) != nil {
		t.Fatal("patterns without a file")
	}
}

// The ignore-file patterns go in the io.openctem extension (never in
// properties), and stay inside the receiver's bounds: at most 100 patterns of
// at most 500 characters, none with a control character.
func TestSetIgnorePatternsBounds(t *testing.T) {
	var pats []string
	for i := 0; i < 150; i++ {
		pats = append(pats, "dir"+string(rune('a'+i%26))+"/"+string(rune('a'+i/26))+"/**")
	}
	pats = append(pats, strings.Repeat("x", MaxPatternLen+1), "bad\x01pattern", "tab\tpattern", "")
	r := &ctis.Report{}
	n := SetIgnorePatterns(r, pats)
	v, ok := r.Metadata.Extensions.Get(ctis.OpenCTEMNamespace, ExtensionKey)
	list, _ := v.([]string)
	if !ok || n != len(list) || n != MaxPatterns || n > 100 {
		t.Fatalf("recorded %d (%d in the report)", n, len(list))
	}
	for _, p := range list {
		if len(p) == 0 || len(p) > 500 || strings.ContainsFunc(p, unicode.IsControl) {
			t.Fatalf("pattern %q is out of bounds", p)
		}
	}
	if len(r.Metadata.Properties) != 0 {
		t.Fatalf("the patterns leaked into properties: %v", r.Metadata.Properties)
	}
	r.Version, r.Metadata.ID, r.Metadata.GeneratedAt = ctis.SchemaVersion, ctis.NewReportID(), time.Now()
	if err := r.Validate(); err != nil {
		t.Fatalf("the extension does not validate: %v", err)
	}
	if SetIgnorePatterns(&ctis.Report{}, []string{"bad\x00", strings.Repeat("y", 501)}) != 0 {
		t.Fatal("out-of-bounds patterns recorded")
	}
}

func TestIgnorePatternsSkipsControlCharacters(t *testing.T) {
	root := tree(t, map[string]string{IgnoreFile: "ok/\nbad\x01pat\ntab\tpat\n" + strings.Repeat("z", 501) + "\n"})
	if got := IgnorePatterns(root); len(got) != 1 || got[0] != "ok/" {
		t.Fatalf("%q", got)
	}
}
