package claims

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/openctemio/ctis"
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
