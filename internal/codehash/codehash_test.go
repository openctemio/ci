package codehash

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/openctemio/ctis"
)

// The vectors are the platform's (ctis fingerprint.SnippetHash): a change
// here re-keys every SAST finding the CLI hashes.
func TestHash_Vectors(t *testing.T) {
	for in, want := range map[string]string{
		"os.system(cmd)":           "3983deb711f566537fe2c1c9aa678e6a",
		"\t  os.system(cmd)  \r\n": "3983deb711f566537fe2c1c9aa678e6a",
		"a\nb":                     "7e18f737311b2dc3b2f269dd78396b03",
		"x  y":                     "f2c75c3a61c508182c14848e59b49fff",
		" \n\t":                    "",
	} {
		if got := Hash(in); got != want {
			t.Errorf("Hash(%q) = %q, want %q", in, got, want)
		}
	}
}

func writeTree(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "app"), 0o755); err != nil {
		t.Fatal(err)
	}
	src := "import os\n\n\ndef run(cmd):\n    os.system(cmd)\n"
	if err := os.WriteFile(filepath.Join(root, "app", "run.py"), []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}
	return root
}

func finding(p string, line int, snippet string) ctis.Finding {
	return ctis.Finding{RuleID: "py.cmdi", Location: &ctis.FindingLocation{Path: p, StartLine: line, EndLine: line, Snippet: snippet}}
}

func TestFill_HashesTheFlaggedLinesNotTheLine(t *testing.T) {
	root := writeTree(t)
	r := &ctis.Report{Findings: []ctis.Finding{
		finding("app/run.py", 5, semgrepPlaceholder),
		finding("app/run.py", 5, "os.system(cmd)"), // the scanner gave the code: left alone
		finding("../etc/passwd", 1, ""),            // outside the tree
		finding("app/missing.py", 1, ""),
		finding("app/run.py", 99, ""), // past the end
	}}
	if n := Fill(r, root); n != 1 {
		t.Fatalf("filled %d, want 1", n)
	}
	if got := r.Findings[0].PartialFingerprints[PartialKey]; got != Hash("os.system(cmd)") {
		t.Fatalf("hash = %q", got)
	}
	for i := 1; i < len(r.Findings); i++ {
		if r.Findings[i].PartialFingerprints[PartialKey] != "" {
			t.Fatalf("finding %d got a hash", i)
		}
	}
	// The same code three lines lower hashes the same: the key survives a
	// line shift.
	src := "import os\n\n\n# a\n# b\n# c\ndef run(cmd):\n    os.system(cmd)\n"
	if err := os.WriteFile(filepath.Join(root, "app", "run.py"), []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}
	r2 := &ctis.Report{Findings: []ctis.Finding{finding("app/run.py", 8, "")}}
	Fill(r2, root)
	if r2.Findings[0].PartialFingerprints[PartialKey] != r.Findings[0].PartialFingerprints[PartialKey] {
		t.Fatal("a line shift changed the hash")
	}
}

func TestFill_SymlinkOutOfTheTreeIsNotRead(t *testing.T) {
	root := writeTree(t)
	outside := filepath.Join(t.TempDir(), "secret.txt")
	if err := os.WriteFile(outside, []byte("TOKEN=abc\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(root, "app", "link.py")); err != nil {
		t.Skip("symlinks unsupported")
	}
	r := &ctis.Report{Findings: []ctis.Finding{finding("app/link.py", 1, "")}}
	if n := Fill(r, root); n != 0 {
		t.Fatal("a symlink out of the tree was read")
	}
}
