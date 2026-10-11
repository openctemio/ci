package repopolicy

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoad(t *testing.T) {
	dir := t.TempDir()
	if raw, _, err := Load(dir); raw != nil || err != nil {
		t.Fatalf("no file: %s %v", raw, err)
	}
	file := `gate:
  fail_on_severity: medium
  new_findings_only: false
  block_rules: [go.sqli]
  exceptions:
    - rule_id: go.weak-hash
      path: legacy/**
      reason: being removed this quarter
      expires: 2026-12-01
`
	if err := os.WriteFile(filepath.Join(dir, ".openctem.yml"), []byte(file), 0o600); err != nil {
		t.Fatal(err)
	}
	raw, name, err := Load(dir)
	if err != nil || name != ".openctem.yml" {
		t.Fatalf("load: %v %s", err, name)
	}
	var g map[string]any
	if err := json.Unmarshal(raw, &g); err != nil || g["fail_on_severity"] != "medium" || g["new_findings_only"] != false {
		t.Fatalf("gate = %s", raw)
	}
	ex := g["exceptions"].([]any)[0].(map[string]any)
	if ex["rule_id"] != "go.weak-hash" || ex["expires"] != "2026-12-01" {
		t.Fatalf("exception = %v", ex)
	}
}

func TestLoadRefusesWhatItCannotTrust(t *testing.T) {
	for name, content := range map[string]string{
		"typo":        "gate:\n  fail_on_severty: medium\n",
		"unknown top": "gates: {}\n",
		"not yaml":    "gate: [\n",
		"wrong type":  "gate:\n  new_findings_only: maybe\n",
	} {
		dir := t.TempDir()
		_ = os.WriteFile(filepath.Join(dir, ".openctem.yml"), []byte(content), 0o600)
		if _, _, err := Load(dir); err == nil {
			t.Fatalf("%s: accepted", name)
		}
	}
	// Too large.
	dir := t.TempDir()
	_ = os.WriteFile(filepath.Join(dir, ".openctem.yml"), []byte("# "+strings.Repeat("x", MaxSize)), 0o600)
	if _, _, err := Load(dir); err == nil {
		t.Fatal("oversized file accepted")
	}
	// A symlink (could point outside the checkout).
	dir = t.TempDir()
	if err := os.Symlink("/etc/hostname", filepath.Join(dir, ".openctem.yml")); err == nil {
		if _, _, err := Load(dir); err == nil {
			t.Fatal("symlink accepted")
		}
	}
	// No gate section: nothing to send.
	dir = t.TempDir()
	_ = os.WriteFile(filepath.Join(dir, ".openctem.yaml"), []byte("gate:\n"), 0o600)
	if raw, _, err := Load(dir); err != nil || raw != nil {
		t.Fatalf("empty gate: %s %v", raw, err)
	}
}
