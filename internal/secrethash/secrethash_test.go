package secrethash

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/openctemio/ctis"
	"github.com/openctemio/ctis/importer"
)

const out = `[{"RuleID":"generic-api-key","StartLine":2,"Secret":"Zq8vT3xK9mB2nR7wL4pY6sD1fH5jC0gA"},
 {"RuleID":"generic-api-key","StartLine":9,"Secret":"Other0secret0value0000000000000"}]`

func sec(rule string, line int) ctis.Finding {
	return ctis.Finding{RuleID: rule, Secret: &ctis.SecretDetails{MaskedValue: "Zq8v****"},
		Location: &ctis.FindingLocation{Path: "a.py", StartLine: line}}
}

func TestApply(t *testing.T) {
	key := []byte(strings.Repeat("k", 32))
	r := &ctis.Report{Findings: []ctis.Finding{sec("generic-api-key", 9), sec("generic-api-key", 2), sec("other", 2)}}
	if n := Apply(r, importer.FormatBetterleaks, []byte(out), key); n != 2 {
		t.Fatalf("hashed %d, want 2", n)
	}
	m := hmac.New(sha256.New, key)
	m.Write([]byte("Zq8vT3xK9mB2nR7wL4pY6sD1fH5jC0gA"))
	if r.Findings[1].PartialFingerprints[PartialKey] != hex.EncodeToString(m.Sum(nil)) {
		t.Fatal("wrong hash for the line-2 secret")
	}
	if r.Findings[0].PartialFingerprints[PartialKey] == r.Findings[1].PartialFingerprints[PartialKey] {
		t.Fatal("two secrets share a hash")
	}
	if r.Findings[2].PartialFingerprints[PartialKey] != "" {
		t.Fatal("a finding of another rule got a hash")
	}
	for _, f := range r.Findings {
		for _, v := range f.PartialFingerprints {
			if strings.Contains(v, "Zq8vT3") {
				t.Fatal("the raw secret is in the report")
			}
		}
	}
	if Apply(&ctis.Report{Findings: []ctis.Finding{sec("generic-api-key", 2)}}, importer.FormatBetterleaks, []byte(out), nil) != 0 {
		t.Fatal("hashed without a key")
	}
}
