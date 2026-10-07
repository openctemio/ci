package redact

import (
	"encoding/json"
	"errors"
	"testing"

	"github.com/openctemio/ctis"
	"github.com/openctemio/ctis/importer"
)

const raw = "Zq8vT3xK9mB2nR7wL4pY6sD1fH5jC0gA"

func TestRawSecrets(t *testing.T) {
	out := []byte(`[{"Secret":"` + raw + `","Match":"api_key = \"` + raw + `\""},{"Secret":"abc","Match":""},{"Secret":"` + raw + `"}]`)
	got := RawSecrets(importer.FormatBetterleaks, out)
	if len(got) != 2 || got[0] != raw {
		t.Fatalf("%q", got)
	}
	if RawSecrets(importer.FormatSemgrep, out) != nil {
		t.Fatal("semgrep output has no raw secret field")
	}
	if RawSecrets(importer.FormatBetterleaks, []byte("not json")) != nil {
		t.Fatal("garbage gave secrets")
	}
}

// Every field of the report is masked, not only the secret's own members.
func TestReportMasksEverywhere(t *testing.T) {
	r := &ctis.Report{Findings: []ctis.Finding{{
		Type: ctis.FindingTypeSecret, Title: "key " + raw, Description: "found " + raw,
		Location: &ctis.FindingLocation{Path: "a.py", Snippet: `api_key = "` + raw + `"`},
		Secret:   &ctis.SecretDetails{MaskedValue: raw},
		Tags:     []string{raw},
	}, {
		Type: ctis.FindingTypeVulnerability, Title: "unrelated finding mentioning " + raw,
	}}}
	Report(r, []string{raw})
	b, _ := json.Marshal(r)
	if err := Check(b, []string{raw}); err != nil {
		t.Fatalf("raw value left: %s", b)
	}
}

func TestCheck(t *testing.T) {
	if !errors.Is(Check([]byte(`{"x":"`+raw+`"}`), []string{raw}), ErrSecretInOutput) {
		t.Fatal("raw value not detected")
	}
	quoted := `p<a>"&` + raw
	enc, _ := json.Marshal(map[string]string{"x": quoted})
	if !errors.Is(Check(enc, []string{quoted}), ErrSecretInOutput) {
		t.Fatalf("JSON-escaped value not detected: %s", enc)
	}
	if Check([]byte("clean"), []string{raw}) != nil || Check([]byte(raw), nil) != nil {
		t.Fatal("false positive")
	}
	if Check([]byte("abc"), []string{"abc"}) != nil {
		t.Fatal("values under 4 characters are not checked")
	}
}
