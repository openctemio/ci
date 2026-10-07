// Package redact keeps raw secret values out of everything openctem-ci
// writes or uploads: the CTIS report sent to the platform, the SARIF file,
// the GitLab security report and the log.
//
// Two layers: every finding is masked with ctis.RedactSecretFinding (with
// the raw values the secret scanner reported), and every serialized output
// is checked for those raw values before it is written or sent. A value
// that survives the masking stops the run instead of leaking (fail closed).
package redact

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"

	"github.com/openctemio/ctis"
	"github.com/openctemio/ctis/importer"
)

// ErrSecretInOutput: an output still holds a raw secret value.
var ErrSecretInOutput = errors.New("an output still holds a raw secret value; nothing was written or sent")

// minLen is the shortest raw value checked (ctis masks from 4 characters).
const minLen = 4

// maxSecrets bounds the raw values collected from one report.
const maxSecrets = 100000

// RawSecrets returns the raw values a secret scanner reported in its native
// output (gitleaks-compatible JSON: Secret and Match of each leak). Other
// formats carry no raw secret field and return nil.
func RawSecrets(format importer.Format, output []byte) []string {
	if format != importer.FormatBetterleaks && format != importer.FormatGitleaks {
		return nil
	}
	var leaks []struct {
		Secret string `json:"Secret"`
		Match  string `json:"Match"`
	}
	if err := json.Unmarshal(output, &leaks); err != nil {
		return nil
	}
	seen := map[string]bool{}
	var out []string
	add := func(s string) {
		s = strings.TrimSpace(s)
		if len(s) >= minLen && !seen[s] && len(out) < maxSecrets {
			seen[s] = true
			out = append(out, s)
		}
	}
	for _, l := range leaks {
		add(l.Secret)
		add(l.Match)
	}
	return out
}

// Report masks every finding of report with the known raw values; secret
// findings also have their snippet and masked value masked.
func Report(report *ctis.Report, known []string) {
	if report == nil {
		return
	}
	for i := range report.Findings {
		ctis.RedactSecretFinding(&report.Findings[i], known...)
	}
}

// Check returns ErrSecretInOutput when data holds one of the raw values,
// as written or JSON-escaped.
func Check(data []byte, known []string) error {
	if len(known) == 0 {
		return nil
	}
	s := string(data)
	for _, k := range known {
		if len(k) < minLen {
			continue
		}
		if strings.Contains(s, k) {
			return ErrSecretInOutput
		}
		if esc := jsonEscaped(k); esc != k && strings.Contains(s, esc) {
			return ErrSecretInOutput
		}
	}
	return nil
}

// jsonEscaped is s as encoding/json writes it inside a string.
func jsonEscaped(s string) string {
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(true)
	_ = enc.Encode(s)
	out := strings.TrimSpace(b.String())
	return strings.TrimSuffix(strings.TrimPrefix(out, `"`), `"`)
}
