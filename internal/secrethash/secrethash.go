// Package secrethash gives each secret finding the keyed hash of its raw
// value, so OpenCTEM keys the finding on the secret itself while the value
// never leaves the job: HMAC-SHA256 under the key the platform hands the
// run (per organization and repository), sent as the CTIS partial
// fingerprint secretHMAC/v1. Two different secrets with the same masked
// value stay two findings, and a change of masking keeps a finding.
package secrethash

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"

	"github.com/openctemio/ctis"
	"github.com/openctemio/ctis/importer"
)

// PartialKey is the CTIS partial_fingerprints key of the hash.
const PartialKey = "secretHMAC/v1"

type leak struct {
	RuleID    string `json:"RuleID"`
	StartLine int    `json:"StartLine"`
	Secret    string `json:"Secret"`
}

// Applies reports whether the tool's output carries raw secrets to hash: only
// then does the job need the key (and so the run) before its upload.
func Applies(format importer.Format) bool {
	return format == importer.FormatBetterleaks || format == importer.FormatGitleaks
}

// Apply hashes, with key, the raw secret behind each secret finding of r:
// the leak of the scanner output with the same rule and line, in order (the
// importer keeps the scanner's order). It returns how many findings it
// hashed; without a key, or for another format, none.
func Apply(r *ctis.Report, format importer.Format, output []byte, key []byte) int {
	if r == nil || len(key) == 0 || !Applies(format) {
		return 0
	}
	var leaks []leak
	if err := json.Unmarshal(output, &leaks); err != nil {
		return 0
	}
	used := make([]bool, len(leaks))
	n := 0
	for i := range r.Findings {
		f := &r.Findings[i]
		if f.Secret == nil || f.Location == nil {
			continue
		}
		for j, l := range leaks {
			if used[j] || l.RuleID != f.RuleID || l.StartLine != f.Location.StartLine || strings.TrimSpace(l.Secret) == "" {
				continue
			}
			used[j] = true
			m := hmac.New(sha256.New, key)
			m.Write([]byte(strings.TrimSpace(l.Secret)))
			if f.PartialFingerprints == nil {
				f.PartialFingerprints = map[string]string{}
			}
			f.PartialFingerprints[PartialKey] = hex.EncodeToString(m.Sum(nil))
			n++
			break
		}
	}
	return n
}
