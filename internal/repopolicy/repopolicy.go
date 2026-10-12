// Package repopolicy reads the gate part of a repository's .openctem.yml.
// The platform applies it only where it is stricter than the organization's
// policy, and turns its exceptions into requests an administrator approves;
// the file never lets a finding pass on its own.
package repopolicy

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

// Names are the file names read, in order.
var Names = []string{".openctem.yml", ".openctem.yaml"}

// MaxSize bounds the file.
const MaxSize = 64 << 10

// File is the repository file. Only gate is read today; unknown keys are an
// error so a typo never silently drops a rule.
type File struct {
	Gate *Gate `yaml:"gate" json:"gate,omitempty"`
}

// Gate is what the platform's gate takes from the file.
type Gate struct {
	FailOnSeverity  string      `yaml:"fail_on_severity" json:"fail_on_severity,omitempty"`
	NewFindingsOnly *bool       `yaml:"new_findings_only" json:"new_findings_only,omitempty"`
	FailOnKEV       *bool       `yaml:"fail_on_kev" json:"fail_on_kev,omitempty"`
	EPSSThreshold   *float64    `yaml:"epss_threshold" json:"epss_threshold,omitempty"`
	BlockRules      []string    `yaml:"block_rules" json:"block_rules,omitempty"`
	Exceptions      []Exception `yaml:"exceptions" json:"exceptions,omitempty"`
}

// Exception asks for a rule (on an optional path pattern) to be suppressed
// until a date.
type Exception struct {
	RuleID  string `yaml:"rule_id" json:"rule_id"`
	Path    string `yaml:"path" json:"path,omitempty"`
	Reason  string `yaml:"reason" json:"reason"`
	Expires string `yaml:"expires" json:"expires"`
}

// Load reads the file at the repository root dir. It returns the gate part
// as the JSON the platform takes, or nil when there is no file or no gate
// section. A file that cannot be read or parsed is an error: the scan must
// not go on as if the repository asked for nothing.
func Load(dir string) (json.RawMessage, string, error) {
	for _, name := range Names {
		p := filepath.Join(dir, name)
		fi, err := os.Lstat(p)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return nil, name, fmt.Errorf("%s: %w", name, err)
		}
		if !fi.Mode().IsRegular() {
			return nil, name, fmt.Errorf("%s is not a regular file", name)
		}
		f, err := os.Open(p) //nolint:gosec // a fixed name in the checkout
		if err != nil {
			return nil, name, fmt.Errorf("%s: %w", name, err)
		}
		data, err := io.ReadAll(io.LimitReader(f, MaxSize+1))
		_ = f.Close()
		if err != nil {
			return nil, name, fmt.Errorf("%s: %w", name, err)
		}
		if len(data) > MaxSize {
			return nil, name, fmt.Errorf("%s is larger than %d bytes", name, MaxSize)
		}
		raw, err := Parse(data)
		if err != nil {
			return nil, name, fmt.Errorf("%s: %w", name, err)
		}
		return raw, name, nil
	}
	return nil, "", nil
}

// Parse decodes the file strictly and returns its gate part as JSON.
func Parse(data []byte) (json.RawMessage, error) {
	var file File
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(&file); err != nil && !errors.Is(err, io.EOF) {
		return nil, err
	}
	if file.Gate == nil {
		return nil, nil
	}
	return json.Marshal(file.Gate)
}
