package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/openctemio/ci/internal/gate"
)

// status is what a scan job hands to the final gate job: whether the scan
// completed and reached the platform, and the counts the local gate needs.
// It holds no finding text, so it can travel as a CI artifact.
type status struct {
	Capability string     `json:"capability"`
	Tool       string     `json:"tool"`
	Version    string     `json:"tool_version,omitempty"`
	OK         bool       `json:"ok"`
	Pushed     bool       `json:"pushed"`
	Error      string     `json:"error,omitempty"`
	Tally      gate.Tally `json:"tally"`
}

// statusSuffix ends every status file name.
const statusSuffix = ".status.json"

// Limits on what the gate job reads.
const (
	maxStatusFiles = 64
	maxStatusSize  = 64 << 10
)

var capNameRe = regexp.MustCompile(`^[a-z][a-z0-9_-]{0,31}$`)

func writeStatus(path string, s status) error {
	b, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	if dir := filepath.Dir(path); dir != "" {
		if err := os.MkdirAll(dir, 0o750); err != nil {
			return err
		}
	}
	return os.WriteFile(path, append(b, '\n'), 0o644) // #nosec G306 -- a CI artifact, no secret
}

// readStatuses reads every *.status.json under dir (one level of
// subdirectories, the shape CI artifact downloads take), keyed by
// capability. Two files for one capability are an error: a job cannot
// stand in for another.
func readStatuses(dir string) (map[string]status, error) {
	var files []string
	for _, pattern := range []string{"*" + statusSuffix, "*/*" + statusSuffix} {
		m, err := filepath.Glob(filepath.Join(dir, pattern))
		if err != nil {
			return nil, err
		}
		files = append(files, m...)
	}
	if len(files) > maxStatusFiles {
		return nil, fmt.Errorf("more than %d status files under %s", maxStatusFiles, dir)
	}
	out := map[string]status{}
	for _, f := range files {
		s, err := readStatus(f)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", f, err)
		}
		if _, dup := out[s.Capability]; dup {
			return nil, fmt.Errorf("two status files for capability %q", s.Capability)
		}
		out[s.Capability] = s
	}
	return out, nil
}

func readStatus(path string) (status, error) {
	var s status
	fi, err := os.Lstat(path)
	if err != nil {
		return s, err
	}
	if !fi.Mode().IsRegular() {
		return s, errors.New("not a regular file")
	}
	f, err := os.Open(path) // #nosec G304 -- a status file the pipeline handed over
	if err != nil {
		return s, err
	}
	defer func() { _ = f.Close() }()
	data, err := io.ReadAll(io.LimitReader(f, maxStatusSize+1))
	if err != nil {
		return s, err
	}
	if len(data) > maxStatusSize {
		return s, errors.New("status file too large")
	}
	if err := json.Unmarshal(data, &s); err != nil {
		return s, fmt.Errorf("not a status file: %w", err)
	}
	s.Capability = strings.ToLower(strings.TrimSpace(s.Capability))
	if !capNameRe.MatchString(s.Capability) {
		return s, errors.New("status file names no valid capability")
	}
	for k, v := range s.Tally.Severity {
		if v < 0 || len(k) > 16 {
			return s, errors.New("status file has an invalid tally")
		}
	}
	for k, v := range s.Tally.Risk {
		if v < 0 || len(k) > 16 {
			return s, errors.New("status file has an invalid tally")
		}
	}
	return s, nil
}
