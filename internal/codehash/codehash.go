// Package codehash gives a SAST finding the hash of the code it flags when
// the scanner left the snippet out (Semgrep without a login writes a
// placeholder). OpenCTEM keys a SAST finding on the rule, the path and this
// hash, not on its line: a finding marked a false positive stays one when
// code above it moves, and becomes a new finding when the flagged code
// itself changes. Only the hash leaves the job, never the source.
package codehash

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io/fs"
	"os"
	"path"
	"regexp"
	"strings"

	"github.com/openctemio/ctis"
)

// PartialKey is the CTIS partial_fingerprints key that carries the hash
// (ctis fingerprint.PartialSnippetHash).
const PartialKey = "snippetHash/v1"

// MaxLines is how many lines of a match are hashed (ctis
// fingerprint.MaxSnippetHashLines): scanners keep the first lines of a long
// match, so the job cuts where they cut.
const MaxLines = 10

// maxLineBytes bounds one source line read; a longer line (minified code)
// gets no hash and the finding keeps its line key.
const maxLineBytes = 64 << 10

// semgrepPlaceholder is what Semgrep without a login writes as the snippet.
const semgrepPlaceholder = "requires login"

var space = regexp.MustCompile(`\s+`)

// Hash is the SnippetHash of CTIS (ctis fingerprint.SnippetHash): each line
// trimmed, inner ASCII whitespace runs made one space, empty lines dropped,
// joined with LF; the first 16 bytes of the SHA-256 in lowercase hex. "" when
// no code is left.
func Hash(snippet string) string {
	lines := strings.Split(strings.ReplaceAll(snippet, "\r\n", "\n"), "\n")
	kept := make([]string, 0, len(lines))
	for _, l := range lines {
		if t := strings.TrimSpace(l); t != "" {
			kept = append(kept, space.ReplaceAllString(t, " "))
		}
	}
	if len(kept) == 0 {
		return ""
	}
	sum := sha256.Sum256([]byte(strings.Join(kept, "\n")))
	return hex.EncodeToString(sum[:16])
}

// Fill sets PartialKey on every finding of r that has a repository path and
// a start line but no snippet, from the lines it flags in the tree at root.
// Files are opened through an os.Root, so a path cannot leave the tree (no
// "..", no symlink out). A file that cannot be read is skipped: the finding
// keeps the key the platform derives from its line. It returns how many
// findings got a hash.
func Fill(r *ctis.Report, root string) int {
	if r == nil || root == "" {
		return 0
	}
	rt, err := os.OpenRoot(root)
	if err != nil {
		return 0
	}
	defer func() { _ = rt.Close() }()
	n := 0
	for i := range r.Findings {
		f := &r.Findings[i]
		loc := f.Location
		if loc == nil || loc.Path == "" || loc.StartLine <= 0 {
			continue
		}
		if s := strings.TrimSpace(loc.Snippet); s != "" && s != semgrepPlaceholder {
			continue
		}
		if f.PartialFingerprints[PartialKey] != "" {
			continue
		}
		end := loc.EndLine
		if end < loc.StartLine {
			end = loc.StartLine
		}
		if end-loc.StartLine >= MaxLines {
			end = loc.StartLine + MaxLines - 1
		}
		code, err := readLines(rt, loc.Path, loc.StartLine, end)
		if err != nil {
			continue
		}
		h := Hash(code)
		if h == "" {
			continue
		}
		if f.PartialFingerprints == nil {
			f.PartialFingerprints = map[string]string{}
		}
		f.PartialFingerprints[PartialKey] = h
		n++
	}
	return n
}

var errLine = errors.New("line not found")

func readLines(rt *os.Root, p string, start, end int) (string, error) {
	p = path.Clean(strings.ReplaceAll(p, "\\", "/"))
	if !fs.ValidPath(p) {
		return "", fs.ErrInvalid
	}
	fh, err := rt.Open(p)
	if err != nil {
		return "", err
	}
	defer func() { _ = fh.Close() }()
	if st, err := fh.Stat(); err != nil || !st.Mode().IsRegular() {
		return "", fs.ErrInvalid
	}
	sc := bufio.NewScanner(fh)
	sc.Buffer(make([]byte, 0, 4096), maxLineBytes)
	var b strings.Builder
	for line := 1; sc.Scan(); line++ {
		if line < start {
			continue
		}
		b.WriteString(sc.Text())
		b.WriteByte('\n')
		if line >= end {
			return b.String(), nil
		}
	}
	if err := sc.Err(); err != nil {
		return "", err
	}
	if b.Len() > 0 {
		return b.String(), nil
	}
	return "", errLine
}
