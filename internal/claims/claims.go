// Package claims finds what a repository says about its own results: inline
// ignore comments (nosemgrep, nosem, noopengrep) and the patterns of a
// .semgrepignore file. They are the author's claims, never decisions: the
// scanner runs with --disable-nosem and --x-ignore-semgrepignore-files so the
// results are still reported, the job marks each claimed result as an
// in-source suppression, and OpenCTEM turns the claims of a default-branch
// run into pending requests for the security team. The gate counts the
// results meanwhile.
package claims

import (
	"bufio"
	"io/fs"
	"os"
	"path"
	"regexp"
	"strings"

	"github.com/openctemio/ctis"
)

// IgnoreFile is the scanner ignore file read at the repository root.
const IgnoreFile = ".semgrepignore"

// Property is the report metadata property that lists the ignore file's
// patterns.
const Property = "ignore_file_paths"

// MaxPatterns and maxPatternLen bound what is sent.
const (
	MaxPatterns   = 20
	maxPatternLen = 500
	maxLineBytes  = 64 << 10
	maxFileBytes  = 64 << 10
)

// marker is an inline ignore comment: the word, optionally ": rule-ids".
var marker = regexp.MustCompile(`(?i)\b(nosemgrep|noopengrep|nosem)\b`)

// MarkInline marks each finding whose flagged line, or the line above it,
// carries an inline ignore comment as an in-source suppression (unless the
// importer already did). Files are read through an os.Root at root. It
// returns how many it marked.
func MarkInline(r *ctis.Report, root string) int {
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
		if f.Suppression != nil || f.Location == nil || f.Location.Path == "" || f.Location.StartLine <= 0 {
			continue
		}
		if hasMarker(rt, f.Location.Path, f.Location.StartLine) {
			f.Suppression = &ctis.Suppression{Kind: "in_source", Status: "under_review", Justification: "inline ignore comment"}
			n++
		}
	}
	return n
}

func hasMarker(rt *os.Root, p string, line int) bool {
	p = path.Clean(strings.ReplaceAll(p, "\\", "/"))
	if !fs.ValidPath(p) {
		return false
	}
	fh, err := rt.Open(p)
	if err != nil {
		return false
	}
	defer func() { _ = fh.Close() }()
	if st, err := fh.Stat(); err != nil || !st.Mode().IsRegular() {
		return false
	}
	sc := bufio.NewScanner(fh)
	sc.Buffer(make([]byte, 0, 4096), maxLineBytes)
	for n := 1; sc.Scan(); n++ {
		// On the flagged line, or alone on the line above (a trailing
		// comment on the line above marks that line, not this one).
		if (n == line && marker.MatchString(sc.Text())) || (n == line-1 && commentOnly(sc.Text()) && marker.MatchString(sc.Text())) {
			return true
		}
		if n >= line {
			return false
		}
	}
	return false
}

// commentOnly reports whether a line holds only a comment.
func commentOnly(l string) bool {
	l = strings.TrimSpace(l)
	for _, p := range []string{"#", "//", "/*", "*", "--", "<!--", ";"} {
		if strings.HasPrefix(l, p) {
			return true
		}
	}
	return false
}

// IgnorePatterns reads the repository's ignore file at root: its pattern
// lines (no comments, blanks, negations or include directives), at most
// MaxPatterns. A missing or unreadable file gives none.
func IgnorePatterns(root string) []string {
	if root == "" {
		return nil
	}
	rt, err := os.OpenRoot(root)
	if err != nil {
		return nil
	}
	defer func() { _ = rt.Close() }()
	fh, err := rt.Open(IgnoreFile)
	if err != nil {
		return nil
	}
	defer func() { _ = fh.Close() }()
	if st, err := fh.Stat(); err != nil || !st.Mode().IsRegular() || st.Size() > maxFileBytes {
		return nil
	}
	var out []string
	sc := bufio.NewScanner(fh)
	sc.Buffer(make([]byte, 0, 4096), maxLineBytes)
	for sc.Scan() && len(out) < MaxPatterns {
		l := strings.TrimSpace(sc.Text())
		if l == "" || strings.HasPrefix(l, "#") || strings.HasPrefix(l, "!") || strings.HasPrefix(l, ":") ||
			len(l) > maxPatternLen || strings.ContainsAny(l, "\x00\r") {
			continue
		}
		out = append(out, l)
	}
	return out
}
