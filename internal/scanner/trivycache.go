package scanner

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// ErrCacheInCheckout refuses a trivy cache directory inside the scanned
// checkout.
//
// trivy trusts its cache directory: the vulnerability database, its
// metadata (which says when the next download is due) and the checks bundle
// that iac runs. A directory in the checkout can be committed by the change
// under review, or left there by a restored CI cache the change could have
// written. Holding a database whose metadata says "fresh", it would decide
// what sca, iac and container scans find. The cache must live outside the
// checkout (the images default to /home/openctem/.cache/trivy).
var ErrCacheInCheckout = errors.New("the trivy cache directory is inside the checkout")

// trivyCacheDir is the cache directory trivy uses with this environment:
// TRIVY_CACHE_DIR, else $XDG_CACHE_HOME/trivy, else $HOME/.cache/trivy.
// A relative path is relative to the directory trivy runs in (dir).
func trivyCacheDir(env []string, dir string) string {
	get := func(k string) string {
		v := ""
		for _, kv := range env {
			if name, val, ok := strings.Cut(kv, "="); ok && name == k {
				v = val // the last one wins, as in exec
			}
		}
		return strings.TrimSpace(v)
	}
	p := get("TRIVY_CACHE_DIR")
	switch {
	case p != "":
	case get("XDG_CACHE_HOME") != "":
		p = filepath.Join(get("XDG_CACHE_HOME"), "trivy")
	case get("HOME") != "":
		p = filepath.Join(get("HOME"), ".cache", "trivy")
	default:
		return ""
	}
	if !filepath.IsAbs(p) {
		p = filepath.Join(dir, p)
	}
	return filepath.Clean(p)
}

// checkTrivyCache refuses a trivy cache inside any of the given trees (the
// scanned target and the repository root). Symbolic links are resolved on
// both sides, so a link in the checkout pointing out, or a cache path that
// reaches the checkout through a link, is judged by where it really is.
func checkTrivyCache(env []string, runDir string, trees ...string) error {
	cache := trivyCacheDir(env, runDir)
	if cache == "" {
		return nil
	}
	real := resolveExisting(cache)
	for _, t := range trees {
		if t == "" {
			continue
		}
		if within(real, resolveExisting(t)) || within(cache, filepath.Clean(t)) {
			return fmt.Errorf("%w (%s): a cache there can be committed by the change under review and would be "+
				"trusted as trivy's vulnerability database and checks. Set TRIVY_CACHE_DIR to a directory outside the "+
				"checkout (the images use /home/openctem/.cache/trivy; the GitLab templates no longer cache it in the tree)",
				ErrCacheInCheckout, cache)
		}
	}
	return nil
}

// resolveExisting resolves the symbolic links of the longest existing
// prefix of p and appends the rest unchanged.
func resolveExisting(p string) string {
	p = filepath.Clean(p)
	rest := ""
	for {
		if r, err := filepath.EvalSymlinks(p); err == nil {
			return filepath.Join(r, rest)
		}
		parent := filepath.Dir(p)
		if parent == p {
			return filepath.Join(p, rest)
		}
		rest = filepath.Join(filepath.Base(p), rest)
		p = parent
	}
}

// within reports whether p is root or below it.
func within(p, root string) bool {
	rel, err := filepath.Rel(root, p)
	if err != nil {
		return false
	}
	return rel == "." || (rel != ".." && !strings.HasPrefix(rel, ".."+string(os.PathSeparator)))
}
