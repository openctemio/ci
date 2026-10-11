package main

// Diff-aware SAST on pull and merge requests: semgrep reports only what the
// change adds compared with the merge base, so a pull request is judged on
// its own findings and the scan stays fast on large repositories. Default
// branch runs and schedules always scan in full, which keeps the platform's
// baseline complete.

import (
	"context"
	"os/exec"
	"strings"
	"time"

	"github.com/openctemio/ci/internal/ciinfo"
	"github.com/openctemio/ci/internal/scanner"
)

// gitRunner runs git with fixed arguments in a directory and returns its
// trimmed output (replaced in tests).
type gitRunner func(ctx context.Context, dir string, args ...string) (string, error)

func runGit(ctx context.Context, dir string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "git", append([]string{"-C", dir}, args...)...) //nolint:gosec // fixed git subcommands; branch names are checked
	cmd.Env = []string{"GIT_TERMINAL_PROMPT=0", "HOME=/nonexistent", "PATH=/usr/bin:/bin:/usr/local/bin"}
	out, err := cmd.Output()
	return strings.TrimSpace(string(out)), err
}

// safeBranch reports whether a branch name can be passed to git as a ref.
func safeBranch(b string) bool {
	return b != "" && len(b) <= 255 && !strings.HasPrefix(b, "-") && !strings.Contains(b, "..") &&
		!strings.ContainsFunc(b, func(r rune) bool { return r <= ' ' || r == 0x7f || strings.ContainsRune(`~^:?*[\`, r) })
}

// baselineCommit returns the commit a diff-aware sast scan compares with,
// and a line saying what the scan does. "" means a full scan.
func baselineCommit(ctx context.Context, mode string, info ciinfo.Info, getenv func(string) string, git gitRunner) (string, string) {
	if mode == "off" {
		return "", "full scan (--diff off)"
	}
	if info.PullRequest == "" {
		return "", "full scan (not a pull or merge request)"
	}
	if info.Fork {
		return "", "full scan (fork)"
	}
	dir := info.Workspace
	// GitLab names the merge base itself.
	if sha := strings.ToLower(strings.TrimSpace(getenv("CI_MERGE_REQUEST_DIFF_BASE_SHA"))); scanner.CommitID(sha) {
		if _, err := git(ctx, dir, "cat-file", "-e", sha+"^{commit}"); err == nil {
			return sha, "diff-aware: findings new since the merge base " + sha[:12]
		}
		return "", "full scan (the merge base is not in the clone: fetch more history)"
	}
	target := info.TargetBranch
	if !safeBranch(target) {
		return "", "full scan (no target branch)"
	}
	for _, ref := range []string{"refs/remotes/origin/" + target, "origin/" + target, target} {
		if sha, err := git(ctx, dir, "merge-base", "HEAD", ref); err == nil && scanner.CommitID(sha) {
			return sha, "diff-aware: findings new since the merge base with " + target + " (" + sha[:12] + ")"
		}
	}
	return "", "full scan (no merge base with " + target + ": check out with full history, e.g. fetch-depth: 0)"
}
