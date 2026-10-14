package main

import (
	"context"
	"errors"
	"os/exec"
	"strings"
	"testing"

	"github.com/openctemio/ci/internal/ciinfo"
)

func fakeGit(answers map[string]string) gitRunner {
	return func(_ context.Context, _ string, args ...string) (string, error) {
		if out, ok := answers[strings.Join(args, " ")]; ok {
			return out, nil
		}
		return "", errors.New("unknown")
	}
}

func TestBaselineCommit(t *testing.T) {
	ctx := context.Background()
	base := strings.Repeat("a", 40)
	pr := ciinfo.Info{PullRequest: "7", TargetBranch: "main", Workspace: "/w"}
	none := func(string) string { return "" }

	if sha, note := baselineCommit(ctx, "auto", pr, none, fakeGit(map[string]string{"merge-base HEAD refs/remotes/origin/main": base})); sha != base || !strings.Contains(note, "diff-aware") {
		t.Fatalf("merge base: %q %q", sha, note)
	}
	// No history: a full scan that says how to fix it.
	if sha, note := baselineCommit(ctx, "auto", pr, none, fakeGit(nil)); sha != "" || !strings.Contains(note, "fetch-depth") {
		t.Fatalf("no history: %q %q", sha, note)
	}
	// GitLab gives the merge base; it must be in the clone.
	gl := func(k string) string {
		if k == "CI_MERGE_REQUEST_DIFF_BASE_SHA" {
			return base
		}
		return ""
	}
	if sha, _ := baselineCommit(ctx, "auto", pr, gl, fakeGit(map[string]string{"cat-file -e " + base + "^{commit}": ""})); sha != base {
		t.Fatalf("gitlab merge base: %q", sha)
	}
	if sha, _ := baselineCommit(ctx, "auto", pr, gl, fakeGit(nil)); sha != "" {
		t.Fatalf("gitlab merge base missing from the clone: %q", sha)
	}
	// Full scans: off, not a pull request, a fork, a hostile target branch.
	for name, c := range map[string]struct {
		mode string
		info ciinfo.Info
	}{
		"off":              {"off", pr},
		"push":             {"auto", ciinfo.Info{TargetBranch: "main"}},
		"fork":             {"auto", ciinfo.Info{PullRequest: "7", TargetBranch: "main", Fork: true}},
		"option injection": {"auto", ciinfo.Info{PullRequest: "7", TargetBranch: "--upload-pack=x"}},
		"range":            {"auto", ciinfo.Info{PullRequest: "7", TargetBranch: "main..evil"}},
	} {
		if sha, _ := baselineCommit(ctx, c.mode, c.info, none, fakeGit(map[string]string{"merge-base HEAD refs/remotes/origin/main": base})); sha != "" {
			t.Fatalf("%s: diff-aware with %q", name, sha)
		}
	}
	// A git answer that is not a commit id is not used.
	if sha, _ := baselineCommit(ctx, "auto", pr, none, fakeGit(map[string]string{"merge-base HEAD refs/remotes/origin/main": "--evil"})); sha != "" {
		t.Fatalf("non-commit answer used: %q", sha)
	}
}

// The diff git calls trust exactly the checkout: a checkout owned by another
// user (GitLab's docker executor clones as root) is otherwise refused as a
// dubious-ownership repository and the scan silently falls back to full.
func TestGitEnvTrustsTheCheckoutOnly(t *testing.T) {
	env := strings.Join(gitEnv("/builds/acme/api"), "\n")
	for _, want := range []string{"GIT_CONFIG_COUNT=1", "GIT_CONFIG_KEY_0=safe.directory", "GIT_CONFIG_VALUE_0=/builds/acme/api", "GIT_TERMINAL_PROMPT=0"} {
		if !strings.Contains(env, want) {
			t.Errorf("missing %s in\n%s", want, env)
		}
	}
	if strings.Contains(env, "=*") {
		t.Errorf("every directory trusted:\n%s", env)
	}
}

// End to end with a real repository owned by this user: the merge base is
// found through gitEnv (a smoke test that the environment does not break git).
func TestRunGitWithTrustedCheckout(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
	dir := t.TempDir()
	for _, args := range [][]string{{"init", "-q", "-b", "main"}, {"-c", "user.email=a@b.c", "-c", "user.name=t", "commit", "-q", "--allow-empty", "-m", "x"}} {
		c := exec.Command("git", append([]string{"-C", dir}, args...)...)
		c.Env = gitEnv(dir)
		if out, err := c.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v %s", args, err, out)
		}
	}
	if out, err := runGit(context.Background(), dir, "rev-parse", "HEAD"); err != nil || len(out) != 40 {
		t.Fatalf("rev-parse: %q %v", out, err)
	}
}
