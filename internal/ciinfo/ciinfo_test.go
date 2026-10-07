package ciinfo

import (
	"os"
	"path/filepath"
	"testing"
)

func envOf(m map[string]string) func(string) string {
	return func(k string) string { return m[k] }
}

func writeEvent(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "event.json")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestGitHubPush(t *testing.T) {
	i := Detect(envOf(map[string]string{
		"GITHUB_ACTIONS": "true", "GITHUB_REPOSITORY": "Acme/App", "GITHUB_SHA": "abc",
		"GITHUB_REF": "refs/heads/main", "GITHUB_EVENT_NAME": "push", "GITHUB_WORKSPACE": "/w",
		"GITHUB_EVENT_PATH": writeEvent(t, `{"repository":{"default_branch":"main"}}`),
	}))
	if i.Provider != GitHub || i.Repository != "github.com/Acme/App" || i.Branch != "main" || i.Commit != "abc" ||
		i.DefaultBranch != "main" || i.Fork || i.PullRequest != "" || i.Workspace != "/w" {
		t.Fatalf("%+v", i)
	}
}

func TestGitHubForkPullRequest(t *testing.T) {
	ev := `{"pull_request":{"number":7,"head":{"sha":"headsha","repo":{"full_name":"mallory/app","fork":true}}},"repository":{"default_branch":"main"}}`
	i := Detect(envOf(map[string]string{
		"GITHUB_ACTIONS": "true", "GITHUB_REPOSITORY": "acme/app", "GITHUB_SHA": "mergesha",
		"GITHUB_HEAD_REF": "feature", "GITHUB_BASE_REF": "main", "GITHUB_EVENT_NAME": "pull_request",
		"GITHUB_EVENT_PATH": writeEvent(t, ev),
	}))
	if !i.Fork || i.PullRequest != "7" || i.Commit != "headsha" || i.Branch != "feature" || i.TargetBranch != "main" {
		t.Fatalf("%+v", i)
	}
}

// A pull request from another repository is a fork even if the payload
// does not say fork (a renamed or transferred head repository).
func TestGitHubPullRequestFromOtherRepositoryIsFork(t *testing.T) {
	ev := `{"pull_request":{"number":8,"head":{"sha":"s","repo":{"full_name":"other/app","fork":false}}}}`
	i := Detect(envOf(map[string]string{"GITHUB_ACTIONS": "true", "GITHUB_REPOSITORY": "acme/app",
		"GITHUB_EVENT_NAME": "pull_request_target", "GITHUB_EVENT_PATH": writeEvent(t, ev)}))
	if !i.Fork || !i.PullRequestTarget {
		t.Fatalf("%+v", i)
	}
}

func TestGitHubSameRepositoryPullRequest(t *testing.T) {
	ev := `{"pull_request":{"number":9,"head":{"sha":"s","repo":{"full_name":"acme/app","fork":false}}}}`
	i := Detect(envOf(map[string]string{"GITHUB_ACTIONS": "true", "GITHUB_REPOSITORY": "acme/app",
		"GITHUB_EVENT_NAME": "pull_request", "GITHUB_EVENT_PATH": writeEvent(t, ev)}))
	if i.Fork {
		t.Fatalf("%+v", i)
	}
}

func TestGitLabMergeRequest(t *testing.T) {
	base := map[string]string{
		"GITLAB_CI": "true", "CI_SERVER_URL": "https://gitlab.example.com", "CI_PROJECT_PATH": "grp/sub/app",
		"CI_COMMIT_SHA": "abc", "CI_DEFAULT_BRANCH": "main", "CI_PROJECT_DIR": "/builds/grp/sub/app",
		"CI_MERGE_REQUEST_IID": "12", "CI_MERGE_REQUEST_SOURCE_BRANCH_NAME": "feat",
		"CI_MERGE_REQUEST_TARGET_BRANCH_NAME": "main",
		"CI_MERGE_REQUEST_SOURCE_PROJECT_ID":  "5", "CI_MERGE_REQUEST_PROJECT_ID": "5",
	}
	i := Detect(envOf(base))
	if i.Provider != GitLab || i.Repository != "gitlab.example.com/grp/sub/app" || i.Branch != "feat" ||
		i.PullRequest != "12" || i.TargetBranch != "main" || i.Fork {
		t.Fatalf("%+v", i)
	}
	base["CI_MERGE_REQUEST_SOURCE_PROJECT_ID"] = "99"
	if !Detect(envOf(base)).Fork {
		t.Fatal("a merge request from another project is a fork")
	}
}

func TestGeneric(t *testing.T) {
	i := Detect(envOf(map[string]string{"OPENCTEM_REPOSITORY": "bitbucket.org/acme/app.git", "OPENCTEM_COMMIT": "c",
		"OPENCTEM_BRANCH": "main", "OPENCTEM_FORK": "true"}))
	if i.Provider != Generic || i.Repository != "bitbucket.org/acme/app" || !i.Fork || !i.InCI() {
		t.Fatalf("%+v", i)
	}
	if Detect(envOf(nil)).InCI() {
		t.Fatal("an empty environment is not CI")
	}
}

// A local GitLab runner (GITLAB_CI=false) is still described from the
// GitLab variables.
func TestGitLabLocalRunner(t *testing.T) {
	i := Detect(envOf(map[string]string{"GITLAB_CI": "false", "CI_PROJECT_PATH": "g/p", "CI_COMMIT_SHA": "abc",
		"CI_COMMIT_BRANCH": "main"}))
	if i.Provider != GitLab || i.Repository != "gitlab.com/g/p" || i.Commit != "abc" {
		t.Fatalf("%+v", i)
	}
}
