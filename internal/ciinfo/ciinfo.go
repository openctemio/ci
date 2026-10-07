// Package ciinfo reads what a CI job is building from its environment:
// the provider, the workspace, the repository, the branch, the commit, the
// pull or merge request and whether the change comes from a fork.
//
// These values describe the job to the user (log lines, report metadata,
// the local gate). They are never trusted for identity: the platform takes
// the repository, branch and commit of a CI run from the verified OIDC
// token, not from what this package reads.
package ciinfo

import (
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// Provider names a CI system.
type Provider string

const (
	GitHub  Provider = "github"
	GitLab  Provider = "gitlab"
	Generic Provider = "generic"
)

// Info is the CI job as its environment describes it.
type Info struct {
	Provider Provider
	// Workspace is the directory the repository is checked out in.
	Workspace string
	// Repository is the canonical name: host/owner/name (github.com/o/r).
	Repository string
	Branch     string
	Commit     string
	// DefaultBranch of the repository, when the CI system says.
	DefaultBranch string
	// PullRequest is the pull or merge request number ("" outside one).
	PullRequest string
	// TargetBranch is the branch a pull or merge request merges into.
	TargetBranch string
	// Event is the trigger (GitHub event name, GitLab pipeline source).
	Event string
	// Fork is true when the change comes from another repository (a fork
	// pull or merge request): such a job must not push results or use
	// credentials.
	Fork bool
	// PullRequestTarget is true for a GitHub pull_request_target event,
	// which runs with the base repository's credentials.
	PullRequestTarget bool
}

// Detect reads the environment through getenv (os.Getenv when nil).
func Detect(getenv func(string) string) Info {
	if getenv == nil {
		getenv = os.Getenv
	}
	switch {
	case getenv("GITHUB_ACTIONS") == "true":
		return github(getenv)
	// A local GitLab runner (gitlab-ci-local) sets GITLAB_CI=false but the
	// same predefined variables: describe the job from them. Only the
	// platform client requires GITLAB_CI=true (an ID token).
	case getenv("GITLAB_CI") == "true" || (getenv("CI_PROJECT_PATH") != "" && getenv("CI_COMMIT_SHA") != ""):
		return gitlab(getenv)
	}
	return generic(getenv)
}

// InCI reports whether the process runs in a CI job.
func (i Info) InCI() bool { return i.Provider != Generic || i.Repository != "" }

func github(getenv func(string) string) Info {
	server := strings.TrimRight(nonEmpty(getenv("GITHUB_SERVER_URL"), "https://github.com"), "/")
	i := Info{
		Provider:   GitHub,
		Workspace:  getenv("GITHUB_WORKSPACE"),
		Repository: canonical(server, getenv("GITHUB_REPOSITORY")),
		Commit:     getenv("GITHUB_SHA"),
		Event:      getenv("GITHUB_EVENT_NAME"),
	}
	ref := getenv("GITHUB_REF")
	switch {
	case getenv("GITHUB_HEAD_REF") != "":
		i.Branch = getenv("GITHUB_HEAD_REF")
		i.TargetBranch = getenv("GITHUB_BASE_REF")
	case strings.HasPrefix(ref, "refs/heads/"):
		i.Branch = strings.TrimPrefix(ref, "refs/heads/")
	}
	ev := readGitHubEvent(getenv("GITHUB_EVENT_PATH"))
	i.DefaultBranch = ev.Repository.DefaultBranch
	if ev.PullRequest != nil {
		i.PullRequest = strconv.Itoa(ev.PullRequest.Number)
		// A pull request's commit is its head commit, not the merge commit
		// GitHub checks out by default.
		if ev.PullRequest.Head.SHA != "" {
			i.Commit = ev.PullRequest.Head.SHA
		}
		head := ev.PullRequest.Head.Repo.FullName
		i.Fork = ev.PullRequest.Head.Repo.Fork ||
			(head != "" && !strings.EqualFold(head, getenv("GITHUB_REPOSITORY")))
	}
	i.PullRequestTarget = i.Event == "pull_request_target"
	return i
}

// gitHubEvent is the part of the event payload this package reads.
type gitHubEvent struct {
	Repository struct {
		DefaultBranch string `json:"default_branch"`
	} `json:"repository"`
	PullRequest *struct {
		Number int `json:"number"`
		Head   struct {
			SHA  string `json:"sha"`
			Repo struct {
				FullName string `json:"full_name"`
				Fork     bool   `json:"fork"`
			} `json:"repo"`
		} `json:"head"`
	} `json:"pull_request"`
}

// maxEventSize bounds the event payload read.
const maxEventSize = 8 << 20

func readGitHubEvent(path string) gitHubEvent {
	var ev gitHubEvent
	if path == "" {
		return ev
	}
	f, err := os.Open(filepath.Clean(path))
	if err != nil {
		return ev
	}
	defer func() { _ = f.Close() }()
	_ = json.NewDecoder(io.LimitReader(f, maxEventSize)).Decode(&ev)
	return ev
}

func gitlab(getenv func(string) string) Info {
	server := strings.TrimRight(nonEmpty(getenv("CI_SERVER_URL"), "https://gitlab.com"), "/")
	i := Info{
		Provider:      GitLab,
		Workspace:     getenv("CI_PROJECT_DIR"),
		Repository:    canonical(server, getenv("CI_PROJECT_PATH")),
		Commit:        getenv("CI_COMMIT_SHA"),
		DefaultBranch: getenv("CI_DEFAULT_BRANCH"),
		Event:         getenv("CI_PIPELINE_SOURCE"),
	}
	i.Branch = nonEmpty(getenv("CI_COMMIT_BRANCH"), getenv("CI_MERGE_REQUEST_SOURCE_BRANCH_NAME"))
	if iid := getenv("CI_MERGE_REQUEST_IID"); iid != "" {
		i.PullRequest = iid
		i.TargetBranch = getenv("CI_MERGE_REQUEST_TARGET_BRANCH_NAME")
		src, dst := getenv("CI_MERGE_REQUEST_SOURCE_PROJECT_ID"), getenv("CI_MERGE_REQUEST_PROJECT_ID")
		i.Fork = src != "" && dst != "" && src != dst
	}
	return i
}

// generic reads the OPENCTEM_* variables a CI system without a built-in
// detector can set (see the examples directory).
func generic(getenv func(string) string) Info {
	return Info{
		Provider:      Generic,
		Workspace:     getenv("OPENCTEM_WORKSPACE"),
		Repository:    strings.TrimSuffix(strings.TrimSpace(getenv("OPENCTEM_REPOSITORY")), ".git"),
		Branch:        getenv("OPENCTEM_BRANCH"),
		Commit:        getenv("OPENCTEM_COMMIT"),
		DefaultBranch: getenv("OPENCTEM_DEFAULT_BRANCH"),
		PullRequest:   getenv("OPENCTEM_PULL_REQUEST"),
		TargetBranch:  getenv("OPENCTEM_TARGET_BRANCH"),
		Fork:          getenv("OPENCTEM_FORK") == "true",
	}
}

// canonical turns a server URL and an owner/name path into host/owner/name.
func canonical(serverURL, path string) string {
	path = strings.Trim(strings.TrimSpace(path), "/")
	if path == "" {
		return ""
	}
	host := serverURL
	if i := strings.Index(host, "://"); i >= 0 {
		host = host[i+3:]
	}
	host = strings.TrimRight(host, "/")
	return strings.ToLower(host) + "/" + path
}

func nonEmpty(s, fallback string) string {
	if strings.TrimSpace(s) == "" {
		return fallback
	}
	return s
}
