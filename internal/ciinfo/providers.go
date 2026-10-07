package ciinfo

import (
	"net/url"
	"strings"
)

// CI systems detected from their own variables. As for GitHub and GitLab,
// what is read here describes the job; the platform takes the identity of
// a run from the verified OIDC token.
const (
	AzureDevOps Provider = "azure_devops"
	Bitbucket   Provider = "bitbucket"
	CircleCI    Provider = "circleci"
	Jenkins     Provider = "jenkins"
)

// detectOther recognizes Azure Pipelines, Bitbucket Pipelines, CircleCI and
// Jenkins. ok is false for any other environment.
func detectOther(getenv func(string) string) (Info, bool) {
	switch {
	case strings.EqualFold(getenv("TF_BUILD"), "true"):
		return azure(getenv), true
	case getenv("BITBUCKET_BUILD_NUMBER") != "":
		return bitbucket(getenv), true
	case getenv("CIRCLECI") == "true":
		return circleci(getenv), true
	case getenv("JENKINS_URL") != "":
		return jenkins(getenv), true
	}
	return Info{}, false
}

func azure(getenv func(string) string) Info {
	i := Info{
		Provider:   AzureDevOps,
		Workspace:  nonEmpty(getenv("OPENCTEM_WORKSPACE"), getenv("BUILD_SOURCESDIRECTORY")),
		Repository: repositoryFromURL(getenv("BUILD_REPOSITORY_URI")),
		Commit:     getenv("BUILD_SOURCEVERSION"),
		Event:      getenv("BUILD_REASON"),
	}
	i.Branch = strings.TrimPrefix(getenv("BUILD_SOURCEBRANCH"), "refs/heads/")
	if pr := nonEmpty(getenv("SYSTEM_PULLREQUEST_PULLREQUESTNUMBER"), getenv("SYSTEM_PULLREQUEST_PULLREQUESTID")); pr != "" {
		i.PullRequest = pr
		i.Branch = strings.TrimPrefix(getenv("SYSTEM_PULLREQUEST_SOURCEBRANCH"), "refs/heads/")
		i.TargetBranch = strings.TrimPrefix(getenv("SYSTEM_PULLREQUEST_TARGETBRANCH"), "refs/heads/")
		i.Fork = strings.EqualFold(getenv("SYSTEM_PULLREQUEST_ISFORK"), "true")
	}
	if strings.HasPrefix(i.Branch, "refs/") {
		i.Branch = ""
	}
	return i
}

func bitbucket(getenv func(string) string) Info {
	i := Info{
		Provider:     Bitbucket,
		Workspace:    nonEmpty(getenv("OPENCTEM_WORKSPACE"), getenv("BITBUCKET_CLONE_DIR")),
		Repository:   canonical("https://bitbucket.org", getenv("BITBUCKET_REPO_FULL_NAME")),
		Commit:       getenv("BITBUCKET_COMMIT"),
		Branch:       getenv("BITBUCKET_BRANCH"),
		PullRequest:  getenv("BITBUCKET_PR_ID"),
		TargetBranch: getenv("BITBUCKET_PR_DESTINATION_BRANCH"),
	}
	// A fork's pipelines run in the fork's own repository, under its own
	// identity: nothing here is a fork of the repository it reports on.
	return i
}

func circleci(getenv func(string) string) Info {
	i := Info{
		Provider:   CircleCI,
		Workspace:  getenv("OPENCTEM_WORKSPACE"),
		Repository: repositoryFromURL(getenv("CIRCLE_REPOSITORY_URL")),
		Commit:     getenv("CIRCLE_SHA1"),
		Branch:     getenv("CIRCLE_BRANCH"),
	}
	if pr := getenv("CIRCLE_PULL_REQUEST"); pr != "" {
		i.PullRequest = pr[strings.LastIndex(pr, "/")+1:]
	}
	// CircleCI sets CIRCLE_PR_NUMBER only for a pull request from a fork.
	if n := getenv("CIRCLE_PR_NUMBER"); n != "" {
		i.Fork, i.PullRequest = true, n
	}
	return i
}

func jenkins(getenv func(string) string) Info {
	i := Info{
		Provider:     Jenkins,
		Workspace:    nonEmpty(getenv("OPENCTEM_WORKSPACE"), getenv("WORKSPACE")),
		Repository:   repositoryFromURL(nonEmpty(getenv("GIT_URL"), getenv("CHANGE_URL"))),
		Commit:       getenv("GIT_COMMIT"),
		Branch:       strings.TrimPrefix(nonEmpty(getenv("BRANCH_NAME"), getenv("GIT_BRANCH")), "origin/"),
		PullRequest:  getenv("CHANGE_ID"),
		TargetBranch: getenv("CHANGE_TARGET"),
		// Set by the branch source for a change request from a fork.
		Fork: getenv("CHANGE_FORK") != "",
	}
	if i.PullRequest != "" {
		i.Branch = nonEmpty(getenv("CHANGE_BRANCH"), i.Branch)
	}
	return i
}

// repositoryFromURL turns a clone URL ("https://github.com/acme/api.git",
// "git@github.com:acme/api.git", an Azure Repos URL) into host/owner/name.
func repositoryFromURL(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	if !strings.Contains(raw, "://") {
		if at := strings.Index(raw, "@"); at >= 0 {
			if c := strings.Index(raw[at:], ":"); c > 0 {
				raw = "ssh://" + raw[:at+c] + "/" + raw[at+c+1:]
			}
		} else {
			raw = "https://" + raw
		}
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return ""
	}
	host := strings.ToLower(u.Hostname())
	p := strings.Trim(strings.TrimSuffix(strings.Trim(u.Path, "/"), ".git"), "/")
	switch {
	case host == "ssh.dev.azure.com":
		host, p = "dev.azure.com", strings.TrimPrefix(p, "v3/")
	case host == "dev.azure.com":
		p = strings.Replace(p, "/_git/", "/", 1)
	case strings.HasSuffix(host, ".visualstudio.com"):
		host, p = "dev.azure.com", strings.TrimSuffix(host, ".visualstudio.com")+"/"+strings.Replace(p, "/_git/", "/", 1)
	}
	if p == "" || !strings.Contains(p, "/") {
		return ""
	}
	return host + "/" + p
}
