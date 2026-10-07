package ciinfo

import "testing"

func TestAzurePipelines(t *testing.T) {
	i := Detect(envOf(map[string]string{
		"TF_BUILD": "True", "BUILD_SOURCESDIRECTORY": "/a/s", "BUILD_REPOSITORY_URI": "https://acme@dev.azure.com/acme/Pay/_git/api",
		"BUILD_SOURCEVERSION": "abc", "BUILD_SOURCEBRANCH": "refs/heads/main", "BUILD_REASON": "IndividualCI",
	}))
	if i.Provider != AzureDevOps || i.Repository != "dev.azure.com/acme/Pay/api" || i.Branch != "main" || i.Commit != "abc" ||
		i.Workspace != "/a/s" || i.Fork {
		t.Fatalf("%+v", i)
	}
	pr := Detect(envOf(map[string]string{
		"TF_BUILD": "True", "BUILD_REPOSITORY_URI": "https://github.com/acme/api", "BUILD_SOURCEBRANCH": "refs/pull/9/merge",
		"SYSTEM_PULLREQUEST_PULLREQUESTNUMBER": "9", "SYSTEM_PULLREQUEST_SOURCEBRANCH": "feature/x",
		"SYSTEM_PULLREQUEST_TARGETBRANCH": "refs/heads/main", "SYSTEM_PULLREQUEST_ISFORK": "True", "OPENCTEM_WORKSPACE": "/src",
	}))
	if pr.PullRequest != "9" || pr.Branch != "feature/x" || pr.TargetBranch != "main" || !pr.Fork ||
		pr.Repository != "github.com/acme/api" || pr.Workspace != "/src" {
		t.Fatalf("%+v", pr)
	}
}

func TestBitbucketPipelines(t *testing.T) {
	i := Detect(envOf(map[string]string{
		"BITBUCKET_BUILD_NUMBER": "3", "BITBUCKET_CLONE_DIR": "/opt/atlassian/pipelines/agent/build",
		"BITBUCKET_REPO_FULL_NAME": "acme/api", "BITBUCKET_COMMIT": "abc", "BITBUCKET_BRANCH": "feature/x",
		"BITBUCKET_PR_ID": "4", "BITBUCKET_PR_DESTINATION_BRANCH": "main",
	}))
	if i.Provider != Bitbucket || i.Repository != "bitbucket.org/acme/api" || i.PullRequest != "4" || i.TargetBranch != "main" || i.Fork {
		t.Fatalf("%+v", i)
	}
}

func TestCircleCI(t *testing.T) {
	i := Detect(envOf(map[string]string{
		"CIRCLECI": "true", "CIRCLE_REPOSITORY_URL": "git@github.com:acme/api.git", "CIRCLE_SHA1": "abc",
		"CIRCLE_BRANCH": "feature/x", "CIRCLE_PULL_REQUEST": "https://github.com/acme/api/pull/12",
	}))
	if i.Provider != CircleCI || i.Repository != "github.com/acme/api" || i.PullRequest != "12" || i.Fork {
		t.Fatalf("%+v", i)
	}
	fork := Detect(envOf(map[string]string{"CIRCLECI": "true", "CIRCLE_PR_NUMBER": "13", "CIRCLE_PR_USERNAME": "mallory"}))
	if !fork.Fork || fork.PullRequest != "13" {
		t.Fatalf("%+v", fork)
	}
}

func TestJenkins(t *testing.T) {
	i := Detect(envOf(map[string]string{
		"JENKINS_URL": "https://ci.example/", "WORKSPACE": "/var/jenkins/ws", "GIT_URL": "https://github.com/acme/api.git",
		"GIT_COMMIT": "abc", "GIT_BRANCH": "origin/main",
	}))
	if i.Provider != Jenkins || i.Repository != "github.com/acme/api" || i.Branch != "main" || i.Workspace != "/var/jenkins/ws" {
		t.Fatalf("%+v", i)
	}
	pr := Detect(envOf(map[string]string{
		"JENKINS_URL": "https://ci.example/", "BRANCH_NAME": "PR-7", "CHANGE_ID": "7", "CHANGE_BRANCH": "feature/x",
		"CHANGE_TARGET": "main", "CHANGE_FORK": "mallory", "GIT_URL": "https://github.com/acme/api.git",
	}))
	if pr.PullRequest != "7" || pr.Branch != "feature/x" || pr.TargetBranch != "main" || !pr.Fork {
		t.Fatalf("%+v", pr)
	}
}

func TestRepositoryFromURL(t *testing.T) {
	for in, want := range map[string]string{
		"https://github.com/acme/api.git":            "github.com/acme/api",
		"git@bitbucket.org:acme/api.git":             "bitbucket.org/acme/api",
		"https://acme.visualstudio.com/Pay/_git/api": "dev.azure.com/acme/Pay/api",
		"git@ssh.dev.azure.com:v3/acme/Pay/api":      "dev.azure.com/acme/Pay/api",
		"https://github.com/acme":                    "",
		"":                                           "",
	} {
		if got := repositoryFromURL(in); got != want {
			t.Errorf("%q = %q, want %q", in, got, want)
		}
	}
}
