//go:build unix

package platform

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/openctemio/ctis"
)

// gitlabJob is one GitLab job's environment against a fake platform.
type gitlabJob struct {
	t   *testing.T
	f   *fakePlatform
	env map[string]string
}

func newGitLabJob(t *testing.T, f *fakePlatform) *gitlabJob {
	t.Helper()
	srv := httptest.NewServer(f.handler(t))
	t.Cleanup(srv.Close)
	return &gitlabJob{t: t, f: f, env: map[string]string{"GITLAB_CI": "true", DefaultIDTokenVar: "gl-jwt-job-77",
		EnvTenantID: "t1", EnvAPIURL: srv.URL, "CI_JOB_ID": "77", "TMPDIR": t.TempDir(), "CI_PROJECT_DIR": t.TempDir()}}
}

// step is one openctem-ci process of the job.
func (j *gitlabJob) step() *Run {
	j.t.Helper()
	cfg := ConfigFromEnv(func(k string) string { return j.env[k] })
	cfg.Aggregate = true
	r, err := New(cfg)
	if err != nil {
		j.t.Fatal(err)
	}
	return r
}

func (j *gitlabJob) cacheFiles() []string {
	j.t.Helper()
	m, _ := filepath.Glob(filepath.Join(j.env["TMPDIR"], "openctem-ci-*", "*.json"))
	return m
}

// Several openctem-ci steps of one job: one exchange, one run, one token.
func TestJobStepsShareOneExchange(t *testing.T) {
	f := &fakePlatform{}
	j := newGitLabJob(t, f)
	ctx := context.Background()
	for i := 0; i < 3; i++ {
		if _, err := j.step().Upload(ctx, &ctis.Report{}); err != nil {
			t.Fatalf("step %d: %v", i, err)
		}
	}
	if n := countPath(f, "/exchange"); n != 1 {
		t.Fatalf("%d exchanges for 3 steps of one job, want 1", n)
	}
	for i, a := range f.auth {
		if strings.HasSuffix(f.paths[i], "/results") && a != "Bearer "+runToken {
			t.Fatalf("upload %d used %q", i, a)
		}
	}
	files := j.cacheFiles()
	if len(files) != 1 {
		t.Fatalf("cache files: %v", files)
	}
	fi, _ := os.Stat(files[0])
	di, _ := os.Stat(filepath.Dir(files[0]))
	if fi.Mode().Perm() != 0o600 || di.Mode().Perm() != 0o700 {
		t.Fatalf("modes file %v dir %v", fi.Mode(), di.Mode())
	}
	b, _ := os.ReadFile(files[0])
	if strings.Contains(string(b), "gl-jwt") {
		t.Fatal("the OIDC token was written to the cache")
	}
	// The verdict closes the run: the file goes.
	if _, err := j.step().Evaluate(ctx, 0); err != nil {
		t.Fatal(err)
	}
	if n := countPath(f, "/exchange"); n != 1 {
		t.Fatalf("the gate step exchanged again: %d", n)
	}
	if files := j.cacheFiles(); len(files) != 0 {
		t.Fatalf("cache kept after the verdict: %v", files)
	}
}

// Another job, or another token, never reads this job's run token.
func TestCacheIsPerJobAndToken(t *testing.T) {
	f := &fakePlatform{}
	j := newGitLabJob(t, f)
	ctx := context.Background()
	if _, err := j.step().Upload(ctx, &ctis.Report{}); err != nil {
		t.Fatal(err)
	}
	j.env["CI_JOB_ID"] = "78"
	j.env[DefaultIDTokenVar] = "gl-jwt-job-78"
	if _, err := j.step().Upload(ctx, &ctis.Report{}); err != nil {
		t.Fatal(err)
	}
	j.env["CI_JOB_ID"] = "77" // same job id, another token (a retried job)
	if _, err := j.step().Upload(ctx, &ctis.Report{}); err != nil {
		t.Fatal(err)
	}
	if n := countPath(f, "/exchange"); n != 3 {
		t.Fatalf("%d exchanges, want 3", n)
	}
}

// A file or directory that is not private to this user is never read.
func TestCacheRefusesLooseFiles(t *testing.T) {
	f := &fakePlatform{}
	j := newGitLabJob(t, f)
	ctx := context.Background()
	if _, err := j.step().Upload(ctx, &ctis.Report{}); err != nil {
		t.Fatal(err)
	}
	file := j.cacheFiles()[0]
	if err := os.Chmod(file, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := j.step().Upload(ctx, &ctis.Report{}); err != nil {
		t.Fatal(err)
	}
	if n := countPath(f, "/exchange"); n != 2 {
		t.Fatalf("a 0644 cache file was used: %d exchanges", n)
	}
	// A directory that is a symlink is not used at all.
	f2 := &fakePlatform{}
	j2 := newGitLabJob(t, f2)
	elsewhere := t.TempDir()
	if err := os.Symlink(elsewhere, filepath.Join(j2.env["TMPDIR"], cacheDirName())); err != nil {
		t.Fatal(err)
	}
	if _, err := j2.step().Upload(ctx, &ctis.Report{}); err != nil {
		t.Fatal(err)
	}
	if m, _ := filepath.Glob(filepath.Join(elsewhere, "*")); len(m) != 0 {
		t.Fatalf("wrote through a symlinked directory: %v", m)
	}
}

// A temp dir inside the workspace (uploaded as artifacts) gets no cache;
// OPENCTEM_TOKEN_CACHE=off neither.
func TestCacheNeverInWorkspace(t *testing.T) {
	ctx := context.Background()
	for name, set := range map[string]func(env map[string]string){
		"workspace": func(env map[string]string) { env["TMPDIR"] = filepath.Join(env["CI_PROJECT_DIR"], "tmp") },
		"off":       func(env map[string]string) { env[EnvTokenCache] = "off" },
	} {
		t.Run(name, func(t *testing.T) {
			f := &fakePlatform{}
			j := newGitLabJob(t, f)
			set(j.env)
			_ = os.MkdirAll(j.env["TMPDIR"], 0o700)
			for i := 0; i < 2; i++ {
				if _, err := j.step().Upload(ctx, &ctis.Report{}); err != nil {
					t.Fatal(err)
				}
			}
			if n := countPath(f, "/exchange"); n != 2 {
				t.Fatalf("%d exchanges, want 2 (no cache)", n)
			}
			m, _ := filepath.Glob(filepath.Join(j.env["TMPDIR"], "openctem-ci-*"))
			if len(m) != 0 {
				t.Fatalf("cache written: %v", m)
			}
		})
	}
}

// A cached token the platform no longer takes: the step exchanges its own.
func TestCachedTokenRefusedFallsBack(t *testing.T) {
	f := &fakePlatform{}
	j := newGitLabJob(t, f)
	ctx := context.Background()
	if _, err := j.step().Upload(ctx, &ctis.Report{}); err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	f.token = "octci_SECOND"
	f.mu.Unlock()
	srvRefusing := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/results") && r.Header.Get("Authorization") == "Bearer "+runToken {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"code":"UNAUTHORIZED","message":"Invalid or expired CI run token"}`))
			return
		}
		f.handler(t).ServeHTTP(w, r)
	}))
	defer srvRefusing.Close()
	// The API URL is part of the cache key: point the job at the refusing
	// server and seed its cache with the token the first step stored.
	j.env[EnvAPIURL] = srvRefusing.URL
	r := j.step()
	old := j.cacheFiles()[0]
	r.mu.Lock()
	newPath := r.cachePath()
	r.mu.Unlock()
	b, _ := os.ReadFile(old)
	if err := os.WriteFile(newPath, b, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Upload(ctx, &ctis.Report{}); err != nil {
		t.Fatalf("upload after a refused cached token: %v", err)
	}
	if n := countPath(f, "/exchange"); n != 2 {
		t.Fatalf("%d exchanges, want 2", n)
	}
}
