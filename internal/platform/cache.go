package platform

// The job's run token cache: one OIDC exchange per CI job, reused by every
// openctem-ci step of that job.
//
// A job may run openctem-ci several times (a scan per capability, then the
// gate). GitLab, Bitbucket, CircleCI and Jenkins give the job one OIDC token;
// GitHub and Azure mint one per request, and each exchange of a fresh one
// would open another run. So the first step stores the run token it got and
// later steps of the same job reuse it until it nearly expires.
//
// Where: <job temp dir>/openctem-ci-<uid>/<name>.json, the job temp dir being
// RUNNER_TEMP (GitHub), AGENT_TEMPDIRECTORY (Azure) or TMPDIR (else /tmp),
// never inside the job's workspace (which is uploaded as artifacts or
// cached). The directory is 0700 and the file 0600, both owned by the
// current user; anything else (a symlink, another owner, wider modes) is not
// read and not written. The name is a hash of the API URL, tenant, provider,
// aggregate mode, the job's id and, for a provider whose job holds one OIDC
// token, that token's digest: another job, or another token, never matches.
//
// The file holds the run id, the run token, its expiry, what the platform
// said about the run and the secret hashing key; never the OIDC token. It is
// removed when the run gets its verdict, when the platform no longer takes
// the token, and when it is found expired; the runner's temp dir goes with
// the job. OPENCTEM_TOKEN_CACHE=off turns it off.

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// EnvTokenCache set to "off" disables the job's run token cache.
const EnvTokenCache = "OPENCTEM_TOKEN_CACHE" //nolint:gosec // G101: a variable name, not a credential

// cacheMargin: a cached run token with less life left is not reused.
const cacheMargin = 30 * time.Second

const maxCacheFile = 64 << 10

type cachedRun struct {
	RunID     string    `json:"run_id"`
	Token     string    `json:"token"`
	ExpiresAt time.Time `json:"expires_at"`
	Info      Info      `json:"info"`
	SecretKey []byte    `json:"secret_key,omitempty"`
}

// jobID is the CI job's identity, "" when the job names none.
func (r *Run) jobID() string {
	g := r.cfg.Getenv
	var parts []string
	switch r.provider {
	case ProviderGitHub:
		parts = []string{g("GITHUB_RUN_ID"), g("GITHUB_RUN_ATTEMPT"), g("GITHUB_JOB")}
	case ProviderGitLab:
		parts = []string{g("CI_JOB_ID")}
	case ProviderAzureDevOps:
		parts = []string{g("BUILD_BUILDID"), g("SYSTEM_JOBID")}
	case ProviderBitbucket:
		parts = []string{g("BITBUCKET_STEP_UUID")}
	case ProviderCircleCI:
		parts = []string{g("CIRCLE_WORKFLOW_JOB_ID")}
	case ProviderJenkins:
		parts = []string{g("BUILD_TAG")}
	}
	for _, p := range parts {
		if strings.TrimSpace(p) == "" {
			return ""
		}
	}
	return strings.Join(parts, "\x00")
}

// singleToken is the job's one OIDC token, without asking the provider ("" for
// a provider that mints one per request).
func (r *Run) singleToken() string {
	switch r.provider {
	case ProviderBitbucket:
		return r.cfg.Getenv("BITBUCKET_STEP_OIDC_TOKEN")
	case ProviderGitLab, ProviderCircleCI, ProviderJenkins:
		return r.cfg.Getenv(r.cfg.IDTokenVar)
	}
	return ""
}

// cachePath is the job's cache file, "" when there is none to use.
func (r *Run) cachePath() string {
	g := r.cfg.Getenv
	if strings.EqualFold(strings.TrimSpace(g(EnvTokenCache)), "off") {
		return ""
	}
	job := r.jobID()
	if job == "" {
		return ""
	}
	dir := ""
	switch r.provider {
	case ProviderGitHub:
		dir = g("RUNNER_TEMP")
	case ProviderAzureDevOps:
		dir = g("AGENT_TEMPDIRECTORY")
	}
	if dir == "" {
		dir = g("TMPDIR")
	}
	if dir == "" {
		dir = "/tmp"
	}
	dir, err := filepath.Abs(dir)
	if err != nil || insideWorkspace(dir, g) {
		return ""
	}
	h := sha256.New()
	for _, p := range []string{r.cfg.APIURL, r.cfg.TenantID, r.provider, boolString(r.cfg.Aggregate), job} {
		h.Write([]byte(p))
		h.Write([]byte{0})
	}
	if t := r.singleToken(); t != "" {
		sum := sha256.Sum256([]byte(t))
		h.Write(sum[:])
	}
	return filepath.Join(dir, cacheDirName(), hex.EncodeToString(h.Sum(nil))[:32]+".json")
}

// insideWorkspace: dir is the job's workspace or under it.
func insideWorkspace(dir string, g func(string) string) bool {
	for _, v := range []string{"CI_PROJECT_DIR", "CI_BUILDS_DIR", "GITHUB_WORKSPACE", "BUILD_SOURCESDIRECTORY",
		"BITBUCKET_CLONE_DIR", "CIRCLE_WORKING_DIRECTORY", "WORKSPACE"} {
		ws := strings.TrimSpace(g(v))
		if ws == "" {
			continue
		}
		ws, err := filepath.Abs(ws)
		if err != nil {
			continue
		}
		if rel, err := filepath.Rel(ws, dir); err == nil && (rel == "." || !strings.HasPrefix(rel, "..")) {
			return true
		}
	}
	return false
}

func boolString(b bool) string {
	if b {
		return "1"
	}
	return "0"
}

// loadCache adopts the run token an earlier step of the job stored. r.mu is
// held.
func (r *Run) loadCache() {
	path := r.cachePath()
	if path == "" || !privateDir(filepath.Dir(path), false) || !privateFile(path) {
		return
	}
	f, err := os.Open(path) // #nosec G304 -- our own 0600 file in our own 0700 dir, checked above
	if err != nil {
		return
	}
	b, err := io.ReadAll(io.LimitReader(f, maxCacheFile+1))
	_ = f.Close()
	var c cachedRun
	if err != nil || len(b) > maxCacheFile || json.Unmarshal(b, &c) != nil ||
		!strings.HasPrefix(c.Token, tokenPrefix) || c.RunID == "" {
		_ = os.Remove(path)
		return
	}
	if time.Until(c.ExpiresAt) <= cacheMargin {
		_ = os.Remove(path)
		return
	}
	r.token, r.expiresAt, r.runID, r.info, r.fromCache = c.Token, c.ExpiresAt, c.RunID, c.Info, true
	if len(c.SecretKey) >= 32 {
		r.secretKey = c.SecretKey
	}
}

// saveCache stores the run token for the job's later steps. r.mu is held. A
// failure only means the next step exchanges again.
func (r *Run) saveCache() {
	path := r.cachePath()
	if path == "" || !privateDir(filepath.Dir(path), true) {
		return
	}
	b, err := json.Marshal(cachedRun{RunID: r.runID, Token: r.token, ExpiresAt: r.expiresAt, Info: r.info, SecretKey: r.secretKey})
	if err != nil {
		return
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".tok-*") // created 0600
	if err != nil {
		return
	}
	name := tmp.Name()
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		_ = os.Remove(name)
		return
	}
	_, werr := tmp.Write(b)
	cerr := tmp.Close()
	if werr != nil || cerr != nil || os.Rename(name, path) != nil {
		_ = os.Remove(name)
	}
}

// dropCache removes the job's cache file. r.mu is held.
func (r *Run) dropCache() {
	if path := r.cachePath(); path != "" && privateDir(filepath.Dir(path), false) {
		_ = os.Remove(path)
	}
}

// privateDir: dir is a real directory (no symlink), mode 0700, owned by the
// current user; with create, it is made when missing.
func privateDir(dir string, create bool) bool {
	if create {
		if err := os.Mkdir(dir, 0o700); err != nil && !errors.Is(err, os.ErrExist) {
			return false
		}
	}
	fi, err := os.Lstat(dir)
	if err != nil || !fi.IsDir() || fi.Mode()&os.ModeSymlink != 0 || fi.Mode().Perm() != 0o700 {
		return false
	}
	return ownedByMe(fi)
}

// privateFile: path is a regular file (no symlink), mode 0600, owned by the
// current user.
func privateFile(path string) bool {
	fi, err := os.Lstat(path)
	if err != nil || !fi.Mode().IsRegular() || fi.Mode().Perm() != 0o600 {
		return false
	}
	return ownedByMe(fi)
}
