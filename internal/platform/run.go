// Package platform talks to the OpenCTEM CI run API with the CI job's own
// identity: the job's OIDC token (GitHub Actions, GitLab CI, Azure
// Pipelines, Bitbucket Pipelines, CircleCI, Jenkins with its OpenID Connect
// provider plugin) is exchanged for a short-lived run token bound to one run
// on one repository. No API key is stored in CI.
//
// The run token never leaves this package: it is not printed, not logged
// and not part of any error. The platform derives the tenant's repository,
// branch and commit of the run from the verified OIDC token; nothing this
// client sends can move a run to another repository.
//
// Design: docs/architecture.md (CI identity and the aggregate run).
package platform

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/openctemio/ctis"
)

// Environment variables.
const (
	// EnvAPIURL is the platform URL.
	EnvAPIURL = "OPENCTEM_API_URL"
	// EnvTenantID turns OIDC on: the organization whose CI trust admits the job.
	EnvTenantID = "OPENCTEM_TENANT_ID"
	// EnvAudience overrides the audience (default openctem:tenant:<id>).
	EnvAudience = "OPENCTEM_OIDC_AUDIENCE"
	// EnvIDTokenVar names the variable that holds the job's token on GitLab
	// (its id_tokens variable), CircleCI (minted with circleci run oidc get)
	// and Jenkins (bound from the plugin's credential); default
	// OPENCTEM_ID_TOKEN.
	EnvIDTokenVar = "OPENCTEM_ID_TOKEN_VAR" // #nosec G101 -- a variable name, not a credential
	// DefaultIDTokenVar is the GitLab id_tokens variable read by default.
	DefaultIDTokenVar = "OPENCTEM_ID_TOKEN" // #nosec G101 -- a variable name, not a credential
)

// Providers an OIDC token can come from.
const (
	ProviderGitHub      = "github"
	ProviderGitLab      = "gitlab"
	ProviderAzureDevOps = "azure_devops"
	ProviderBitbucket   = "bitbucket"
	ProviderCircleCI    = "circleci"
	ProviderJenkins     = "jenkins"
)

// azureOIDCAPIVersion is the Azure DevOps OIDC token API version.
const azureOIDCAPIVersion = "7.1-preview.1"

// canMint reports whether the client can ask the provider for a fresh token
// (and so renew an expiring run token); elsewhere the job holds one token,
// good for one exchange.
func canMint(provider string) bool {
	return provider == ProviderGitHub || provider == ProviderAzureDevOps
}

// ErrNoOIDC: the job offers no OIDC token (no tenant set, GitHub Actions
// without id-token: write, no GitLab id_tokens variable, another CI system).
var ErrNoOIDC = errors.New("no CI OIDC token available")

// ErrRefused: the platform did not accept the job's OIDC token.
var ErrRefused = errors.New("the platform did not accept the CI token")

// ErrNoAggregate: the platform did not open an aggregate run when asked.
var ErrNoAggregate = errors.New("the platform does not support aggregate CI runs; update it, or run one job per capability without --aggregate")

// tokenPrefix is the prefix of every run token the platform issues.
const tokenPrefix = "octci_"

// renewBefore re-exchanges (GitHub and Azure, which mint a token on request)
// when the run token expires sooner.
const renewBefore = 2 * time.Minute

// Response bounds.
const (
	maxErrBody = 4 << 10
	// defaultRetries repeats a request after a transient failure.
	defaultRetries = 3
	// gzipFrom: a request body at least this large is sent gzip-compressed.
	gzipFrom     = 4 << 10
	maxBody      = 8 << 20
	maxTokenBody = 64 << 10
)

// Config configures a run.
type Config struct {
	APIURL   string
	TenantID string
	// Audience defaults to openctem:tenant:<TenantID>.
	Audience string
	// IDTokenVar is the GitLab id_tokens variable (OPENCTEM_ID_TOKEN).
	IDTokenVar string
	// Aggregate joins the run every job of the same CI pipeline run shares
	// (same pipeline, commit and attempt) instead of opening one run per
	// job: several capability jobs then report into one run and one final
	// job asks for the verdict on all of them.
	Aggregate bool
	// UserAgent is sent with every request (openctem-ci/<version>).
	UserAgent string
	// HTTPClient makes every request (default: no redirects; each request
	// is bounded by RequestTimeout, an upload by UploadTimeout).
	HTTPClient *http.Client
	// RequestTimeout bounds the token exchange and the verdict request
	// (default 30s); UploadTimeout bounds one results upload (default 5m).
	RequestTimeout time.Duration
	UploadTimeout  time.Duration
	// Retries is how often a request is repeated after a transient failure
	// (default 3; negative: never). See retryable for what is transient.
	Retries int
	// Getenv reads the environment.
	Getenv func(string) string
}

// ConfigFromEnv fills a configuration from the environment.
func ConfigFromEnv(getenv func(string) string) Config {
	c := Config{APIURL: getenv(EnvAPIURL), TenantID: getenv(EnvTenantID),
		Audience: getenv(EnvAudience), IDTokenVar: getenv(EnvIDTokenVar), Getenv: getenv}
	// OPENCTEM_RETRIES: 0 to 10 repeats after a transient failure.
	if n, err := strconv.Atoi(strings.TrimSpace(getenv(EnvRetries))); err == nil && n >= 0 && n <= 10 {
		c.Retries = n
		if n == 0 {
			c.Retries = -1
		}
	}
	// OPENCTEM_UPLOAD_TIMEOUT: a Go duration, 10s to 1h.
	if d, err := time.ParseDuration(strings.TrimSpace(getenv(EnvUploadTimeout))); err == nil && d >= 10*time.Second && d <= time.Hour {
		c.UploadTimeout = d
	}
	return c
}

// Tuning variables.
const (
	EnvRetries       = "OPENCTEM_RETRIES"
	EnvUploadTimeout = "OPENCTEM_UPLOAD_TIMEOUT"
)

func (c *Config) normalize() {
	c.APIURL = strings.TrimRight(strings.TrimSpace(c.APIURL), "/")
	c.TenantID = strings.TrimSpace(c.TenantID)
	if c.Audience == "" && c.TenantID != "" {
		c.Audience = "openctem:tenant:" + c.TenantID
	}
	if c.IDTokenVar == "" {
		c.IDTokenVar = DefaultIDTokenVar
	}
	if c.RequestTimeout <= 0 {
		c.RequestTimeout = 30 * time.Second
	}
	if c.UploadTimeout <= 0 {
		c.UploadTimeout = 5 * time.Minute
	}
	switch {
	case c.Retries == 0:
		c.Retries = defaultRetries
	case c.Retries < 0:
		c.Retries = 0
	}
	if c.HTTPClient == nil {
		c.HTTPClient = &http.Client{
			// A redirect could carry the bearer to another host: refuse it.
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		}
	}
}

// DetectOIDC reports which CI provider can give this job an OIDC token.
func DetectOIDC(cfg Config) (string, bool) {
	cfg.normalize()
	if cfg.TenantID == "" || cfg.Getenv == nil {
		return "", false
	}
	if cfg.Getenv("GITHUB_ACTIONS") == "true" && cfg.Getenv("ACTIONS_ID_TOKEN_REQUEST_URL") != "" &&
		cfg.Getenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN") != "" {
		return ProviderGitHub, true
	}
	if cfg.Getenv("GITLAB_CI") == "true" && cfg.Getenv(cfg.IDTokenVar) != "" {
		return ProviderGitLab, true
	}
	if strings.EqualFold(cfg.Getenv("TF_BUILD"), "true") && cfg.Getenv("SYSTEM_OIDCREQUESTURI") != "" &&
		cfg.Getenv("SYSTEM_ACCESSTOKEN") != "" {
		return ProviderAzureDevOps, true
	}
	if cfg.Getenv("BITBUCKET_BUILD_NUMBER") != "" && cfg.Getenv("BITBUCKET_STEP_OIDC_TOKEN") != "" {
		return ProviderBitbucket, true
	}
	if cfg.Getenv("CIRCLECI") == "true" && cfg.Getenv(cfg.IDTokenVar) != "" {
		return ProviderCircleCI, true
	}
	if cfg.Getenv("JENKINS_URL") != "" && cfg.Getenv(cfg.IDTokenVar) != "" {
		return ProviderJenkins, true
	}
	return "", false
}

// hints are what the job reports about itself for what its provider's token
// does not sign: the commit (CircleCI, and Bitbucket or Jenkins tokens
// without one) and the repository name (Bitbucket). The platform uses them
// only then, and marks such a commit unverified.
//
// base_ref is the pull or merge request's target branch. The platform takes
// it only to pick the gate's baseline among the repository's release lines
// (GitHub also signs it), so a wrong value can narrow but never widen what
// passes.
func (r *Run) hints() map[string]string {
	g := r.cfg.Getenv
	h := map[string]string{}
	switch r.provider {
	case ProviderGitHub:
		h["base_ref"] = g("GITHUB_BASE_REF")
	case ProviderGitLab:
		h["base_ref"] = g("CI_MERGE_REQUEST_TARGET_BRANCH_NAME")
	case ProviderAzureDevOps:
		h["base_ref"] = strings.TrimPrefix(g("SYSTEM_PULLREQUEST_TARGETBRANCH"), "refs/heads/")
	case ProviderBitbucket:
		h["commit_sha"], h["repository"] = g("BITBUCKET_COMMIT"), g("BITBUCKET_REPO_FULL_NAME")
		h["base_ref"] = g("BITBUCKET_PR_DESTINATION_BRANCH")
	case ProviderCircleCI:
		h["commit_sha"] = g("CIRCLE_SHA1")
	case ProviderJenkins:
		h["commit_sha"] = g("GIT_COMMIT")
		h["base_ref"] = g("CHANGE_TARGET")
	}
	return h
}

// Run is one CI run on the platform. The run token is obtained at the
// first call, after the scan, so its lifetime covers the upload and the
// verdict.
type Run struct {
	cfg      Config
	provider string

	mu        sync.Mutex
	runID     string
	token     string
	expiresAt time.Time
	info      Info
	// exchangeErr is why the exchange of the job's single OIDC token (every
	// provider but GitHub and Azure) failed: every later call reports it
	// (SecretKey has no error to return).
	exchangeErr error
	// cacheRead: the job's token cache was looked at; fromCache: the run
	// token came from it.
	cacheRead bool
	fromCache bool
	// repoPolicy is the gate part of the repository's .openctem.yml.
	repoPolicy json.RawMessage
	// secretKey hashes the raw secrets the job finds (from the exchange).
	secretKey []byte
}

// SetRepoPolicy sends the repository file's gate settings with the verdict
// request (the platform applies only what is stricter).
func (r *Run) SetRepoPolicy(raw json.RawMessage) { r.repoPolicy = raw }

// SecretKey is the key the platform hands the job to hash the raw secrets
// it finds (the run is opened if it is not yet); nil when the platform gives
// none, and the secrets then go up masked only.
func (r *Run) SecretKey(ctx context.Context) []byte {
	if _, err := r.bearer(ctx); err != nil {
		return nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]byte(nil), r.secretKey...)
}

// Info is what the platform says about the run.
type Info struct {
	RunID           string `json:"run_id"`
	Repository      string `json:"repository"`
	Branch          string `json:"branch"`
	CommitSHA       string `json:"commit_sha"`
	PullRequest     string `json:"pull_request"`
	DefaultBranch   string `json:"default_branch"`
	IsDefaultBranch bool   `json:"is_default_branch"`
}

// New returns a run for this CI job, or ErrNoOIDC when the job has no OIDC
// token to offer.
func New(cfg Config) (*Run, error) {
	cfg.normalize()
	provider, ok := DetectOIDC(cfg)
	if !ok {
		return nil, ErrNoOIDC
	}
	if cfg.APIURL == "" {
		return nil, fmt.Errorf("%s is required to report to the platform", EnvAPIURL)
	}
	if err := CheckAPIURL(cfg.APIURL); err != nil {
		return nil, err
	}
	return &Run{cfg: cfg, provider: provider}, nil
}

// CheckAPIURL accepts an https URL without credentials, query or fragment;
// plain http only for a loopback host (a local test platform), because the
// run token travels in every request.
func CheckAPIURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return fmt.Errorf("%s must be an https URL without credentials, query or fragment", EnvAPIURL)
	}
	switch u.Scheme {
	case "https":
		return nil
	case "http":
		switch u.Hostname() {
		case "localhost", "127.0.0.1", "::1":
			return nil
		}
	}
	return fmt.Errorf("%s must use https (plain http is accepted only for localhost)", EnvAPIURL)
}

// Provider is the CI provider the run authenticates with.
func (r *Run) Provider() string { return r.provider }

// Info is the run as the platform registered it (empty before the first call).
func (r *Run) Info() Info {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.info
}

// String never shows the token.
func (r *Run) String() string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return fmt.Sprintf("Run{provider=%s run=%s token=[redacted]}", r.provider, r.runID)
}

// bearer returns a valid run token: the one this process holds, the one an
// earlier openctem-ci step of the same job left in the job's token cache
// (cache.go), or a new one from an exchange (renewing as needed).
func (r *Run) bearer(ctx context.Context) (string, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.token == "" && !r.cacheRead {
		r.cacheRead = true
		r.loadCache()
	}
	if r.token != "" && time.Until(r.expiresAt) > renewBefore {
		return r.token, nil
	}
	if r.token != "" && !canMint(r.provider) && time.Until(r.expiresAt) > cacheMargin {
		// The job holds one OIDC token: keep the run token until it
		// (nearly) expires, then exchange the same OIDC token again,
		// which the platform answers with the same run.
		return r.token, nil
	}
	if r.exchangeErr != nil {
		return "", r.exchangeErr
	}
	idToken, err := r.idToken(ctx)
	if err != nil {
		return "", err
	}
	token, err := r.exchange(ctx, idToken)
	if err != nil && !canMint(r.provider) {
		// The same token would be refused for the same reason: keep the
		// cause for every later call instead of asking again.
		r.exchangeErr = err
	}
	if err == nil {
		r.saveCache()
	}
	return token, err
}

// exchange trades the job's OIDC token for a run token. r.mu is held.
func (r *Run) exchange(ctx context.Context, idToken string) (string, error) {
	body := map[string]any{"tenant_id": r.cfg.TenantID, "id_token": idToken}
	for k, v := range r.hints() {
		if v = strings.TrimSpace(v); v != "" {
			body[k] = v
		}
	}
	if r.runID != "" {
		body["run_id"] = r.runID
	} else if r.cfg.Aggregate {
		body["aggregate"] = true
	}
	var out struct {
		Info
		Token     string    `json:"token"`
		ExpiresAt time.Time `json:"expires_at"`
		Aggregate bool      `json:"aggregate"`
		SecretKey string    `json:"secret_key"`
	}
	if err := r.do(ctx, kindExchange, "", "/api/v1/ci/oidc/exchange", body, &out); err != nil {
		var se *StatusError
		if errors.As(err, &se) && se.Status == http.StatusUnauthorized {
			if strings.HasPrefix(se.Message, "The CI token was not accepted") {
				// The platform says why and what to check.
				return "", fmt.Errorf("%w: %s (audience %q)", ErrRefused, se.Message, r.cfg.Audience)
			}
			return "", fmt.Errorf("%w: %s (check the CI trust configuration and the audience %q)",
				ErrRefused, se.Message, r.cfg.Audience)
		}
		return "", fmt.Errorf("CI token exchange: %w", err)
	}
	if !strings.HasPrefix(out.Token, tokenPrefix) || out.RunID == "" {
		return "", errors.New("CI token exchange: unexpected response")
	}
	// A platform that does not know aggregate runs would give each job a
	// run of its own, and the final gate job would judge an empty run and
	// pass: refuse instead of failing open.
	if r.cfg.Aggregate && r.runID == "" && !out.Aggregate {
		return "", ErrNoAggregate
	}
	r.token, r.expiresAt, r.runID, r.info = out.Token, out.ExpiresAt, out.RunID, out.Info
	if k, err := base64.StdEncoding.DecodeString(out.SecretKey); err == nil && len(k) >= 32 {
		r.secretKey = k
	}
	return r.token, nil
}

// idToken asks the CI provider for the job's OIDC token.
func (r *Run) idToken(ctx context.Context) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, r.cfg.RequestTimeout)
	defer cancel()
	switch r.provider {
	case ProviderGitHub:
		u, err := url.Parse(r.cfg.Getenv("ACTIONS_ID_TOKEN_REQUEST_URL"))
		if err != nil || u.Host == "" || u.Scheme != "https" {
			return "", errors.New("ACTIONS_ID_TOKEN_REQUEST_URL is not an https URL")
		}
		q := u.Query()
		q.Set("audience", r.cfg.Audience)
		u.RawQuery = q.Encode()
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
		if err != nil {
			return "", err
		}
		req.Header.Set("Authorization", "bearer "+r.cfg.Getenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN"))
		req.Header.Set("Accept", "application/json")
		resp, err := r.cfg.HTTPClient.Do(req)
		if err != nil {
			return "", fmt.Errorf("request the GitHub OIDC token: %w", scrubURL(err))
		}
		defer func() { _ = resp.Body.Close() }()
		if resp.StatusCode != http.StatusOK {
			_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxErrBody))
			return "", fmt.Errorf("request the GitHub OIDC token: status %d (does the workflow grant id-token: write?)", resp.StatusCode)
		}
		var out struct {
			Value string `json:"value"`
		}
		if err := json.NewDecoder(io.LimitReader(resp.Body, maxTokenBody)).Decode(&out); err != nil || out.Value == "" {
			return "", errors.New("request the GitHub OIDC token: no token in the response")
		}
		return out.Value, nil
	case ProviderAzureDevOps:
		return r.azureToken(ctx)
	case ProviderGitLab, ProviderBitbucket, ProviderCircleCI, ProviderJenkins:
		if r.provider == ProviderBitbucket {
			return r.cfg.Getenv("BITBUCKET_STEP_OIDC_TOKEN"), nil
		}
		return r.cfg.Getenv(r.cfg.IDTokenVar), nil
	}
	return "", ErrNoOIDC
}

// azureToken asks Azure DevOps for the job's pipeline token: the job's
// System.OidcRequestUri, authenticated with its own System.AccessToken
// (mapped into the step as SYSTEM_ACCESSTOKEN), without a service
// connection. Neither token is printed.
func (r *Run) azureToken(ctx context.Context) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, r.cfg.RequestTimeout)
	defer cancel()
	u, err := url.Parse(r.cfg.Getenv("SYSTEM_OIDCREQUESTURI"))
	if err != nil || u.Host == "" || u.Scheme != "https" {
		return "", errors.New("SYSTEM_OIDCREQUESTURI is not an https URL")
	}
	q := u.Query()
	q.Set("api-version", azureOIDCAPIVersion)
	u.RawQuery = q.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u.String(), strings.NewReader("{}"))
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+r.cfg.Getenv("SYSTEM_ACCESSTOKEN"))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	resp, err := r.cfg.HTTPClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("request the Azure Pipelines OIDC token: %w", scrubURL(err))
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxErrBody))
		return "", fmt.Errorf("request the Azure Pipelines OIDC token: status %d (is SYSTEM_ACCESSTOKEN mapped from $(System.AccessToken)?)", resp.StatusCode)
	}
	var out struct {
		OIDCToken string `json:"oidcToken"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxTokenBody)).Decode(&out); err != nil || out.OIDCToken == "" {
		return "", errors.New("request the Azure Pipelines OIDC token: no token in the response")
	}
	return out.OIDCToken, nil
}

// StatusError is an HTTP error from the platform: the status and the
// platform's message only.
type StatusError struct {
	Status  int
	Message string
}

func (e *StatusError) Error() string {
	if e.Message == "" {
		return fmt.Sprintf("status %d", e.Status)
	}
	return fmt.Sprintf("status %d: %s", e.Status, e.Message)
}

// requestKind says how a request may be repeated after a transient
// failure (retryable).
type requestKind int

const (
	// kindExchange: the job's OIDC token is single use and the platform may
	// have spent it on a request whose answer was lost, so the exchange is
	// repeated only when nothing reached the platform's token check (no
	// connection, or 429/503 from the rate limiter or a proxy).
	kindExchange requestKind = iota
	// kindUpload: repeating a report is harmless (findings are keyed by
	// fingerprint).
	kindUpload
	// kindEvaluate: the first verdict is final, so asking again returns it.
	kindEvaluate
)

// retryable reports whether a failed request may be repeated: a network
// error or 429 or 5xx, never another 4xx (the request itself is wrong, or
// was refused).
func retryable(kind requestKind, status int, err error) bool {
	if err != nil {
		if kind == kindExchange {
			var op *net.OpError
			return errors.As(err, &op) && op.Op == "dial"
		}
		return !errors.Is(err, context.Canceled)
	}
	switch {
	case status == http.StatusTooManyRequests, status == http.StatusServiceUnavailable:
		return true
	case kind == kindExchange:
		return false
	}
	return status >= 500
}

// backoff is the wait before attempt n (1-based): 1s, 2s, 4s ... capped at
// 30s with ±25% jitter; a Retry-After of up to 2 minutes wins.
func backoff(n int, retryAfter string) time.Duration {
	if s, err := strconv.Atoi(strings.TrimSpace(retryAfter)); err == nil && s >= 0 && s <= 120 {
		return time.Duration(s) * time.Second
	}
	d := time.Second << min(n-1, 5)
	d = min(d, 30*time.Second)
	return d - d/4 + time.Duration(rand.Int64N(int64(d/2)+1)) // #nosec G404 -- jitter, not a secret
}

// sleep waits d or until ctx ends (replaced in tests).
var sleep = func(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// do sends a JSON request to the platform, repeating it after a transient
// failure (retryable). The bearer is never part of an error. A large body
// goes gzip-compressed.
func (r *Run) do(ctx context.Context, kind requestKind, bearer, path string, body, out any) error {
	b, err := json.Marshal(body)
	if err != nil {
		return err
	}
	encoding := ""
	if len(b) >= gzipFrom {
		var z bytes.Buffer
		zw := gzip.NewWriter(&z)
		if _, err := zw.Write(b); err != nil {
			return err
		}
		if err := zw.Close(); err != nil {
			return err
		}
		b, encoding = z.Bytes(), "gzip"
	}
	timeout := r.cfg.RequestTimeout
	if kind == kindUpload {
		timeout = r.cfg.UploadTimeout
	}
	for attempt := 1; ; attempt++ {
		status, retryAfter, err := r.once(ctx, timeout, bearer, path, b, encoding, out)
		if err == nil || attempt > r.cfg.Retries || !retryable(kind, status, transportErr(status, err)) {
			return err
		}
		if serr := sleep(ctx, backoff(attempt, retryAfter)); serr != nil {
			return err
		}
	}
}

// transportErr is err when the request got no HTTP answer, nil otherwise.
func transportErr(status int, err error) error {
	if status != 0 {
		return nil
	}
	return err
}

// once sends one request; status is 0 when no HTTP answer came back.
func (r *Run) once(ctx context.Context, timeout time.Duration, bearer, path string, body []byte, encoding string, out any) (int, string, error) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, r.cfg.APIURL+path, bytes.NewReader(body))
	if err != nil {
		return 0, "", err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	if encoding != "" {
		req.Header.Set("Content-Encoding", encoding)
	}
	if r.cfg.UserAgent != "" {
		req.Header.Set("User-Agent", r.cfg.UserAgent)
	}
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	resp, err := r.cfg.HTTPClient.Do(req)
	if err != nil {
		return 0, "", scrubURL(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		raw, _ := io.ReadAll(io.LimitReader(resp.Body, maxErrBody))
		var e struct {
			Message string `json:"message"`
			Code    string `json:"code"`
		}
		_ = json.Unmarshal(raw, &e)
		msg := e.Message
		if e.Code != "" && msg != "" {
			msg = e.Code + ": " + msg
		}
		return resp.StatusCode, resp.Header.Get("Retry-After"), &StatusError{Status: resp.StatusCode, Message: Sanitize(msg)}
	}
	if out == nil {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxErrBody))
		return resp.StatusCode, "", nil
	}
	return resp.StatusCode, "", json.NewDecoder(io.LimitReader(resp.Body, maxBody)).Decode(out)
}

// call runs an authenticated request on the run.
func (r *Run) call(ctx context.Context, kind requestKind, action string, body, out any) error {
	tok, err := r.bearer(ctx)
	if err != nil {
		return err
	}
	r.mu.Lock()
	path := "/api/v1/ci/runs/" + url.PathEscape(r.runID) + "/" + action
	fromCache := r.fromCache
	r.mu.Unlock()
	err = r.do(ctx, kind, tok, path, body, out)
	var se *StatusError
	if fromCache && errors.As(err, &se) && se.Status == http.StatusUnauthorized {
		// A run token another step left behind that the platform no longer
		// takes: forget it and exchange this job's own token once.
		r.mu.Lock()
		r.dropCache()
		r.token, r.runID, r.fromCache = "", "", false
		r.mu.Unlock()
		if tok, err = r.bearer(ctx); err != nil {
			return err
		}
		r.mu.Lock()
		path = "/api/v1/ci/runs/" + url.PathEscape(r.runID) + "/" + action
		r.mu.Unlock()
		err = r.do(ctx, kind, tok, path, body, out)
	}
	return err
}

// UploadResult counts what the platform stored from a report.
type UploadResult struct {
	FindingsCreated int `json:"findings_created"`
	FindingsUpdated int `json:"findings_updated"`
	AssetsCreated   int `json:"assets_created"`
	AssetsUpdated   int `json:"assets_updated"`
	// Known are the results of the uploaded report that already carry a
	// decision on OpenCTEM (false positive, duplicate, accepted risk, an
	// approved exception), by their index in the report. The gate does not
	// count them; the job leaves them out of its own output.
	Known []Known `json:"known"`
}

// Known is one uploaded result OpenCTEM has already decided.
type Known struct {
	Index     int    `json:"index"`
	Decision  string `json:"decision"`
	FindingID string `json:"finding_id"`
}

// Upload sends a report to the run.
func (r *Run) Upload(ctx context.Context, report *ctis.Report) (*UploadResult, error) {
	if report == nil {
		return &UploadResult{}, nil
	}
	var out UploadResult
	if err := r.call(ctx, kindUpload, "results", map[string]any{"report": report}, &out); err != nil {
		return nil, fmt.Errorf("upload results: %w", err)
	}
	return &out, nil
}

// Reason is one line of a verdict.
type Reason struct {
	Code      string `json:"code"`
	Message   string `json:"message"`
	Title     string `json:"title,omitempty"`
	Severity  string `json:"severity,omitempty"`
	File      string `json:"file,omitempty"`
	Line      int    `json:"line,omitempty"`
	URL       string `json:"url,omitempty"`
	FindingID string `json:"finding_id,omitempty"`
}

// Verdict is the platform's gate verdict for the run.
type Verdict struct {
	RunID     string   `json:"run_id"`
	Verdict   string   `json:"verdict"`
	WouldFail bool     `json:"would_fail"`
	Reasons   []Reason `json:"reasons"`
	Summary   struct {
		Evaluated   int `json:"evaluated"`
		New         int `json:"new"`
		PreExisting int `json:"pre_existing"`
		Accepted    int `json:"accepted"`
		Blocking    int `json:"blocking"`
	} `json:"summary"`
	Policy struct {
		Source string `json:"source"`
		Mode   string `json:"mode"`
	} `json:"policy"`
	Baseline struct {
		Branch string `json:"branch"`
		Known  bool   `json:"known"`
	} `json:"baseline"`
	Links struct {
		Run      string `json:"run"`
		Findings string `json:"findings"`
	} `json:"links"`
}

// Failed reports whether the pipeline must fail.
func (v *Verdict) Failed() bool { return v != nil && v.Verdict == "fail" }

// Evaluate asks the platform's gate for the run's verdict. scanFailures is
// the number of scans that failed to run or to report: any fails the run.
func (r *Run) Evaluate(ctx context.Context, scanFailures int) (*Verdict, error) {
	var v Verdict
	body := map[string]any{"scan_failures": scanFailures}
	if len(r.repoPolicy) > 0 {
		body["repo_policy"] = r.repoPolicy
	}
	if err := r.call(ctx, kindEvaluate, "evaluate", body, &v); err != nil {
		return nil, fmt.Errorf("evaluate: %w", err)
	}
	// The run has its verdict: no later step reports into it.
	r.mu.Lock()
	r.dropCache()
	r.mu.Unlock()
	return &v, nil
}

// WriteVerdict prints a verdict for a pipeline log. Every platform string
// is sanitized: no control characters reach the log (no fake log lines,
// no terminal escapes, no CI workflow commands).
func WriteVerdict(w io.Writer, v *Verdict) {
	if v == nil {
		return
	}
	state := "PASS"
	switch {
	case v.Failed():
		state = "FAIL"
	case v.WouldFail:
		state = "PASS (break-glass or warn mode; it would fail)"
	}
	_, _ = fmt.Fprintf(w, "\nOpenCTEM gate: %s (policy: %s)\n", state, Sanitize(v.Policy.Source))
	_, _ = fmt.Fprintf(w, "  %d judged: %d new, %d already on %s, %d accepted, %d blocking\n",
		v.Summary.Evaluated, v.Summary.New, v.Summary.PreExisting,
		Sanitize(nonEmpty(v.Baseline.Branch, "the default branch")), v.Summary.Accepted, v.Summary.Blocking)
	for _, rs := range v.Reasons {
		where := ""
		if rs.File != "" {
			where = " " + rs.File
			if rs.Line > 0 {
				where += fmt.Sprintf(":%d", rs.Line)
			}
		}
		title := rs.Title
		if title == "" {
			title = rs.Message
		} else {
			title += ": " + rs.Message
		}
		_, _ = fmt.Fprintf(w, "  - [%s]%s %s\n", Sanitize(rs.Code), Sanitize(where), Sanitize(title))
	}
	if v.Links.Run != "" {
		_, _ = fmt.Fprintf(w, "  Run: %s\n", Sanitize(v.Links.Run))
	}
}

// Sanitize replaces control characters, the "::" that starts a GitHub
// workflow command and the "##" that starts an Azure Pipelines logging
// command ("##vso[...]", "##[...]", read anywhere in a line), so platform,
// scanner or repository text (file paths, titles) cannot forge log lines or
// set pipeline variables.
func Sanitize(s string) string {
	s = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f || (r >= 0x80 && r < 0xa0) {
			return ' '
		}
		return r
	}, s)
	s = strings.ReplaceAll(s, "::", ": :")
	return strings.ReplaceAll(s, "##", "# #")
}

func nonEmpty(s, fallback string) string {
	if s == "" {
		return fallback
	}
	return s
}

// scrubURL drops the request URL from a transport error: a GitHub token
// request URL carries a query the log does not need.
func scrubURL(err error) error {
	var ue *url.Error
	if errors.As(err, &ue) {
		return fmt.Errorf("%s: %w", ue.Op, ue.Err)
	}
	return err
}
