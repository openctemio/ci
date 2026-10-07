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
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
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
	maxErrBody   = 4 << 10
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
	// HTTPClient makes every request (default: 30s timeout, no redirects).
	HTTPClient *http.Client
	// Getenv reads the environment.
	Getenv func(string) string
}

// ConfigFromEnv fills a configuration from the environment.
func ConfigFromEnv(getenv func(string) string) Config {
	return Config{APIURL: getenv(EnvAPIURL), TenantID: getenv(EnvTenantID),
		Audience: getenv(EnvAudience), IDTokenVar: getenv(EnvIDTokenVar), Getenv: getenv}
}

func (c *Config) normalize() {
	c.APIURL = strings.TrimRight(strings.TrimSpace(c.APIURL), "/")
	c.TenantID = strings.TrimSpace(c.TenantID)
	if c.Audience == "" && c.TenantID != "" {
		c.Audience = "openctem:tenant:" + c.TenantID
	}
	if c.IDTokenVar == "" {
		c.IDTokenVar = DefaultIDTokenVar
	}
	if c.HTTPClient == nil {
		c.HTTPClient = &http.Client{
			Timeout: 30 * time.Second,
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
func (r *Run) hints() map[string]string {
	g := r.cfg.Getenv
	switch r.provider {
	case ProviderBitbucket:
		return map[string]string{"commit_sha": g("BITBUCKET_COMMIT"), "repository": g("BITBUCKET_REPO_FULL_NAME")}
	case ProviderCircleCI:
		return map[string]string{"commit_sha": g("CIRCLE_SHA1")}
	case ProviderJenkins:
		return map[string]string{"commit_sha": g("GIT_COMMIT")}
	}
	return nil
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
	// usedToken: the job's single token (every provider but GitHub and
	// Azure) was exchanged.
	usedToken bool
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

// bearer returns a valid run token, exchanging or renewing as needed.
func (r *Run) bearer(ctx context.Context) (string, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.token != "" && time.Until(r.expiresAt) > renewBefore {
		return r.token, nil
	}
	if r.token != "" && !canMint(r.provider) {
		// The job's token is good for one exchange: keep the run token
		// until it expires.
		if time.Now().Before(r.expiresAt) {
			return r.token, nil
		}
		return "", fmt.Errorf("the CI run token expired and %s offers no second OIDC token to this job", r.provider)
	}
	idToken, err := r.idToken(ctx)
	if err != nil {
		return "", err
	}
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
	}
	if err := r.do(ctx, "", "/api/v1/ci/oidc/exchange", body, &out); err != nil {
		var se *StatusError
		if errors.As(err, &se) && se.Status == http.StatusUnauthorized {
			return "", fmt.Errorf("%w: %s (check the CI trust configuration, the audience %q and that the token is used once)",
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
	return r.token, nil
}

// idToken asks the CI provider for the job's OIDC token.
func (r *Run) idToken(ctx context.Context) (string, error) {
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
		if r.usedToken {
			return "", fmt.Errorf("the %s OIDC token was already exchanged", r.provider)
		}
		r.usedToken = true
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

// do sends a JSON request to the platform. The bearer is never part of an
// error.
func (r *Run) do(ctx context.Context, bearer, path string, body, out any) error {
	b, err := json.Marshal(body)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, r.cfg.APIURL+path, bytes.NewReader(b))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	if r.cfg.UserAgent != "" {
		req.Header.Set("User-Agent", r.cfg.UserAgent)
	}
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	resp, err := r.cfg.HTTPClient.Do(req)
	if err != nil {
		return scrubURL(err)
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
		return &StatusError{Status: resp.StatusCode, Message: Sanitize(msg)}
	}
	if out == nil {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxErrBody))
		return nil
	}
	return json.NewDecoder(io.LimitReader(resp.Body, maxBody)).Decode(out)
}

// call runs an authenticated request on the run.
func (r *Run) call(ctx context.Context, action string, body, out any) error {
	tok, err := r.bearer(ctx)
	if err != nil {
		return err
	}
	r.mu.Lock()
	path := "/api/v1/ci/runs/" + url.PathEscape(r.runID) + "/" + action
	r.mu.Unlock()
	return r.do(ctx, tok, path, body, out)
}

// UploadResult counts what the platform stored from a report.
type UploadResult struct {
	FindingsCreated int `json:"findings_created"`
	FindingsUpdated int `json:"findings_updated"`
	AssetsCreated   int `json:"assets_created"`
	AssetsUpdated   int `json:"assets_updated"`
}

// Upload sends a report to the run.
func (r *Run) Upload(ctx context.Context, report *ctis.Report) (*UploadResult, error) {
	if report == nil {
		return &UploadResult{}, nil
	}
	var out UploadResult
	if err := r.call(ctx, "results", map[string]any{"report": report}, &out); err != nil {
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
	if err := r.call(ctx, "evaluate", map[string]int{"scan_failures": scanFailures}, &v); err != nil {
		return nil, fmt.Errorf("evaluate: %w", err)
	}
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

// Sanitize replaces control characters, and the "::" that starts a GitHub
// workflow command, so platform or scanner text cannot forge log lines.
func Sanitize(s string) string {
	s = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f || (r >= 0x80 && r < 0xa0) {
			return ' '
		}
		return r
	}, s)
	return strings.ReplaceAll(s, "::", ": :")
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
