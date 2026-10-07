package platform

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/openctemio/ctis"
)

const runToken = "octci_RUNTOKEN_never_printed"

// fakePlatform records the requests it got.
type fakePlatform struct {
	mu        sync.Mutex
	exchanges []map[string]any
	paths     []string
	auth      []string
	status    map[string]int // path suffix -> forced status
	token     string
	// noAggregate plays a platform that does not know aggregate runs.
	noAggregate bool
}

func (f *fakePlatform) handler(t *testing.T) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		f.paths = append(f.paths, r.URL.Path)
		f.auth = append(f.auth, r.Header.Get("Authorization"))
		for suffix, code := range f.status {
			if strings.HasSuffix(r.URL.Path, suffix) {
				w.WriteHeader(code)
				_, _ = fmt.Fprintf(w, `{"code":"X","message":"refused \u001b[31m"}`)
				return
			}
		}
		switch {
		case r.URL.Path == "/api/v1/ci/oidc/exchange":
			var body map[string]any
			_ = json.NewDecoder(r.Body).Decode(&body)
			f.exchanges = append(f.exchanges, body)
			tok := f.token
			if tok == "" {
				tok = runToken
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"run_id": "run-1", "token": tok, "aggregate": body["aggregate"] == true && !f.noAggregate,
				"expires_at": time.Now().Add(15 * time.Minute), "repository": "github.com/acme/app", "commit_sha": "abc"})
		case strings.HasSuffix(r.URL.Path, "/results"):
			_, _ = w.Write([]byte(`{"findings_created":2}`))
		case strings.HasSuffix(r.URL.Path, "/evaluate"):
			_, _ = w.Write([]byte(`{"run_id":"run-1","verdict":"fail","reasons":[{"code":"new_high","message":"::error::forged\nline","file":"a.py","line":3}],"links":{"run":"https://x/ci-runners/run-1"}}`))
		default:
			http.NotFound(w, r)
		}
	})
}

// githubEnv starts the GitHub OIDC token endpoint (TLS) and returns the
// job environment and an HTTP client that trusts it.
func githubEnv(t *testing.T, apiURL string) (func(string) string, *http.Client) {
	t.Helper()
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "bearer req-token" || r.URL.Query().Get("audience") != "openctem:tenant:t1" {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		_, _ = w.Write([]byte(`{"value":"gh-oidc-jwt"}`))
	}))
	t.Cleanup(ts.Close)
	env := map[string]string{"GITHUB_ACTIONS": "true", "ACTIONS_ID_TOKEN_REQUEST_URL": ts.URL + "/token?x=1",
		"ACTIONS_ID_TOKEN_REQUEST_TOKEN": "req-token", EnvTenantID: "t1", EnvAPIURL: apiURL}
	return func(k string) string { return env[k] }, ts.Client()
}

func newRun(t *testing.T, f *fakePlatform, aggregate bool) *Run {
	t.Helper()
	srv := httptest.NewServer(f.handler(t))
	t.Cleanup(srv.Close)
	getenv, client := githubEnv(t, srv.URL)
	cfg := ConfigFromEnv(getenv)
	cfg.HTTPClient, cfg.Aggregate, cfg.UserAgent = client, aggregate, "openctem-ci/test"
	r, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func TestGitHubRunUploadEvaluate(t *testing.T) {
	f := &fakePlatform{}
	r := newRun(t, f, false)
	if r.Provider() != ProviderGitHub {
		t.Fatal(r.Provider())
	}
	up, err := r.Upload(context.Background(), &ctis.Report{Version: "1.6"})
	if err != nil || up.FindingsCreated != 2 {
		t.Fatalf("%v %+v", err, up)
	}
	v, err := r.Evaluate(context.Background(), 1)
	if err != nil || !v.Failed() {
		t.Fatalf("%v %+v", err, v)
	}
	if len(f.exchanges) != 1 || f.exchanges[0]["id_token"] != "gh-oidc-jwt" || f.exchanges[0]["tenant_id"] != "t1" {
		t.Fatalf("exchanges %+v", f.exchanges)
	}
	if _, ok := f.exchanges[0]["aggregate"]; ok {
		t.Fatal("aggregate sent for a per-job run")
	}
	if f.auth[0] != "" || f.auth[1] != "Bearer "+runToken || f.paths[1] != "/api/v1/ci/runs/run-1/results" {
		t.Fatalf("auth %q paths %q", f.auth, f.paths)
	}
	if r.Info().RunID != "run-1" || strings.Contains(r.String(), runToken) {
		t.Fatalf("%s", r)
	}

	var b bytes.Buffer
	WriteVerdict(&b, v)
	out := b.String()
	if strings.Contains(out, "::error::") || strings.Contains(out, "forged\n") {
		t.Fatalf("platform text forged a log line:\n%s", out)
	}
	if !strings.Contains(out, "FAIL") || !strings.Contains(out, "a.py:3") {
		t.Fatalf("%s", out)
	}
}

func TestAggregateFlag(t *testing.T) {
	f := &fakePlatform{}
	r := newRun(t, f, true)
	if _, err := r.Upload(context.Background(), &ctis.Report{}); err != nil {
		t.Fatal(err)
	}
	if f.exchanges[0]["aggregate"] != true {
		t.Fatalf("%+v", f.exchanges[0])
	}
}

// A platform that answers an aggregate request with a run of its own is
// refused: the final gate would judge an empty run and pass.
func TestAggregateNotSupportedFailsClosed(t *testing.T) {
	f := &fakePlatform{noAggregate: true}
	r := newRun(t, f, true)
	if _, err := r.Upload(context.Background(), &ctis.Report{}); !errors.Is(err, ErrNoAggregate) {
		t.Fatalf("%v", err)
	}
}

// The run token never appears in an error.
func TestTokenNeverInErrors(t *testing.T) {
	f := &fakePlatform{status: map[string]int{"/results": http.StatusForbidden, "/evaluate": http.StatusBadGateway}}
	r := newRun(t, f, false)
	_, err1 := r.Upload(context.Background(), &ctis.Report{})
	_, err2 := r.Evaluate(context.Background(), 0)
	for _, err := range []error{err1, err2} {
		if err == nil {
			t.Fatal("no error")
		}
		if strings.Contains(err.Error(), runToken) || strings.Contains(err.Error(), "gh-oidc-jwt") || strings.Contains(err.Error(), "\x1b") {
			t.Fatalf("error leaks: %q", err)
		}
	}
	var se *StatusError
	if !errors.As(err1, &se) || se.Status != http.StatusForbidden {
		t.Fatalf("%v", err1)
	}
}

func TestExchangeRefused(t *testing.T) {
	f := &fakePlatform{status: map[string]int{"/exchange": http.StatusUnauthorized}}
	r := newRun(t, f, false)
	_, err := r.Upload(context.Background(), &ctis.Report{})
	if !errors.Is(err, ErrRefused) {
		t.Fatalf("%v", err)
	}
}

func TestUnexpectedTokenRefused(t *testing.T) {
	f := &fakePlatform{token: "not-a-run-token"}
	r := newRun(t, f, false)
	if _, err := r.Upload(context.Background(), &ctis.Report{}); err == nil || !strings.Contains(err.Error(), "unexpected") {
		t.Fatalf("%v", err)
	}
}

// A redirect is not followed: it could carry the bearer to another host.
func TestRedirectNotFollowed(t *testing.T) {
	var hit bool
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hit = true }))
	defer other.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, other.URL+r.URL.Path, http.StatusTemporaryRedirect)
	}))
	defer srv.Close()
	env := map[string]string{"GITLAB_CI": "true", DefaultIDTokenVar: "gl-jwt", EnvTenantID: "t1", EnvAPIURL: srv.URL}
	r, err := New(ConfigFromEnv(func(k string) string { return env[k] }))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.Upload(context.Background(), &ctis.Report{}); err == nil {
		t.Fatal("a redirect was followed")
	}
	if hit {
		t.Fatal("the other host was reached")
	}
}

// A GitLab ID token is good for one exchange.
func TestGitLabSingleExchange(t *testing.T) {
	f := &fakePlatform{}
	srv := httptest.NewServer(f.handler(t))
	defer srv.Close()
	env := map[string]string{"GITLAB_CI": "true", "MY_TOKEN": "gl-jwt", EnvIDTokenVar: "MY_TOKEN", EnvTenantID: "t1", EnvAPIURL: srv.URL}
	r, err := New(ConfigFromEnv(func(k string) string { return env[k] }))
	if err != nil || r.Provider() != ProviderGitLab {
		t.Fatalf("%v", err)
	}
	if _, err := r.Upload(context.Background(), &ctis.Report{}); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Evaluate(context.Background(), 0); err != nil {
		t.Fatal(err)
	}
	if len(f.exchanges) != 1 || f.exchanges[0]["id_token"] != "gl-jwt" {
		t.Fatalf("%+v", f.exchanges)
	}
	r.mu.Lock()
	r.expiresAt = time.Now().Add(-time.Second)
	r.mu.Unlock()
	if _, err := r.Evaluate(context.Background(), 0); err == nil {
		t.Fatal("an expired GitLab run token was renewed with a used ID token")
	}
}

func TestNoOIDC(t *testing.T) {
	for name, env := range map[string]map[string]string{
		"no tenant":       {"GITHUB_ACTIONS": "true", "ACTIONS_ID_TOKEN_REQUEST_URL": "https://x", "ACTIONS_ID_TOKEN_REQUEST_TOKEN": "t"},
		"no id-token":     {"GITHUB_ACTIONS": "true", EnvTenantID: "t1"},
		"gitlab no token": {"GITLAB_CI": "true", EnvTenantID: "t1"},
		"other CI":        {EnvTenantID: "t1", "JENKINS_URL": "x"},
	} {
		env[EnvAPIURL] = "https://p.example"
		if _, err := New(ConfigFromEnv(func(k string) string { return env[k] })); !errors.Is(err, ErrNoOIDC) {
			t.Errorf("%s: %v", name, err)
		}
	}
	env := map[string]string{"GITLAB_CI": "true", DefaultIDTokenVar: "j", EnvTenantID: "t1"}
	if _, err := New(ConfigFromEnv(func(k string) string { return env[k] })); err == nil {
		t.Error("no API URL accepted")
	}
}

func TestCheckAPIURL(t *testing.T) {
	for _, ok := range []string{"https://openctem.example.com", "https://x.example:8443/base", "http://localhost:8080", "http://127.0.0.1:1"} {
		if err := CheckAPIURL(ok); err != nil {
			t.Errorf("%s: %v", ok, err)
		}
	}
	for _, bad := range []string{"http://openctem.example.com", "https://user:pw@x.example", "https://x.example?a=b",
		"ftp://x", "x.example", "", "https://x.example#f"} {
		if CheckAPIURL(bad) == nil {
			t.Errorf("%s accepted", bad)
		}
	}
}

func TestSanitize(t *testing.T) {
	if got := Sanitize("a\nb\x1b[31m::warning::c\u0085"); strings.ContainsAny(got, "\n\x1b\u0085") || strings.Contains(got, "::") {
		t.Fatalf("%q", got)
	}
}
