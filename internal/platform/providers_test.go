package platform

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/openctemio/ctis"
)

// Azure Pipelines: openctem-ci asks the job's System.OidcRequestUri for a
// pipeline token with the job's own access token, and asks again to renew.
func TestAzureMintsAndRenews(t *testing.T) {
	f := &fakePlatform{}
	var mints atomic.Int32
	mux := http.NewServeMux()
	mux.HandleFunc("/org/proj/_apis/oidctoken", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.Header.Get("Authorization") != "Bearer job-access-token" ||
			r.URL.Query().Get("api-version") != azureOIDCAPIVersion || r.URL.Query().Get("serviceConnectionId") != "" {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		mints.Add(1)
		_, _ = w.Write([]byte(`{"oidcToken":"az-oidc-jwt"}`))
	})
	mux.Handle("/", f.handler(t))
	srv := httptest.NewTLSServer(mux)
	defer srv.Close()
	env := map[string]string{"TF_BUILD": "True", "SYSTEM_OIDCREQUESTURI": srv.URL + "/org/proj/_apis/oidctoken",
		"SYSTEM_ACCESSTOKEN": "job-access-token", EnvTenantID: "t1", EnvAPIURL: srv.URL}
	cfg := ConfigFromEnv(func(k string) string { return env[k] })
	cfg.HTTPClient = srv.Client()
	r, err := New(cfg)
	if err != nil || r.Provider() != ProviderAzureDevOps {
		t.Fatalf("%v %s", err, r.Provider())
	}
	if _, err := r.Upload(context.Background(), &ctis.Report{}); err != nil {
		t.Fatal(err)
	}
	if len(f.exchanges) != 1 || f.exchanges[0]["id_token"] != "az-oidc-jwt" || f.exchanges[0]["commit_sha"] != nil {
		t.Fatalf("exchanges %+v", f.exchanges)
	}
	r.mu.Lock()
	r.expiresAt = time.Now().Add(time.Minute)
	r.mu.Unlock()
	if _, err := r.Evaluate(context.Background(), 0); err != nil {
		t.Fatal(err)
	}
	if mints.Load() != 2 || len(f.exchanges) != 2 || f.exchanges[1]["run_id"] != "run-1" {
		t.Fatalf("renewal: %d mints, exchanges %+v", mints.Load(), f.exchanges)
	}
}

// A refused token request never prints the job's access token.
func TestAzureErrorsCarryNoToken(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()
	env := map[string]string{"TF_BUILD": "True", "SYSTEM_OIDCREQUESTURI": srv.URL + "/oidc",
		"SYSTEM_ACCESSTOKEN": "job-access-token", EnvTenantID: "t1", EnvAPIURL: srv.URL}
	cfg := ConfigFromEnv(func(k string) string { return env[k] })
	cfg.HTTPClient = srv.Client()
	r, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	_, err = r.Upload(context.Background(), &ctis.Report{})
	if err == nil || strings.Contains(err.Error(), "job-access-token") || !strings.Contains(err.Error(), "System.AccessToken") {
		t.Fatalf("%v", err)
	}
	env["SYSTEM_OIDCREQUESTURI"] = "http://plain.example/oidc"
	r, _ = New(cfg)
	if _, err := r.Upload(context.Background(), &ctis.Report{}); err == nil || !strings.Contains(err.Error(), "https") {
		t.Fatalf("plain http token request: %v", err)
	}
}

// Bitbucket, CircleCI and Jenkins hold one token each; the job reports what
// its token does not sign, once, and never renews with a used token.
func TestSingleTokenProviders(t *testing.T) {
	cases := map[string]struct {
		env      map[string]string
		provider string
		token    string
		hints    map[string]string
	}{
		"bitbucket": {
			env: map[string]string{"BITBUCKET_BUILD_NUMBER": "7", "BITBUCKET_STEP_OIDC_TOKEN": "bb-jwt",
				"BITBUCKET_COMMIT": "c0ffee", "BITBUCKET_REPO_FULL_NAME": "acme/api"},
			provider: ProviderBitbucket, token: "bb-jwt",
			hints: map[string]string{"commit_sha": "c0ffee", "repository": "acme/api"},
		},
		"circleci": {
			env:      map[string]string{"CIRCLECI": "true", "OPENCTEM_ID_TOKEN": "cc-jwt", "CIRCLE_SHA1": "beef"},
			provider: ProviderCircleCI, token: "cc-jwt", hints: map[string]string{"commit_sha": "beef"},
		},
		"jenkins": {
			env:      map[string]string{"JENKINS_URL": "https://ci.example/", "OPENCTEM_ID_TOKEN": "jk-jwt", "GIT_COMMIT": "f00d"},
			provider: ProviderJenkins, token: "jk-jwt", hints: map[string]string{"commit_sha": "f00d"},
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			f := &fakePlatform{}
			srv := httptest.NewServer(f.handler(t))
			defer srv.Close()
			tc.env[EnvTenantID], tc.env[EnvAPIURL] = "t1", srv.URL
			r, err := New(ConfigFromEnv(func(k string) string { return tc.env[k] }))
			if err != nil || r.Provider() != tc.provider {
				t.Fatalf("%v %s", err, r.Provider())
			}
			if _, err := r.Upload(context.Background(), &ctis.Report{}); err != nil {
				t.Fatal(err)
			}
			ex := f.exchanges[0]
			if ex["id_token"] != tc.token {
				t.Fatalf("exchange %+v", ex)
			}
			for k, v := range tc.hints {
				if ex[k] != v {
					t.Fatalf("%s = %v, want %s", k, ex[k], v)
				}
			}
			r.mu.Lock()
			r.expiresAt = time.Now().Add(-time.Second)
			r.mu.Unlock()
			if _, err := r.Evaluate(context.Background(), 0); err == nil || len(f.exchanges) != 1 {
				t.Fatalf("renewed with a used token: %v, %d exchanges", err, len(f.exchanges))
			}
		})
	}
}

// CircleCI's ready-made token carries the organization id as its audience,
// which the platform refuses: without a minted OPENCTEM_ID_TOKEN there is
// no token to offer.
func TestCircleCIReadyMadeTokenNotUsed(t *testing.T) {
	env := map[string]string{"CIRCLECI": "true", "CIRCLE_OIDC_TOKEN_V2": "cc-default", EnvTenantID: "t1", EnvAPIURL: "https://x"}
	if _, ok := DetectOIDC(ConfigFromEnv(func(k string) string { return env[k] })); ok {
		t.Fatal("the default CircleCI token was offered")
	}
	env = map[string]string{"BITBUCKET_BUILD_NUMBER": "7", EnvTenantID: "t1", EnvAPIURL: "https://x"}
	if _, ok := DetectOIDC(ConfigFromEnv(func(k string) string { return env[k] })); ok {
		t.Fatal("a Bitbucket step without oidc: true offered a token")
	}
}
