package platform

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/openctemio/ctis"
)

func gitlabRun(t *testing.T, f *fakePlatform, aggregate bool) *Run {
	t.Helper()
	srv := httptest.NewServer(f.handler(t))
	t.Cleanup(srv.Close)
	env := map[string]string{"GITLAB_CI": "true", DefaultIDTokenVar: "gl-jwt", EnvTenantID: "t1", EnvAPIURL: srv.URL}
	cfg := ConfigFromEnv(func(k string) string { return env[k] })
	cfg.Aggregate = aggregate
	r, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

// The job's one GitLab token is spent by the first exchange. When that
// exchange fails (here: the platform refuses it) during SecretKey, which
// has no error to return, the upload that follows must report the
// platform's refusal, not "the gitlab OIDC token was already exchanged".
func TestFirstExchangeFailureIsNotMasked(t *testing.T) {
	f := &fakePlatform{status: map[string]int{"/exchange": http.StatusUnauthorized}}
	r := gitlabRun(t, f, true)
	if k := r.SecretKey(context.Background()); k != nil {
		t.Fatal("a refused exchange gave a secret key")
	}
	_, err := r.Upload(context.Background(), &ctis.Report{})
	if err == nil || strings.Contains(err.Error(), "already exchanged") || !errors.Is(err, ErrRefused) {
		t.Fatalf("upload after a refused exchange: %v, want the refusal", err)
	}
	if countPath(f, "/exchange") != 1 {
		t.Fatalf("exchanges: %d, want exactly 1 (the token is single use)", countPath(f, "/exchange"))
	}
}

// A platform without aggregate runs: the refusal names that, every time.
func TestNoAggregateIsNotMasked(t *testing.T) {
	f := &fakePlatform{noAggregate: true}
	r := gitlabRun(t, f, true)
	_ = r.SecretKey(context.Background())
	if _, err := r.Upload(context.Background(), &ctis.Report{}); !errors.Is(err, ErrNoAggregate) {
		t.Fatalf("upload: %v, want ErrNoAggregate", err)
	}
	if _, err := r.Evaluate(context.Background(), 0); !errors.Is(err, ErrNoAggregate) {
		t.Fatalf("evaluate: %v, want ErrNoAggregate", err)
	}
}

func countPath(f *fakePlatform, suffix string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := 0
	for _, p := range f.paths {
		if strings.HasSuffix(p, suffix) {
			n++
		}
	}
	return n
}
