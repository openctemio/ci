package platform

import (
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/openctemio/ctis"
)

// Tests never wait: the backoff a retry would sleep is recorded instead.
var (
	waitsMu sync.Mutex
	waits   []time.Duration
)

func TestMain(m *testing.M) {
	sleep = func(_ context.Context, d time.Duration) error {
		waitsMu.Lock()
		waits = append(waits, d)
		waitsMu.Unlock()
		return nil
	}
	os.Exit(m.Run())
}

func takeWaits() []time.Duration {
	waitsMu.Lock()
	defer waitsMu.Unlock()
	w := waits
	waits = nil
	return w
}

// scripted answers each path with the next scripted status (200 once the
// script is used up) and records what it received.
type scripted struct {
	mu       sync.Mutex
	script   map[string][]int
	after    map[string]string // path suffix -> Retry-After
	calls    map[string]int
	encoding []string
	bodies   [][]byte
}

func (s *scripted) server(t *testing.T) *Run {
	t.Helper()
	s.calls = map[string]int{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.mu.Lock()
		defer s.mu.Unlock()
		key := r.URL.Path[strings.LastIndex(r.URL.Path, "/")+1:]
		s.calls[key]++
		if key == "results" {
			s.encoding = append(s.encoding, r.Header.Get("Content-Encoding"))
			b, _ := io.ReadAll(r.Body)
			s.bodies = append(s.bodies, b)
		}
		if q := s.script[key]; len(q) > 0 {
			s.script[key] = q[1:]
			if ra := s.after[key]; ra != "" {
				w.Header().Set("Retry-After", ra)
			}
			w.WriteHeader(q[0])
			_, _ = w.Write([]byte(`{"message":"busy"}`))
			return
		}
		switch key {
		case "exchange":
			_ = json.NewEncoder(w).Encode(map[string]any{"run_id": "run-1", "token": runToken, "expires_at": time.Now().Add(15 * time.Minute)})
		case "results":
			_, _ = w.Write([]byte(`{"findings_created":1}`))
		case "evaluate":
			_, _ = w.Write([]byte(`{"run_id":"run-1","verdict":"pass"}`))
		}
	}))
	t.Cleanup(srv.Close)
	getenv, client := githubEnv(t, srv.URL)
	cfg := ConfigFromEnv(getenv)
	cfg.HTTPClient = client
	r, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	takeWaits()
	return r
}

func smallReport() *ctis.Report {
	return &ctis.Report{Version: "1.0", Tool: &ctis.Tool{Name: "semgrep"}}
}

func TestUploadRetriesTransientFailures(t *testing.T) {
	s := &scripted{script: map[string][]int{"results": {503, 502}}}
	r := s.server(t)
	if _, err := r.Upload(context.Background(), smallReport()); err != nil {
		t.Fatal(err)
	}
	if s.calls["results"] != 3 || len(takeWaits()) != 2 {
		t.Fatalf("results calls %d", s.calls["results"])
	}
}

func TestNoRetryOnAClientError(t *testing.T) {
	s := &scripted{script: map[string][]int{"results": {400}, "evaluate": {409}}}
	r := s.server(t)
	if _, err := r.Upload(context.Background(), smallReport()); err == nil {
		t.Fatal("400 accepted")
	}
	if _, err := r.Evaluate(context.Background(), 0); err == nil {
		t.Fatal("409 accepted")
	}
	if s.calls["results"] != 1 || s.calls["evaluate"] != 1 || len(takeWaits()) != 0 {
		t.Fatalf("a client error was repeated: %v", s.calls)
	}
}

func TestRetriesAreBounded(t *testing.T) {
	s := &scripted{script: map[string][]int{"results": {500, 500, 500, 500, 500}}}
	r := s.server(t)
	var se *StatusError
	if _, err := r.Upload(context.Background(), smallReport()); !errors.As(err, &se) || se.Status != 500 {
		t.Fatalf("%v", err)
	}
	if s.calls["results"] != 1+defaultRetries {
		t.Fatalf("results calls %d, want %d", s.calls["results"], 1+defaultRetries)
	}
}

// The verdict is asked again after a lost or failed answer (the first
// verdict is final, so the answer is the same), never after a verdict.
func TestEvaluateRetriesOnlyWithoutAVerdict(t *testing.T) {
	s := &scripted{script: map[string][]int{"evaluate": {500}}}
	r := s.server(t)
	v, err := r.Evaluate(context.Background(), 0)
	if err != nil || v.Verdict != "pass" || s.calls["evaluate"] != 2 {
		t.Fatalf("%v %v calls %d", v, err, s.calls["evaluate"])
	}
	if _, err := r.Evaluate(context.Background(), 0); err != nil || s.calls["evaluate"] != 3 {
		t.Fatalf("a verdict was asked twice: calls %d", s.calls["evaluate"])
	}
}

// The job's OIDC token is single use: the exchange is repeated only when
// the rate limiter (429, honouring Retry-After) or an unavailable platform
// answered, never after a 5xx that may have spent the token.
func TestExchangeRetries(t *testing.T) {
	s := &scripted{script: map[string][]int{"exchange": {429}}, after: map[string]string{"exchange": "7"}}
	r := s.server(t)
	if _, err := r.Evaluate(context.Background(), 0); err != nil {
		t.Fatal(err)
	}
	if w := takeWaits(); s.calls["exchange"] != 2 || len(w) != 1 || w[0] != 7*time.Second {
		t.Fatalf("exchange calls %d waits %v", s.calls["exchange"], w)
	}
	s2 := &scripted{script: map[string][]int{"exchange": {502}}}
	r2 := s2.server(t)
	if _, err := r2.Evaluate(context.Background(), 0); err == nil || s2.calls["exchange"] != 1 {
		t.Fatalf("exchange after 502 repeated: %v calls %d", err, s2.calls["exchange"])
	}
}

func TestRetryable(t *testing.T) {
	dial := &net.OpError{Op: "dial", Err: errors.New("connection refused")}
	read := &net.OpError{Op: "read", Err: errors.New("reset")}
	for _, c := range []struct {
		kind   requestKind
		status int
		err    error
		want   bool
	}{
		{kindExchange, 0, dial, true},
		{kindExchange, 0, read, false},
		{kindExchange, 503, nil, true},
		{kindExchange, 500, nil, false},
		{kindUpload, 0, read, true},
		{kindUpload, 0, context.Canceled, false},
		{kindUpload, 504, nil, true},
		{kindUpload, 429, nil, true},
		{kindUpload, 413, nil, false},
		{kindEvaluate, 401, nil, false},
	} {
		if got := retryable(c.kind, c.status, c.err); got != c.want {
			t.Errorf("%v %d %v: %v", c.kind, c.status, c.err, got)
		}
	}
	for n := 1; n <= 10; n++ {
		if d := backoff(n, ""); d <= 0 || d > 30*time.Second+30*time.Second/4 {
			t.Errorf("backoff(%d) = %s", n, d)
		}
	}
	if d := backoff(1, "600"); d != maxRetryAfter {
		t.Errorf("a Retry-After past the bound waits %s, want the bound %s", d, maxRetryAfter)
	}
}

// A large report goes gzip-compressed (the platform decompresses ingest
// bodies); a small one as is.
func TestUploadCompressesLargeReports(t *testing.T) {
	s := &scripted{}
	r := s.server(t)
	big := smallReport()
	for i := 0; i < 200; i++ {
		big.Findings = append(big.Findings, ctis.Finding{Title: strings.Repeat("x", 64), RuleID: "r"})
	}
	if _, err := r.Upload(context.Background(), smallReport()); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Upload(context.Background(), big); err != nil {
		t.Fatal(err)
	}
	if len(s.encoding) != 2 || s.encoding[0] != "" || s.encoding[1] != "gzip" {
		t.Fatalf("encodings %q", s.encoding)
	}
	zr, err := gzip.NewReader(strings.NewReader(string(s.bodies[1])))
	if err != nil {
		t.Fatal(err)
	}
	var body map[string]json.RawMessage
	if err := json.NewDecoder(zr).Decode(&body); err != nil || body["report"] == nil {
		t.Fatalf("gzip body: %v", err)
	}
}

func TestTuningFromEnvironment(t *testing.T) {
	env := map[string]string{EnvRetries: "0", EnvUploadTimeout: "15m"}
	c := ConfigFromEnv(func(k string) string { return env[k] })
	c.normalize()
	if c.Retries != 0 || c.UploadTimeout != 15*time.Minute {
		t.Fatalf("%d %s", c.Retries, c.UploadTimeout)
	}
	env = map[string]string{EnvRetries: "99", EnvUploadTimeout: "1ms"}
	c = ConfigFromEnv(func(k string) string { return env[k] })
	c.normalize()
	if c.Retries != defaultRetries || c.UploadTimeout != 5*time.Minute || c.RequestTimeout != 30*time.Second {
		t.Fatalf("out-of-range values used: %d %s", c.Retries, c.UploadTimeout)
	}
}
