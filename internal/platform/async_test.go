package platform

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

const testUploadID = "0b9f2c1e-7d4a-4c1b-9a53-1f2e3d4c5b6a"

// asyncServer is a stand-in platform that answers an upload with a
// scripted status and body, a poll with the next scripted answer, and an
// evaluate with the next scripted answer.
type asyncServer struct {
	mu       sync.Mutex
	upload   func() (int, string)
	poll     func(call int) (int, string)
	evaluate func(call int) (int, string, string) // status, body, Retry-After
	calls    map[string]int
	queries  []string
	auth     []string
}

// count and seen read the recorded requests under the same lock the handler
// writes them with: the client returns before the server goroutine is done.
func (s *asyncServer) count(key string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.calls[key]
}

func (s *asyncServer) seen() (queries, auth []string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.queries...), append([]string(nil), s.auth...)
}

func (s *asyncServer) run(t *testing.T) *Run {
	t.Helper()
	s.calls = map[string]int{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.mu.Lock()
		defer s.mu.Unlock()
		_, _ = io.Copy(io.Discard, r.Body)
		switch {
		case strings.HasSuffix(r.URL.Path, "/exchange"):
			_ = json.NewEncoder(w).Encode(map[string]any{"run_id": "run-7", "token": runToken, "expires_at": time.Now().Add(15 * time.Minute)})
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/runs/run-7/results"):
			s.calls["upload"]++
			st, body := s.upload()
			w.WriteHeader(st)
			_, _ = io.WriteString(w, body)
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/runs/run-7/results/"+testUploadID):
			s.calls["poll"]++
			s.queries = append(s.queries, r.URL.RawQuery)
			s.auth = append(s.auth, r.Header.Get("Authorization"))
			st, body := s.poll(s.calls["poll"])
			w.WriteHeader(st)
			_, _ = io.WriteString(w, body)
		case strings.HasSuffix(r.URL.Path, "/runs/run-7/evaluate"):
			s.calls["evaluate"]++
			st, body, ra := s.evaluate(s.calls["evaluate"])
			if ra != "" {
				w.Header().Set("Retry-After", ra)
			}
			w.WriteHeader(st)
			_, _ = io.WriteString(w, body)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	getenv, client := githubEnv(t, srv.URL)
	cfg := ConfigFromEnv(getenv)
	cfg.HTTPClient = client
	cfg.UploadTimeout = 2 * time.Second
	r, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	takeWaits()
	return r
}

const accepted = `{"upload_id":"` + testUploadID + `","status":"queued","location":"/api/v1/ci/runs/run-7/results/` + testUploadID + `"}`

const appliedBody = `{"upload_id":"` + testUploadID + `","status":"applied","findings_created":3,"findings_updated":2,"assets_created":1,"assets_updated":4,` +
	`"known":[{"index":1,"decision":"false_positive","finding_id":"f1"},{"index":9,"decision":"x","finding_id":"f9"}],"known_total":2}`

func TestUploadAcceptedThenPolled(t *testing.T) {
	cases := []struct {
		name       string
		poll       func(call int) (int, string)
		wantErr    string
		wantCreate int
		wantKnown  int
		incomplete bool
		polls      int
	}{
		{"applied after queued and processing", func(c int) (int, string) {
			switch c {
			case 1:
				return 200, `{"status":"queued"}`
			case 2:
				return 200, `{"status":"processing"}`
			}
			return 200, appliedBody
		}, "", 3, 1, false, 3},
		{"failed names the code", func(int) (int, string) {
			return 200, `{"status":"failed","error_code":"report_out_of_scope"}`
		}, "report_out_of_scope", 0, 0, false, 1},
		{"failed code is sanitized", func(int) (int, string) {
			return 200, `{"status":"failed","error_code":"bad\u001b[31m"}`
		}, "bad [31m", 0, 0, false, 1},
		{"unknown upload leaves the list incomplete", func(int) (int, string) {
			return 404, `{"code":"NOT_FOUND","message":"no"}`
		}, "", 0, 0, true, 1},
		{"never applied within the upload timeout", func(int) (int, string) {
			return 200, `{"status":"processing"}`
		}, "", 0, 0, true, -1},
		{"transport-level 5xx after the retries", func(int) (int, string) {
			return 502, `{}`
		}, "", 0, 0, true, 1 + defaultRetries},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			s := &asyncServer{upload: func() (int, string) { return 202, accepted }, poll: c.poll}
			r := s.run(t)
			if c.polls == -1 {
				r.cfg.UploadTimeout = 100 * time.Millisecond
			}
			res, err := r.Upload(context.Background(), reportWith(3))
			if c.wantErr != "" {
				var uf *UploadFailedError
				if !errors.As(err, &uf) || !strings.Contains(err.Error(), c.wantErr) || strings.ContainsRune(err.Error(), 0x1b) {
					t.Fatalf("error %v", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("a stored upload must not fail: %v", err)
			}
			if res.FindingsCreated != c.wantCreate || len(res.Known) != c.wantKnown || res.KnownIncomplete != c.incomplete {
				t.Fatalf("%+v", res)
			}
			if c.wantCreate > 0 && (res.FindingsUpdated != 2 || res.AssetsCreated != 1 || res.AssetsUpdated != 4 || res.Known[0].FindingID != "f1") {
				t.Fatalf("counts not read from the poll: %+v", res)
			}
			if s.count("poll") == 0 || (c.polls > 0 && s.count("poll") != c.polls) {
				t.Fatalf("polls %d, want %d", s.count("poll"), c.polls)
			}
			queries, auth := s.seen()
			for i := range queries {
				if queries[i] != "wait=10" || auth[i] != "Bearer "+runToken {
					t.Fatalf("poll %d: query %q auth %q", i, queries[i], auth[i])
				}
			}
		})
	}
}

// A platform that answers 201 with the result needs no poll.
func TestUploadCreatedAnswerStillWorks(t *testing.T) {
	s := &asyncServer{upload: func() (int, string) {
		return 201, `{"findings_created":5,"known":[{"index":0,"decision":"duplicate","finding_id":"f"}]}`
	}, poll: func(int) (int, string) { return 500, "" }}
	r := s.run(t)
	res, err := r.Upload(context.Background(), reportWith(2))
	if err != nil || res.FindingsCreated != 5 || len(res.Known) != 1 || res.KnownIncomplete || s.count("poll") != 0 {
		t.Fatalf("%+v %v polls %d", res, err, s.count("poll"))
	}
}

// A reply naming a hostile upload id is never put into a path.
func TestUploadRefKeepsOnlyAPlainID(t *testing.T) {
	for in, want := range map[string]string{testUploadID: testUploadID, "../x": "", "a/b": "", "": "", strings.Repeat("a", 65): ""} {
		if got := uploadRef(in, ""); got != want {
			t.Errorf("uploadRef(%q) = %q, want %q", in, got, want)
		}
	}
	if got := uploadRef("", "/api/v1/ci/runs/r/results/"+testUploadID); got != testUploadID {
		t.Errorf("location fallback %q", got)
	}
}

func TestUploadFileAcceptedThenPolled(t *testing.T) {
	fileApplied := `{"status":"applied","findings_created":4,"findings_updated":1,"vex_stored":2,` +
		`"files":[{"name":"a.sarif","format":"sarif"},{"name":"b.txt","error":{"kind":"unknown_format","message":"no","line":1,"column":2}}]}`
	cases := []struct {
		name       string
		poll       func(int) (int, string)
		wantErr    string
		incomplete bool
	}{
		{"applied", func(c int) (int, string) {
			if c == 1 {
				return 200, `{"status":"processing"}`
			}
			return 200, fileApplied
		}, "", false},
		{"failed", func(int) (int, string) { return 200, `{"status":"failed","error_code":"unreadable"}` }, "unreadable", false},
		{"not applied in time", func(int) (int, string) { return 404, `{}` }, "", true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			s := &asyncServer{upload: func() (int, string) { return 202, accepted }, poll: c.poll}
			r := s.run(t)
			rec, err := r.UploadFile(context.Background(), writeFile(t, sarifDoc))
			if c.wantErr != "" {
				var uf *UploadFailedError
				if !errors.As(err, &uf) || !strings.Contains(err.Error(), c.wantErr) {
					t.Fatalf("error %v", err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if rec.Incomplete != c.incomplete {
				t.Fatalf("%+v", rec)
			}
			if !c.incomplete && (rec.New != 4 || rec.StillDetected != 1 || rec.VEXStored != 2 || len(rec.Files) != 2 || rec.Failed != 1) {
				t.Fatalf("receipt not read from the poll: %+v", rec)
			}
			if c.incomplete && (rec.New != 0 || len(rec.Files) != 0) {
				t.Fatalf("%+v", rec)
			}
		})
	}
}

const pendingBody = `{"code":"INGEST_PENDING","message":"uploads are still being applied"}`

func TestEvaluateWaitsForPendingUploads(t *testing.T) {
	cases := []struct {
		name      string
		gate      time.Duration
		answer    func(call int) (int, string, string)
		wantErr   bool
		wantCalls int
		wantWaits []time.Duration
	}{
		{"retried until the verdict, honouring Retry-After", 0, func(c int) (int, string, string) {
			if c <= 2 {
				return 503, pendingBody, "7"
			}
			return 200, `{"run_id":"run-7","verdict":"pass"}`, ""
		}, false, 3, []time.Duration{7 * time.Second, 7 * time.Second}},
		{"each wait is capped at 30s and defaults to 5s", 0, func(c int) (int, string, string) {
			switch c {
			case 1:
				return 503, pendingBody, "120"
			case 2:
				return 503, pendingBody, ""
			}
			return 200, `{"run_id":"run-7","verdict":"pass"}`, ""
		}, false, 3, []time.Duration{30 * time.Second, 5 * time.Second}},
		{"gives up when the budget is used", 70 * time.Second, func(int) (int, string, string) {
			return 503, pendingBody, "30"
		}, true, 3, []time.Duration{30 * time.Second, 30 * time.Second}},
		{"a zero budget asks once", -1, func(int) (int, string, string) {
			return 503, pendingBody, "1"
		}, true, 1, nil},
		{"another 503 keeps the retry count", 0, func(int) (int, string, string) {
			return 503, `{"message":"busy"}`, ""
		}, true, 1 + defaultRetries, nil},
		{"a 4xx is never retried", 0, func(int) (int, string, string) {
			return 422, pendingBody, ""
		}, true, 1, nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			s := &asyncServer{evaluate: c.answer}
			r := s.run(t)
			if c.gate != 0 {
				r.cfg.GateWait = c.gate
			}
			v, err := r.Evaluate(context.Background(), 0)
			if (err != nil) != c.wantErr || (err == nil && v.Verdict != "pass") {
				t.Fatalf("%v %v", v, err)
			}
			if s.count("evaluate") != c.wantCalls {
				t.Fatalf("calls %d, want %d", s.count("evaluate"), c.wantCalls)
			}
			if c.wantWaits != nil {
				got := takeWaits()
				if len(got) != len(c.wantWaits) {
					t.Fatalf("waits %v, want %v", got, c.wantWaits)
				}
				for i := range got {
					if got[i] != c.wantWaits[i] {
						t.Fatalf("waits %v, want %v", got, c.wantWaits)
					}
				}
			}
		})
	}
}

func TestGateWaitFromEnvironment(t *testing.T) {
	for in, want := range map[string]time.Duration{"": 0, "90": 90 * time.Second, "5m": 5 * time.Minute, "60m": time.Hour,
		"61m": 0, "-5": 0, "abc": 0} {
		c := ConfigFromEnv(func(k string) string {
			if k == EnvGateWait {
				return in
			}
			return ""
		})
		if c.GateWait != want {
			t.Errorf("%q: %s, want %s", in, c.GateWait, want)
		}
		wantEff := want
		if want == 0 {
			wantEff = defaultGateWait
		}
		if c.gateWait() != wantEff {
			t.Errorf("%q: effective %s, want %s", in, c.gateWait(), wantEff)
		}
	}
	c := ConfigFromEnv(func(k string) string {
		if k == EnvGateWait {
			return "0"
		}
		return ""
	})
	if c.gateWait() != 0 {
		t.Errorf("0 means no wait, got %s", c.gateWait())
	}
}
