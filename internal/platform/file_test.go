package platform

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// fileServer is a stand-in platform for file uploads: each results request
// gets the next scripted answer (201 with reply once the script is used up).
type fileServer struct {
	mu        sync.Mutex
	script    []int
	after     string // Retry-After on scripted answers
	reply     string
	replayed  bool
	refuse    bool // the exchange answers 401
	exchanges int
	keys      []string
	bodies    [][]byte
	lengths   []int64
	types     []string
	queries   []string
}

func (s *fileServer) run(t *testing.T) *Run {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.mu.Lock()
		defer s.mu.Unlock()
		switch {
		case strings.HasSuffix(r.URL.Path, "/exchange"):
			s.exchanges++
			if s.refuse {
				w.WriteHeader(http.StatusUnauthorized)
				_, _ = io.WriteString(w, `{"code":"CI_TOKEN_NOT_TRUSTED","message":"The CI token was not accepted: no trust configuration admits this repository."}`)
				return
			}
			_, _ = io.WriteString(w, `{"run_id":"run-7","token":"`+runToken+`","expires_at":"`+time.Now().Add(15*time.Minute).Format(time.RFC3339)+`","repository":"github.com/acme/app","commit_sha":"c0ffee"}`)
		case strings.HasSuffix(r.URL.Path, "/runs/run-7/results"):
			if r.Header.Get("Authorization") != "Bearer "+runToken {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			body, _ := io.ReadAll(r.Body)
			s.keys = append(s.keys, r.Header.Get("Idempotency-Key"))
			s.bodies = append(s.bodies, body)
			s.lengths = append(s.lengths, r.ContentLength)
			s.types = append(s.types, r.Header.Get("Content-Type"))
			s.queries = append(s.queries, r.URL.RawQuery)
			if len(s.script) > 0 {
				st := s.script[0]
				s.script = s.script[1:]
				if s.after != "" {
					w.Header().Set("Retry-After", s.after)
				}
				w.WriteHeader(st)
				_, _ = io.WriteString(w, `{"code":"X","message":"scripted"}`)
				return
			}
			if s.replayed {
				w.Header().Set("Idempotent-Replayed", "true")
			}
			w.WriteHeader(http.StatusCreated)
			_, _ = io.WriteString(w, s.reply)
		default:
			http.NotFound(w, r)
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
	return r
}

func writeFile(t *testing.T, content string) File {
	t.Helper()
	p := filepath.Join(t.TempDir(), "report.sarif")
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return File{Path: p, Size: int64(len(content)), SHA256: sha256.Sum256([]byte(content)), ContentType: "application/sarif+json"}
}

const sarifDoc = `{"version":"2.1.0","runs":[]}`

func TestUploadFileSendsTheFileWithARunBoundKey(t *testing.T) {
	s := &fileServer{reply: `{"findings_created":3,"findings_updated":2,"findings_skipped":1,"findings_dropped_out_of_scope":4,` +
		`"errors":["store_failed"],"files":[{"name":"results","format":"sarif"}]}`}
	r := s.run(t)
	f := writeFile(t, sarifDoc)
	rec, err := r.UploadFile(context.Background(), f)
	if err != nil {
		t.Fatal(err)
	}
	if len(s.bodies) != 1 || !bytes.Equal(s.bodies[0], []byte(sarifDoc)) {
		t.Fatalf("body sent: %q", s.bodies)
	}
	if s.lengths[0] != f.Size || s.types[0] != "application/sarif+json" {
		t.Errorf("length %d type %q: the file goes up as-is with its length", s.lengths[0], s.types[0])
	}
	if want := IdempotencyKey("run-7", f.SHA256); s.keys[0] != want || len(want) > 128 {
		t.Errorf("key %q, want %q (at most 128 characters)", s.keys[0], want)
	}
	if s.queries[0] != "" {
		t.Errorf("query %q: an upload never declares coverage", s.queries[0])
	}
	if rec.New != 3 || rec.StillDetected != 2 || rec.Skipped != 1 || rec.Dropped != 4 || rec.Failed != 1 || rec.Replayed {
		t.Errorf("receipt %+v", rec)
	}
	if rec.Resolved != nil || rec.Reopened != nil {
		t.Errorf("resolved/reopened must stay unknown when the platform does not report them: %+v", rec)
	}
}

func TestIdempotencyKeyIsBoundToRunAndContent(t *testing.T) {
	a, b := sha256.Sum256([]byte("a")), sha256.Sum256([]byte("b"))
	if k := IdempotencyKey("run-1", a); !strings.HasPrefix(k, "ocu1-") || len(k) != 69 {
		t.Errorf("key %q: ocu1- and a hex SHA-256", k)
	}
	if IdempotencyKey("run-1", sha256.Sum256([]byte("a"))) != IdempotencyKey("run-1", a) {
		t.Error("not stable")
	}
	if IdempotencyKey("run-1", a) == IdempotencyKey("run-2", a) || IdempotencyKey("run-1", a) == IdempotencyKey("run-1", b) {
		t.Error("the key must change with the run and with the content")
	}
}

func TestUploadFileRetriesWithTheSameKey(t *testing.T) {
	takeWaits()
	// 503, then 409 while the first request is still being imported, then
	// the stored answer replayed.
	s := &fileServer{script: []int{503, 409}, after: "2", replayed: true, reply: `{"findings_created":1}`}
	r := s.run(t)
	f := writeFile(t, sarifDoc)
	rec, err := r.UploadFile(context.Background(), f)
	if err != nil {
		t.Fatal(err)
	}
	if len(s.keys) != 3 || s.keys[0] != s.keys[1] || s.keys[1] != s.keys[2] {
		t.Fatalf("keys %q: every attempt carries the same key", s.keys)
	}
	for i, b := range s.bodies {
		if !bytes.Equal(b, []byte(sarifDoc)) {
			t.Errorf("attempt %d sent %q: the file is read again for each attempt", i+1, b)
		}
	}
	if !rec.Replayed {
		t.Error("a replayed answer is reported as such")
	}
	if w := takeWaits(); len(w) != 2 || w[0] != 2*time.Second || w[1] != 2*time.Second {
		t.Errorf("waits %v: Retry-After is honoured", w)
	}
	if s.exchanges != 1 {
		t.Errorf("%d exchanges: one run for every attempt", s.exchanges)
	}
}

func TestUploadFileDoesNotRetryARefusal(t *testing.T) {
	for _, st := range []int{400, 409, 413, 422} {
		s := &fileServer{script: []int{st}}
		r := s.run(t)
		_, err := r.UploadFile(context.Background(), writeFile(t, sarifDoc))
		var se *StatusError
		if !errors.As(err, &se) || se.Status != st {
			t.Fatalf("%d: err %v", st, err)
		}
		if len(s.keys) != 1 {
			t.Errorf("%d: %d attempts (a 409 without Retry-After, a 422 key reuse or another refusal is final)", st, len(s.keys))
		}
	}
}

func TestUploadFileRefusedTokenIsNoRun(t *testing.T) {
	s := &fileServer{refuse: true}
	r := s.run(t)
	_, err := r.UploadFile(context.Background(), writeFile(t, sarifDoc))
	if !errors.Is(err, ErrNoRun) || !errors.Is(err, ErrRefused) {
		t.Fatalf("err %v: want ErrNoRun and ErrRefused", err)
	}
	if len(s.bodies) != 0 {
		t.Error("nothing is sent without a run")
	}
	if strings.Contains(err.Error(), runToken) {
		t.Error("the token is in the error")
	}
}

func TestUploadFileRefusesTooLargeAndChangedFiles(t *testing.T) {
	s := &fileServer{reply: `{}`}
	r := s.run(t)
	f := writeFile(t, sarifDoc)
	big := f
	big.Size = MaxFileBytes + 1
	if _, err := r.UploadFile(context.Background(), big); err == nil {
		t.Error("a file over the limit must be refused before sending")
	}
	changed := f
	changed.Size--
	if _, err := r.UploadFile(context.Background(), changed); !errors.Is(err, ErrFileChanged) {
		t.Errorf("err %v: a file whose size changed is refused", err)
	}
	if len(s.bodies) != 0 {
		t.Errorf("%d requests sent", len(s.bodies))
	}
}

func TestUploadFileReadsReceiptCounts(t *testing.T) {
	s := &fileServer{reply: `{"findings_created":1,"receipt":{"reactivated":2,"closed":0},` +
		`"files":[{"name":"a.json","format":"trivy"},{"name":"b.txt","error":{"kind":"unknown_format","message":"unknown format\u001b[31m"}}]}`}
	r := s.run(t)
	rec, err := r.UploadFile(context.Background(), writeFile(t, sarifDoc))
	if err != nil {
		t.Fatal(err)
	}
	if rec.Reopened == nil || *rec.Reopened != 2 || rec.Resolved == nil || *rec.Resolved != 0 {
		t.Errorf("receipt %+v", rec)
	}
	if rec.Failed != 1 || len(rec.Files) != 2 || strings.ContainsRune(rec.Files[1].Error, 0x1b) {
		t.Errorf("files %+v: a file the platform could not read fails, its message sanitized", rec.Files)
	}
}
