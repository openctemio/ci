package platform

import (
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/openctemio/ctis"
)

// uploadServer is a stand-in platform whose results and known replies the
// test writes; it records every uploaded report.
type uploadServer struct {
	mu      sync.Mutex
	results func(rep *ctis.Report, call int) (int, string)
	known   func(cursor string) (int, string)
	reports []*ctis.Report
	calls   map[string]int
}

func (u *uploadServer) run(t *testing.T) *Run {
	t.Helper()
	u.calls = map[string]int{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u.mu.Lock()
		defer u.mu.Unlock()
		key := r.URL.Path[strings.LastIndex(r.URL.Path, "/")+1:]
		u.calls[key]++
		var body io.Reader = r.Body
		if r.Header.Get("Content-Encoding") == "gzip" {
			zr, err := gzip.NewReader(r.Body)
			if err != nil {
				t.Error(err)
				return
			}
			body = zr
		}
		switch key {
		case "exchange":
			_ = json.NewEncoder(w).Encode(map[string]any{"run_id": "run-1", "token": runToken, "expires_at": time.Now().Add(15 * time.Minute)})
		case "results":
			var req struct {
				Report *ctis.Report `json:"report"`
			}
			if err := json.NewDecoder(body).Decode(&req); err != nil {
				t.Error(err)
				return
			}
			status, reply := u.results(req.Report, u.calls[key])
			if status < 300 {
				u.reports = append(u.reports, req.Report)
			}
			w.WriteHeader(status)
			_, _ = io.WriteString(w, reply)
		case "known":
			var req struct {
				Cursor string `json:"cursor"`
			}
			_ = json.NewDecoder(body).Decode(&req)
			if u.known == nil {
				http.NotFound(w, r)
				return
			}
			status, reply := u.known(req.Cursor)
			w.WriteHeader(status)
			_, _ = io.WriteString(w, reply)
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

func reportWith(n int) *ctis.Report {
	r := &ctis.Report{Version: "1.0", Tool: &ctis.Tool{Name: "trivy"}}
	for i := 0; i < n; i++ {
		r.Findings = append(r.Findings, ctis.Finding{RuleID: fmt.Sprintf("r%d", i), Title: "t"})
	}
	return r
}

func knownJSON(indexes ...int) string {
	var b strings.Builder
	b.WriteString("[")
	for i, x := range indexes {
		if i > 0 {
			b.WriteString(",")
		}
		fmt.Fprintf(&b, `{"index":%d,"decision":"false_positive","finding_id":"00000000-0000-0000-0000-%012d"}`, x, x)
	}
	b.WriteString("]")
	return b.String()
}

func setPartLimits(t *testing.T, bytes, findings int) {
	t.Helper()
	pb, pf := partBytes, partFindings
	partBytes, partFindings = bytes, findings
	t.Cleanup(func() { partBytes, partFindings = pb, pf })
}

// A stored report whose reply lists ~100k decided results (more than the 8 MB
// the client used to read) counts as uploaded, with every decided result.
func TestUploadReadsALargeReply(t *testing.T) {
	setPartLimits(t, 64<<20, 200000) // one request, to exercise the reply itself
	const n = 100000
	idx := make([]int, n)
	for i := range idx {
		idx[i] = i
	}
	reply := `{"findings_created":7,"known":` + knownJSON(idx...) + `,"extra":{"ignored":[1,2,3]}}`
	if len(reply) <= maxBody {
		t.Fatalf("reply of %d bytes does not exceed the old limit", len(reply))
	}
	u := &uploadServer{results: func(*ctis.Report, int) (int, string) { return http.StatusCreated, reply }}
	res, err := u.run(t).Upload(context.Background(), reportWith(n))
	if err != nil {
		t.Fatalf("a stored report counted as failed: %v", err)
	}
	if res.FindingsCreated != 7 || len(res.Known) != n || res.KnownIncomplete || res.Parts != 1 {
		t.Fatalf("created %d, known %d, incomplete %v, parts %d", res.FindingsCreated, len(res.Known), res.KnownIncomplete, res.Parts)
	}
}

// A 2xx reply that cannot be read in full (cut off, over the bound, not
// JSON) still means stored: only the list of decided results is incomplete.
func TestUploadStoredDespiteAnUnreadableReply(t *testing.T) {
	for name, reply := range map[string]string{
		"cut":      `{"findings_created":3,"known":[{"index":0,"decision":"false_positive"},{"ind`,
		"not json": `<html>proxy</html>`,
		"huge":     `{"findings_created":3,"known":[{"index":0,"decision":"false_positive"}],"pad":"` + strings.Repeat("x", replyBase+10<<10) + `"}`,
	} {
		u := &uploadServer{results: func(*ctis.Report, int) (int, string) { return http.StatusCreated, reply }}
		res, err := u.run(t).Upload(context.Background(), reportWith(2))
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if !res.KnownIncomplete || u.calls["results"] != 1 {
			t.Fatalf("%s: incomplete %v, %d upload(s)", name, res.KnownIncomplete, u.calls["results"])
		}
		if name != "not json" && (res.FindingsCreated != 3 || len(res.Known) != 1) {
			t.Fatalf("%s: created %d known %v", name, res.FindingsCreated, res.Known)
		}
	}
}

// Decided results outside the report, and repeated ones, are dropped.
func TestUploadKnownIsBounded(t *testing.T) {
	u := &uploadServer{results: func(*ctis.Report, int) (int, string) {
		return http.StatusCreated, `{"known":` + knownJSON(-1, 0, 0, 2, 3, 99) + `}`
	}}
	res, err := u.run(t).Upload(context.Background(), reportWith(3))
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Known) != 2 || res.Known[0].Index != 0 || res.Known[1].Index != 2 {
		t.Fatalf("%+v", res.Known)
	}
}

// A platform that pages the decided results: the client follows the cursor.
// An older platform without the known endpoint, or one that cuts the list
// short without a cursor, leaves the list incomplete but the upload stored.
func TestUploadFollowsKnownPages(t *testing.T) {
	u := &uploadServer{
		results: func(*ctis.Report, int) (int, string) {
			return http.StatusCreated, `{"findings_created":5,"known":` + knownJSON(0, 1) + `,"known_total":5,"known_next":"c1"}`
		},
		known: func(cursor string) (int, string) {
			switch cursor {
			case "c1":
				return http.StatusOK, `{"known":` + knownJSON(1, 2, 3) + `,"next":"c2"}`
			case "c2":
				return http.StatusOK, `{"known":` + knownJSON(4) + `}`
			}
			return http.StatusBadRequest, `{"message":"bad cursor"}`
		},
	}
	res, err := u.run(t).Upload(context.Background(), reportWith(5))
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Known) != 5 || res.KnownIncomplete || u.calls["known"] != 2 {
		t.Fatalf("known %d incomplete %v pages %d", len(res.Known), res.KnownIncomplete, u.calls["known"])
	}

	old := &uploadServer{results: func(*ctis.Report, int) (int, string) {
		return http.StatusCreated, `{"known":` + knownJSON(0) + `,"known_next":"c1"}`
	}}
	if res, err := old.run(t).Upload(context.Background(), reportWith(5)); err != nil || !res.KnownIncomplete || len(res.Known) != 1 {
		t.Fatalf("older platform: %v %+v", err, res)
	}

	capped := &uploadServer{results: func(*ctis.Report, int) (int, string) {
		return http.StatusCreated, `{"known":` + knownJSON(0) + `,"known_truncated":true}`
	}}
	if res, err := capped.run(t).Upload(context.Background(), reportWith(5)); err != nil || !res.KnownIncomplete {
		t.Fatalf("capped list: %v %+v", err, res)
	}
}

// A large report goes up in parts: every finding exactly once, in order,
// each part a complete report, the dependencies once, and decided results
// mapped back to their index in the whole report.
func TestUploadSplitsALargeReport(t *testing.T) {
	setPartLimits(t, 4<<10, 50)
	rep := reportWith(300)
	rep.Metadata.SourceType = "ci"
	rep.Dependencies = []ctis.Dependency{{Name: "lodash", Version: "4.17.15"}}
	u := &uploadServer{results: func(r *ctis.Report, _ int) (int, string) {
		return http.StatusCreated, `{"findings_created":` + fmt.Sprint(len(r.Findings)) + `,"known":` + knownJSON(0) + `}`
	}}
	res, err := u.run(t).Upload(context.Background(), rep)
	if err != nil {
		t.Fatal(err)
	}
	if res.Parts < 2 || res.Parts != len(u.reports) || res.FindingsCreated != 300 {
		t.Fatalf("parts %d (%d stored), created %d", res.Parts, len(u.reports), res.FindingsCreated)
	}
	next, deps := 0, 0
	for i, p := range u.reports {
		if p.Tool == nil || p.Tool.Name != "trivy" || p.Metadata.SourceType != "ci" {
			t.Fatalf("part %d lacks the report's tool or metadata", i)
		}
		deps += len(p.Dependencies)
		if i > 0 && len(p.Dependencies) > 0 {
			t.Fatalf("dependencies in part %d", i)
		}
		if b, _ := json.Marshal(p); len(b) > partBytes || len(p.Findings) > partFindings {
			t.Fatalf("part %d: %d bytes, %d findings", i, len(b), len(p.Findings))
		}
		if res.Known[i].Index != next {
			t.Fatalf("known %d maps to %d, want %d", i, res.Known[i].Index, next)
		}
		for _, f := range p.Findings {
			if f.RuleID != fmt.Sprintf("r%d", next) {
				t.Fatalf("finding %s where r%d was expected", f.RuleID, next)
			}
			next++
		}
	}
	if next != 300 || deps != 1 {
		t.Fatalf("%d findings, %d dependencies uploaded", next, deps)
	}
}

// A platform with a lower body limit (413) gets the part again in halves.
func TestUploadSplitsOnTooLarge(t *testing.T) {
	u := &uploadServer{results: func(r *ctis.Report, _ int) (int, string) {
		if len(r.Findings) > 10 {
			return http.StatusRequestEntityTooLarge, `{"code":"PAYLOAD_TOO_LARGE","message":"too large"}`
		}
		return http.StatusCreated, `{"findings_created":` + fmt.Sprint(len(r.Findings)) + `,"known":` + knownJSON(len(r.Findings)-1) + `}`
	}}
	res, err := u.run(t).Upload(context.Background(), reportWith(40))
	if err != nil {
		t.Fatal(err)
	}
	if res.FindingsCreated != 40 || res.Parts != 4 {
		t.Fatalf("created %d in %d parts", res.FindingsCreated, res.Parts)
	}
	for i, k := range res.Known {
		if k.Index != i*10+9 {
			t.Fatalf("known %+v", res.Known)
		}
	}

	never := &uploadServer{results: func(*ctis.Report, int) (int, string) {
		return http.StatusRequestEntityTooLarge, `{"message":"too large"}`
	}}
	_, err = never.run(t).Upload(context.Background(), reportWith(3))
	var se *StatusError
	if !errors.As(err, &se) || se.Status != http.StatusRequestEntityTooLarge || never.calls["results"] > maxRequests {
		t.Fatalf("%v after %d requests", err, never.calls["results"])
	}
}

func TestSplitReportLimits(t *testing.T) {
	small := reportWith(3)
	if parts, err := splitReport(small, 1<<20, 10); err != nil || len(parts) != 1 || parts[0].report != small {
		t.Fatalf("a small report must go up unchanged: %v %d", err, len(parts))
	}
	huge := reportWith(1)
	huge.Findings[0].Description = strings.Repeat("x", 8<<10)
	if _, err := splitReport(huge, 4<<10, 10); !errors.Is(err, ErrReportTooLarge) {
		t.Fatalf("one oversized finding: %v", err)
	}
	if _, err := splitReport(reportWith(maxRequests*2+1), 1<<20, 2); !errors.Is(err, ErrReportTooLarge) {
		t.Fatalf("too many parts: %v", err)
	}
	extras := reportWith(1)
	extras.Dependencies = []ctis.Dependency{{Name: strings.Repeat("d", 8<<10)}}
	if _, err := splitReport(extras, 4<<10, 10); !errors.Is(err, ErrReportTooLarge) {
		t.Fatalf("oversized dependencies: %v", err)
	}
}
