package platform

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"

	"github.com/openctemio/ctis"
)

// Upload limits. The platform accepts at most 50 MB (decompressed) per
// request and at most 200 reports per run.
var (
	// partBytes: a report whose JSON is larger goes up in parts. Each part
	// is a complete report carrying a share of the findings, so any
	// platform version accepts it, and findings are keyed by fingerprint,
	// so the parts add up to the whole report.
	partBytes = 24 << 20
	// partFindings bounds the findings of one part (the platform also
	// bounds the values one report may hold).
	partFindings = 10000
)

const (
	// maxRequests bounds the requests one report becomes, including the
	// splits of a part the platform refused as too large (413).
	maxRequests = 64
	// maxKnownPages bounds the pages of decided results read for one part.
	maxKnownPages = 1000
	// An upload reply is read up to replyBase plus replyPerFinding for
	// each finding of the part, at most maxReply: the reply lists decided
	// results, so it may grow with the report, but never without bound.
	replyBase       = 8 << 20
	replyPerFinding = 1 << 10
	maxReply        = 256 << 20
	// maxCursor bounds the cursor of the next page of decided results.
	maxCursor = 1024
	// maxLabel bounds the decision and finding id kept per decided result.
	maxLabel = 128
)

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
	// KnownIncomplete: the platform stored the report, but its list of
	// decided results could not be read in full (cut short, or an older
	// platform without paging). The job then keeps the remaining results in
	// its own output; the platform's verdict is not affected.
	KnownIncomplete bool `json:"-"`
	// Parts is the number of requests that carried the report (1 unless it
	// was large).
	Parts int `json:"-"`
}

// Known is one uploaded result OpenCTEM has already decided.
type Known struct {
	Index     int    `json:"index"`
	Decision  string `json:"decision"`
	FindingID string `json:"finding_id"`
}

// ErrReportTooLarge: a report cannot be cut into parts the platform
// accepts.
var ErrReportTooLarge = errors.New("the report is too large to upload")

// part is one request's share of a report: findings start at offset in
// the whole report.
type part struct {
	report *ctis.Report
	offset int
}

// Upload sends a report to the run, in parts when it is large.
//
// A 2xx reply means the platform stored the part, whatever the reply body
// holds: a reply that cannot be read in full only leaves the list of
// decided results incomplete, it never turns a stored report into a failed
// upload.
func (r *Run) Upload(ctx context.Context, report *ctis.Report) (*UploadResult, error) {
	if report == nil {
		return &UploadResult{}, nil
	}
	parts, err := splitReport(report, partBytes, partFindings)
	if err != nil {
		return nil, fmt.Errorf("upload results: %w", err)
	}
	u := &uploader{r: r, out: &UploadResult{}}
	for i, p := range parts {
		if err := u.send(ctx, p); err != nil {
			if len(parts) > 1 {
				return nil, fmt.Errorf("upload results (part %d of %d): %w", i+1, len(parts), err)
			}
			return nil, fmt.Errorf("upload results: %w", err)
		}
	}
	return u.out, nil
}

type uploader struct {
	r        *Run
	out      *UploadResult
	requests int
}

// send uploads one part. A part the platform refuses as too large (413) is
// split in two and sent again, so a platform with a lower limit still
// takes the report.
func (u *uploader) send(ctx context.Context, p part) error {
	if u.requests >= maxRequests {
		return fmt.Errorf("%w: more than %d requests", ErrReportTooLarge, maxRequests)
	}
	u.requests++
	reply := &uploadReply{n: len(p.report.Findings)}
	err := u.r.call(ctx, kindUpload, "results", map[string]any{"report": p.report}, reply)
	var se *StatusError
	if errors.As(err, &se) && se.Status == http.StatusRequestEntityTooLarge && len(p.report.Findings) > 1 {
		left, right := halve(p)
		if err := u.send(ctx, left); err != nil {
			return err
		}
		return u.send(ctx, right)
	}
	if err != nil {
		return err
	}
	u.out.Parts++
	u.out.FindingsCreated += reply.res.FindingsCreated
	u.out.FindingsUpdated += reply.res.FindingsUpdated
	u.out.AssetsCreated += reply.res.AssetsCreated
	u.out.AssetsUpdated += reply.res.AssetsUpdated

	seen := map[int]bool{}
	add := func(known []Known) {
		for _, k := range known {
			if !seen[k.Index] {
				seen[k.Index] = true
				k.Index += p.offset
				u.out.Known = append(u.out.Known, k)
			}
		}
	}
	add(reply.known)
	incomplete := reply.incomplete
	// Further pages of decided results, from a platform that pages them.
	for page, next := 0, reply.next; next != "" && !incomplete; page++ {
		if page >= maxKnownPages {
			incomplete = true
			break
		}
		pr := &uploadReply{n: len(p.report.Findings)}
		if err := u.r.call(ctx, kindUpload, "known", map[string]string{"cursor": next}, pr); err != nil {
			incomplete = true
			break
		}
		add(pr.known)
		incomplete, next = pr.incomplete, pr.next
	}
	u.out.KnownIncomplete = u.out.KnownIncomplete || incomplete
	return nil
}

// halve splits a part's findings in two; the first half keeps the
// report's other content.
func halve(p part) (part, part) {
	mid := len(p.report.Findings) / 2
	left := *p.report
	left.Findings = p.report.Findings[:mid]
	right := withoutExtras(p.report)
	right.Findings = p.report.Findings[mid:]
	return part{&left, p.offset}, part{right, p.offset + mid}
}

// withoutExtras is a copy of the report without findings and without the
// content that goes up once (dependencies, relationships, endpoints).
func withoutExtras(r *ctis.Report) *ctis.Report {
	c := *r
	c.Findings, c.Dependencies, c.Relationships, c.Endpoints = nil, nil, nil, nil
	return &c
}

// splitReport cuts a report into parts of at most maxBytes of JSON and
// maxFindings findings. A report within both limits is one part, unchanged.
// Every part carries the report's metadata, tool and assets; the first one
// also carries its dependencies, relationships and endpoints.
func splitReport(r *ctis.Report, maxBytes, maxFindings int) ([]part, error) {
	whole, err := json.Marshal(r)
	if err != nil {
		return nil, err
	}
	if len(whole) <= maxBytes && len(r.Findings) <= maxFindings {
		return []part{{r, 0}}, nil
	}
	size := func(v any) (int, error) {
		b, err := json.Marshal(v)
		return len(b), err
	}
	first := *r
	first.Findings = nil
	firstSize, err := size(&first)
	if err != nil {
		return nil, err
	}
	if firstSize > maxBytes {
		return nil, fmt.Errorf("%w: its content other than findings is %d bytes (limit %d)", ErrReportTooLarge, firstSize, maxBytes)
	}
	rest := withoutExtras(r)
	restSize, err := size(rest)
	if err != nil {
		return nil, err
	}
	hasExtras := len(r.Dependencies)+len(r.Relationships)+len(r.Endpoints) > 0

	var parts []part
	cur, curSize, start := &first, firstSize, 0
	emit := func(end int) {
		c := *cur
		c.Findings = r.Findings[start:end]
		parts = append(parts, part{&c, start})
		cur, curSize, start = rest, restSize, end
	}
	for i := range r.Findings {
		fs, err := size(&r.Findings[i])
		if err != nil {
			return nil, err
		}
		fs++ // the separating comma
		if restSize+fs > maxBytes {
			return nil, fmt.Errorf("%w: finding %d alone is %d bytes (limit %d)", ErrReportTooLarge, i, fs, maxBytes)
		}
		full := curSize+fs > maxBytes || i-start >= maxFindings
		if full && (i > start || (len(parts) == 0 && hasExtras)) {
			emit(i)
		}
		curSize += fs
	}
	emit(len(r.Findings))
	if len(parts) > maxRequests {
		return nil, fmt.Errorf("%w: it needs %d parts (at most %d)", ErrReportTooLarge, len(parts), maxRequests)
	}
	return parts, nil
}

// streamDecoder reads a reply body as a stream, up to maxReplyBytes.
type streamDecoder interface {
	decodeStream(r io.Reader) error
	maxReplyBytes() int64
}

// uploadReply is an upload reply, or a page of decided results, read as a
// stream: the counts, the decided results whose index is within the part
// (each index once), and the cursor of the next page. It never fails: what
// cannot be read marks the decided results incomplete.
type uploadReply struct {
	n          int // findings in the part
	res        UploadResult
	known      []Known
	next       string
	incomplete bool
}

func (u *uploadReply) maxReplyBytes() int64 {
	return min(int64(replyBase)+int64(u.n)*replyPerFinding, maxReply)
}

func (u *uploadReply) decodeStream(r io.Reader) error {
	*u = uploadReply{n: u.n} // a repeated request starts afresh
	dec := json.NewDecoder(r)
	truncated, err := u.walk(dec)
	if err != nil || (truncated && u.next == "") {
		u.incomplete = true
	}
	return nil
}

// walk reads the reply object. truncated reports a platform that cut the
// list of decided results short.
func (u *uploadReply) walk(dec *json.Decoder) (truncated bool, err error) {
	if err := delim(dec, '{'); err != nil {
		return false, err
	}
	seen := map[int]bool{}
	for dec.More() {
		t, err := dec.Token()
		if err != nil {
			return truncated, err
		}
		key, _ := t.(string)
		switch key {
		case "findings_created":
			err = dec.Decode(&u.res.FindingsCreated)
		case "findings_updated":
			err = dec.Decode(&u.res.FindingsUpdated)
		case "assets_created":
			err = dec.Decode(&u.res.AssetsCreated)
		case "assets_updated":
			err = dec.Decode(&u.res.AssetsUpdated)
		case "known":
			err = u.readKnown(dec, seen)
		case "known_next", "next":
			var s string
			if err = dec.Decode(&s); err == nil {
				if len(s) > maxCursor {
					return truncated, errors.New("cursor too long")
				}
				u.next = s
			}
		case "known_truncated":
			err = dec.Decode(&truncated)
		default:
			var skip json.RawMessage
			err = dec.Decode(&skip)
		}
		if err != nil {
			return truncated, err
		}
	}
	return truncated, delim(dec, '}')
}

// readKnown reads the decided results one at a time, keeping each index
// within the part once.
func (u *uploadReply) readKnown(dec *json.Decoder, seen map[int]bool) error {
	t, err := dec.Token()
	if err != nil {
		return err
	}
	if t == nil {
		return nil // null
	}
	if d, ok := t.(json.Delim); !ok || d != '[' {
		return errors.New("known is not a list")
	}
	for dec.More() {
		var k Known
		if err := dec.Decode(&k); err != nil {
			return err
		}
		if k.Index < 0 || k.Index >= u.n || seen[k.Index] {
			continue
		}
		seen[k.Index] = true
		k.Decision, k.FindingID = cut(k.Decision, maxLabel), cut(k.FindingID, maxLabel)
		u.known = append(u.known, k)
	}
	_, err = dec.Token() // ]
	return err
}

func delim(dec *json.Decoder, want json.Delim) error {
	t, err := dec.Token()
	if err != nil {
		return err
	}
	if d, ok := t.(json.Delim); !ok || d != want {
		return fmt.Errorf("expected %q", want)
	}
	return nil
}

func cut(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}
