package platform

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
)

// Limits of a scanner file sent as-is (UploadFile). They match the
// platform: a CI results request body is at most 50 MiB, and a run keeps at
// most 200 reports.
const (
	// MaxFileBytes is the largest file one request carries.
	MaxFileBytes = 50 << 20
	// MaxRunReports is the most reports one run takes, from every job.
	MaxRunReports = 200
)

// File is a scanner file to send to the run as it is: the platform detects
// its format and converts it with the same importers as the console.
type File struct {
	Path string
	// Size and SHA256 are the file's, read before the upload. The upload
	// refuses a file whose size changed since.
	Size   int64
	SHA256 [32]byte
	// ContentType of the request (application/sarif+json for SARIF).
	ContentType string
	// Mapping is the saved import mapping the file goes through
	// ("mapping:<name>[@<version>]"), sent as the format query parameter.
	// Empty: the platform detects the file's format.
	Mapping string
}

var mappingRe = regexp.MustCompile(`^mapping:([a-z0-9][a-z0-9._-]{0,63})(?:@([1-9][0-9]{0,8}))?$`)

// MappingPrefix starts a format value that names a saved import mapping.
const MappingPrefix = "mapping:"

// ParseMapping checks a format value of the form mapping:<name> or
// mapping:<name>@<version> (a name of lowercase letters, digits, dot,
// underscore and hyphen, at most 64 characters; a positive integer
// version) and returns the mapping's name and version (0 for the current
// one).
func ParseMapping(v string) (name string, version int, err error) {
	m := mappingRe.FindStringSubmatch(v)
	if m == nil {
		return "", 0, fmt.Errorf("%q is not mapping:<name>[@<version>]: the name matches [a-z0-9][a-z0-9._-]{0,63}, the version is a positive integer", v)
	}
	if m[2] != "" {
		version, _ = strconv.Atoi(m[2])
	}
	return m[1], version, nil
}

// mappingKeyDigest binds the idempotency digest to the mapping: the same
// file through another mapping is a different import.
func mappingKeyDigest(d [32]byte, mapping string) [32]byte {
	if mapping == "" {
		return d
	}
	return sha256.Sum256(append(append(d[:], 0), mapping...))
}

// FileReceipt is what the platform did with one file.
type FileReceipt struct {
	// Replayed: the platform answered with the stored result of an earlier
	// request with the same Idempotency-Key; nothing was imported again.
	Replayed bool `json:"replayed"`
	// New and StillDetected count findings created and seen again.
	New           int `json:"new"`
	StillDetected int `json:"still_detected"`
	// Resolved and Reopened are nil when the platform does not report
	// them. A CI upload is partial: it never closes findings.
	Resolved *int `json:"resolved"`
	Reopened *int `json:"reopened"`
	// Skipped: findings not stored (an excluded asset, a duplicate in the
	// file). Dropped: findings on an asset other than the run's
	// repository, refused.
	Skipped int `json:"skipped"`
	Dropped int `json:"dropped_out_of_scope"`
	// Failed: findings that could not be stored, plus files of an archive
	// the platform could not read.
	Failed int `json:"failed"`
	// VEXStored: statements stored on findings of the run's repository.
	VEXStored int `json:"vex_stored,omitempty"`
	// Files of the request with the format the platform read (an archive
	// has several).
	Files []ReceiptFile `json:"files"`
}

// ReceiptFile is one file the platform read from a request.
type ReceiptFile struct {
	Name   string `json:"name"`
	Format string `json:"format,omitempty"`
	Error  string `json:"error,omitempty"`
}

// fileReply is the platform's answer to an uploaded tool file.
type fileReply struct {
	FindingsCreated int      `json:"findings_created"`
	FindingsUpdated int      `json:"findings_updated"`
	FindingsSkipped int      `json:"findings_skipped"`
	Errors          []string `json:"errors"`
	Dropped         int      `json:"findings_dropped_out_of_scope"`
	VEXStored       int      `json:"vex_stored"`
	Files           []struct {
		Name   string `json:"name"`
		Format string `json:"format"`
		Error  *struct {
			Kind    string `json:"kind"`
			Message string `json:"message"`
		} `json:"error"`
	} `json:"files"`
	// Receipt carries the receipt counts of a platform that reports them.
	Receipt *struct {
		Reactivated *int `json:"reactivated"`
		Closed      *int `json:"closed"`
	} `json:"receipt"`
}

// maxFileReply bounds the reply to an uploaded file (it lists the files
// of the request and short errors, never findings).
const maxFileReply = 1 << 20

// IdempotencyKey is the Idempotency-Key of a file sent to a run: derived
// from the run and the file's content, so the same file sent again to the
// same run (a retried request, a repeated step, a retried job that joins
// the same aggregate run) is answered from the first import, never
// imported twice.
func IdempotencyKey(runID string, digest [32]byte) string {
	h := sha256.New()
	_, _ = io.WriteString(h, "openctem-ci upload v1\x00"+runID+"\x00"+hex.EncodeToString(digest[:]))
	return "ocu1-" + hex.EncodeToString(h.Sum(nil))
}

// ErrNoRun: the job's run could not be opened (the token exchange failed
// or was refused); nothing was sent.
var ErrNoRun = errors.New("the CI run could not be opened")

// ErrFileChanged: the file is not the one that was checked (its size
// changed between the check and the upload).
var ErrFileChanged = errors.New("the file changed after it was checked")

// UploadFile sends a scanner file to the run as the request body, read from
// disk as it goes (never held in memory), with an Idempotency-Key from the
// run and the file's digest. A transient failure (network, 429, 5xx, or 409
// while the platform is still importing an earlier request with the key)
// is retried with the same key.
func (r *Run) UploadFile(ctx context.Context, f File) (*FileReceipt, error) {
	if f.Size > MaxFileBytes {
		return nil, fmt.Errorf("%s: %d bytes, more than the platform accepts (%d)", filepath.Base(f.Path), f.Size, MaxFileBytes)
	}
	// The run is opened first, so a refused token is told apart from a file
	// the platform refused.
	if _, err := r.bearer(ctx); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrNoRun, err)
	}
	var out *FileReceipt
	err := r.onRun(ctx, func(tok, runID string) error {
		rec, err := r.sendFile(ctx, tok, runPath(runID, "results"), IdempotencyKey(runID, mappingKeyDigest(f.SHA256, f.Mapping)), f)
		out = rec
		return err
	})
	if err != nil {
		return nil, fmt.Errorf("upload %s: %w", filepath.Base(f.Path), err)
	}
	return out, nil
}

// sendFile repeats one file request after a transient failure.
func (r *Run) sendFile(ctx context.Context, tok, path, key string, f File) (*FileReceipt, error) {
	for attempt := 1; ; attempt++ {
		rec, status, retryAfter, err := r.onceFile(ctx, tok, path, key, f)
		if err == nil {
			return rec, nil
		}
		again := retryable(kindUpload, status, transportErr(status, err)) ||
			// The first request with this key is still being imported.
			(status == http.StatusConflict && retryAfter != "")
		if attempt > r.cfg.Retries || !again || errors.Is(err, ErrFileChanged) {
			return nil, err
		}
		if serr := sleep(ctx, backoff(attempt, retryAfter)); serr != nil {
			return nil, err
		}
	}
}

// onceFile sends the file once; status is 0 when no HTTP answer came back.
func (r *Run) onceFile(ctx context.Context, tok, path, key string, f File) (*FileReceipt, int, string, error) {
	fh, err := os.Open(f.Path) // #nosec G304 -- a file the job's own command line names
	if err != nil {
		return nil, 0, "", err
	}
	defer func() { _ = fh.Close() }()
	st, err := fh.Stat()
	if err != nil {
		return nil, 0, "", err
	}
	if st.Size() != f.Size {
		return nil, 0, "", ErrFileChanged
	}
	ctx, cancel := context.WithTimeout(ctx, r.cfg.UploadTimeout)
	defer cancel()
	// The body is the file itself, streamed with a known length; the
	// platform reads at most MaxFileBytes.
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, r.cfg.APIURL+path+mappingQuery(f.Mapping), io.LimitReader(fh, f.Size))
	if err != nil {
		return nil, 0, "", err
	}
	req.ContentLength = f.Size
	req.Header.Set("Content-Type", f.ContentType)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Idempotency-Key", key)
	if r.cfg.UserAgent != "" {
		req.Header.Set("User-Agent", r.cfg.UserAgent)
	}
	req.Header.Set("Authorization", "Bearer "+tok)
	resp, err := r.cfg.HTTPClient.Do(req)
	if err != nil {
		return nil, 0, "", scrubURL(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if err := replyError(resp); err != nil {
		return nil, resp.StatusCode, resp.Header.Get("Retry-After"), err
	}
	var rep fileReply
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxFileReply)).Decode(&rep); err != nil {
		// Stored: a 2xx is the platform's word, whatever the body holds.
		rep = fileReply{}
	}
	rec := &FileReceipt{
		Replayed:      resp.Header.Get("Idempotent-Replayed") == "true",
		New:           rep.FindingsCreated,
		StillDetected: rep.FindingsUpdated,
		Skipped:       rep.FindingsSkipped,
		Dropped:       rep.Dropped,
		Failed:        len(rep.Errors),
		VEXStored:     rep.VEXStored,
		Files:         []ReceiptFile{},
	}
	if rep.Receipt != nil {
		rec.Reopened, rec.Resolved = rep.Receipt.Reactivated, rep.Receipt.Closed
	}
	for i, fl := range rep.Files {
		if i >= MaxRunReports {
			break
		}
		rf := ReceiptFile{Name: cut(Sanitize(fl.Name), maxLabel), Format: cut(Sanitize(fl.Format), maxLabel)}
		if fl.Error != nil {
			rf.Error = cut(Sanitize(nonEmpty(fl.Error.Message, fl.Error.Kind)), 512)
			rec.Failed++
		}
		rec.Files = append(rec.Files, rf)
	}
	return rec, resp.StatusCode, "", nil
}

// mappingQuery is the query string that selects a saved import mapping.
func mappingQuery(mapping string) string {
	if mapping == "" {
		return ""
	}
	return "?" + url.Values{"format": {mapping}}.Encode()
}
