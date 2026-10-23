package platform

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// The platform stores an upload and applies it afterwards: the upload
// answers 202 with an upload id, and the result is read from the run with
// a GET that waits on the server. A platform that still answers 201 with
// the result needs none of this.
const (
	// pollWait is the server-side wait of one poll (the platform caps it).
	pollWait = 10 * time.Second
	// maxUploadID bounds the upload id kept from a reply.
	maxUploadID = 64
	// gateRetryCap caps one wait between evaluate requests while the
	// platform is still applying the run's uploads.
	gateRetryCap = 30 * time.Second
	// defaultGateWait is the total wait for pending uploads at evaluate.
	defaultGateWait = 10 * time.Minute
	maxGateWait     = 60 * time.Minute
	codeIngestPend  = "INGEST_PENDING"
)

// UploadFailedError: the platform stored the upload but could not apply
// it; Code is one of its fixed error codes.
type UploadFailedError struct{ Code string }

func (e *UploadFailedError) Error() string {
	if e.Code == "" {
		return "the platform could not apply the upload"
	}
	return "the platform could not apply the upload: " + e.Code
}

// pollReply is an upload answer that says how far the platform is.
type pollReply interface {
	pollState() (status, code string)
}

// uploadRef is the id to poll for, from an upload id or, failing that, the
// last segment of the location. Only a short plain token is kept: the id
// goes into a path built by the client, never a URL taken from the reply.
func uploadRef(id, location string) string {
	if id == "" {
		if i := strings.LastIndex(location, "/"); i >= 0 {
			id = location[i+1:]
		}
	}
	if id == "" || len(id) > maxUploadID {
		return ""
	}
	for _, c := range id {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') && (c < 'A' || c > 'F') && c != '-' {
			return ""
		}
	}
	return id
}

// awaitUpload polls an upload until it is applied (done, and out holds the
// answer) or failed (an *UploadFailedError). Anything else that stops the
// poll (the upload timeout, the context, a 404, transport errors after the
// retries) leaves done false and no error: the upload is stored and the
// platform's verdict still judges it.
func (r *Run) awaitUpload(ctx context.Context, id string, out pollReply) (bool, error) {
	ctx, cancel := context.WithTimeout(ctx, r.cfg.UploadTimeout)
	defer cancel()
	failures := 0
	for {
		var status int
		var retryAfter string
		err := r.onRun(ctx, func(tok, runID string) error {
			var e error
			status, retryAfter, e = r.getOnce(ctx, tok, runPath(runID, "results/"+url.PathEscape(id))+"?wait="+strconv.Itoa(int(pollWait/time.Second)), out)
			return e
		})
		if err != nil {
			if ctx.Err() != nil || failures >= r.cfg.Retries || !retryable(kindEvaluate, status, transportErr(status, err)) {
				return false, nil
			}
			failures++
			if serr := sleep(ctx, backoff(failures, retryAfter)); serr != nil {
				return false, nil
			}
			continue
		}
		failures = 0
		st, code := out.pollState()
		switch st {
		case "applied":
			return true, nil
		case "failed":
			return false, &UploadFailedError{Code: cut(Sanitize(code), maxLabel)}
		}
		// queued or processing (or unknown): ask again after a short pause,
		// so a platform that answers at once is not hammered.
		if serr := sleep(ctx, time.Second); serr != nil {
			return false, nil
		}
	}
}

// getOnce sends one authenticated GET; status is 0 when no HTTP answer
// came back.
func (r *Run) getOnce(ctx context.Context, tok, path string, out any) (int, string, error) {
	ctx, cancel := context.WithTimeout(ctx, r.cfg.RequestTimeout+pollWait)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, r.cfg.APIURL+path, nil)
	if err != nil {
		return 0, "", err
	}
	req.Header.Set("Accept", "application/json")
	if r.cfg.UserAgent != "" {
		req.Header.Set("User-Agent", r.cfg.UserAgent)
	}
	req.Header.Set("Authorization", "Bearer "+tok)
	resp, err := r.cfg.HTTPClient.Do(req)
	if err != nil {
		return 0, "", scrubURL(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if err := replyError(resp); err != nil {
		return resp.StatusCode, resp.Header.Get("Retry-After"), err
	}
	if sd, ok := out.(streamDecoder); ok {
		return resp.StatusCode, "", sd.decodeStream(io.LimitReader(resp.Body, sd.maxReplyBytes()))
	}
	return resp.StatusCode, "", json.NewDecoder(io.LimitReader(resp.Body, maxBody)).Decode(out)
}

// gateWait is the wait for the run's uploads to be applied at evaluate.
func (c *Config) gateWait() time.Duration {
	if c.GateWait < 0 {
		return 0
	}
	if c.GateWait == 0 {
		return defaultGateWait
	}
	return c.GateWait
}

// parseGateWait reads OPENCTEM_GATE_WAIT: a Go duration or whole seconds,
// 0 to 60m. ok is false for anything else.
func parseGateWait(s string) (time.Duration, bool) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, false
	}
	d, err := time.ParseDuration(s)
	if err != nil {
		n, nerr := strconv.Atoi(s)
		if nerr != nil {
			return 0, false
		}
		d = time.Duration(n) * time.Second
	}
	if d < 0 || d > maxGateWait {
		return 0, false
	}
	return d, true
}

// gateRetryWait is the wait before asking for the verdict again: the
// platform's Retry-After (whole seconds), at least 1s, at most 30s; 5s
// when it names none.
func gateRetryWait(retryAfter string) time.Duration {
	d := 5 * time.Second
	if s, err := strconv.Atoi(strings.TrimSpace(retryAfter)); err == nil && s >= 0 {
		d = time.Duration(min(s, 3600)) * time.Second
	}
	return min(max(d, time.Second), gateRetryCap)
}

func isIngestPending(err error) bool {
	var se *StatusError
	return errors.As(err, &se) && se.Status == http.StatusServiceUnavailable && se.Code == codeIngestPend
}
