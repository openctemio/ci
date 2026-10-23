package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"text/tabwriter"

	"github.com/openctemio/ctis/importer"

	"github.com/openctemio/ci/internal/ciinfo"
	"github.com/openctemio/ci/internal/gate"
	"github.com/openctemio/ci/internal/platform"
)

// maxUploadFiles bounds the files of one upload command (the platform keeps
// at most platform.MaxRunReports reports per run, from every job).
const maxUploadFiles = 50

// zipLimits are the platform's limits on an uploaded archive.
var zipLimits = importer.ArchiveLimits{MaxEntries: 50, MaxEntryBytes: 100 << 20, MaxTotalBytes: 400 << 20, MaxRatio: 200}

// formatZip names an archive of scanner files.
const formatZip = "zip"

type uploadFlags struct {
	format        string
	aggregate     bool
	gate          bool
	receiptOut    string
	onUploadError string
}

// uploadFile is a file that passed the checks, ready to send.
type uploadFile struct {
	platform.File
	format string
	dupOf  string // the earlier argument with the same content
}

// cmdUpload sends scanner reports a pipeline already has to an OpenCTEM CI
// run, as they are: the platform detects and converts them. The run is the
// one the job's OIDC identity opens (the repository, branch and commit come
// from the verified token, never from the files or the command line).
func cmdUpload(ctx context.Context, args []string, stdout, stderr io.Writer, e env) int {
	fs := flag.NewFlagSet("upload", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() {
		_, _ = fmt.Fprint(stderr, "Usage: openctem-ci upload [flags] <file or directory>...\n\n"+
			"Uploads scanner reports to the job's OpenCTEM CI run. Formats: "+formatNames()+", or a ZIP of them.\n"+
			"A directory uploads its regular files (not its subdirectories).\n\nFlags:\n")
		fs.PrintDefaults()
	}
	var f uploadFlags
	fs.StringVar(&f.format, "format", "auto", "the format every file must have ("+formatNames()+"), auto (detect each file), or mapping:<name>[@<version>] to read every file through a saved import mapping")
	fs.BoolVar(&f.aggregate, "aggregate", false, "upload into the run shared by all jobs of this pipeline; a final 'gate' job decides")
	fs.BoolVar(&f.gate, "gate", false, "ask the platform's gate for the run's verdict after the upload (not with --aggregate)")
	fs.StringVar(&f.receiptOut, "receipt", "", "write the receipt as JSON to this file")
	fs.StringVar(&f.onUploadError, "on-upload-error", e.getenv("OPENCTEM_ON_UPLOAD_ERROR"), "fail (exit 2, the default) or warn when a file is not stored")
	if err := fs.Parse(args); err != nil {
		return gate.ExitError
	}
	errf := func(format string, a ...any) int {
		_, _ = fmt.Fprintf(stderr, "Error: "+format+"\n", a...)
		return gate.ExitError
	}
	// A mapping name is case-sensitive (lowercase only): it is validated as
	// typed, never lowercased into a name the user did not write.
	if f.format = strings.TrimSpace(f.format); !strings.HasPrefix(f.format, platform.MappingPrefix) {
		f.format = strings.ToLower(f.format)
	}
	if strings.HasPrefix(f.format, platform.MappingPrefix) {
		if _, _, err := platform.ParseMapping(f.format); err != nil {
			return errf("invalid --format: %v", err)
		}
	} else if f.format != "auto" && f.format != formatZip && !importer.Format(f.format).IsValid() {
		return errf("unknown --format %q; one of: auto, %s, zip, or mapping:<name>[@<version>]", f.format, formatNames())
	}
	switch f.onUploadError = strings.ToLower(strings.TrimSpace(f.onUploadError)); f.onUploadError {
	case "":
		f.onUploadError = "fail"
	case "warn", "fail":
	default:
		return errf("--on-upload-error must be warn or fail")
	}
	if f.gate && f.aggregate {
		return errf("--gate judges the run now; with --aggregate the final 'gate' job does that")
	}
	if fs.NArg() == 0 {
		fs.Usage()
		return gate.ExitError
	}

	// Every file is checked before anything is sent: an unknown format, a
	// file too large or too many files fail the job without a partial
	// upload.
	paths, err := expandPaths(fs.Args())
	if err != nil {
		return errf("%v", err)
	}
	if len(paths) > maxUploadFiles {
		return errf("%d files; at most %d per upload (a run keeps at most %d reports)", len(paths), maxUploadFiles, platform.MaxRunReports)
	}
	files := make([]uploadFile, 0, len(paths))
	seen := map[[32]byte]string{}
	for _, p := range paths {
		uf, err := checkFile(p, f.format)
		if err != nil {
			return errf("%v", err)
		}
		if first, ok := seen[uf.SHA256]; ok {
			uf.dupOf = first
		} else {
			seen[uf.SHA256] = p
		}
		files = append(files, uf)
	}

	info := ciinfo.Detect(e.getenv)
	tenant := strings.TrimSpace(e.getenv(platform.EnvTenantID))
	if info.Fork {
		_, _ = fmt.Fprintln(stderr, "Warning: this change comes from a fork: nothing is uploaded and no credential is used")
		return gate.ExitPass
	}
	if tenant == "" {
		return errf("%s is not set: upload reports to an OpenCTEM organization with the job's OIDC identity", platform.EnvTenantID)
	}
	cfg := platform.ConfigFromEnv(e.getenv)
	cfg.Aggregate = f.aggregate
	cfg.UserAgent = "openctem-ci/" + Version
	pr, err := platform.New(cfg)
	if err != nil {
		rerr := reportingError(err, nonEmpty(cfg.IDTokenVar, platform.DefaultIDTokenVar))
		if enforced(e.getenv) {
			return errf("%s", platform.Sanitize(rerr.Error()))
		}
		_, _ = fmt.Fprintf(stderr, "Warning: %s; nothing is uploaded (%s=false)\n", platform.Sanitize(rerr.Error()), envEnforce)
		return gate.ExitPass
	}

	u := &uploadJob{stdout: stdout, stderr: stderr, pr: pr}
	u.run(ctx, files)
	if f.receiptOut != "" {
		if err := writeReceipt(f.receiptOut, u.receipt); err != nil {
			return errf("write the receipt: %v", err)
		}
	}
	if u.authErr != nil {
		// Nothing can reach the run: the gate cannot be asked either.
		return errf("%s", platform.Sanitize(u.authErr.Error()))
	}
	failed := u.receipt.Total.FilesFailed
	code := gate.ExitPass
	if failed > 0 {
		if f.onUploadError == "fail" {
			_, _ = fmt.Fprintf(stderr, "Error: %d file(s) were not stored in full; the upload is not trusted\n", failed)
			code = gate.ExitError
		} else {
			_, _ = fmt.Fprintf(stderr, "Warning: %d file(s) were not stored in full; the job passes (--on-upload-error warn)\n", failed)
		}
	}
	if !f.gate {
		if f.aggregate {
			_, _ = fmt.Fprintln(stdout, "Aggregate mode: the final gate job decides.")
		}
		return code
	}
	// The gate counts a file that was not stored as a failed scan: the run
	// fails rather than passing on what did not arrive.
	v, err := pr.Evaluate(ctx, failed)
	if err != nil {
		return errf("the OpenCTEM gate could not be reached: %s", platform.Sanitize(err.Error()))
	}
	platform.WriteVerdict(stdout, v)
	if code != gate.ExitPass {
		return code
	}
	if v.Failed() {
		return gate.ExitFail
	}
	return gate.ExitPass
}

// expandPaths turns the arguments into files: a file as named, a directory
// as its regular files (sorted; no subdirectories, no symbolic links).
func expandPaths(args []string) ([]string, error) {
	var out []string
	for _, a := range args {
		st, err := os.Stat(a)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", a, errors.Unwrap(err))
		}
		if !st.IsDir() {
			out = append(out, a)
			continue
		}
		entries, err := os.ReadDir(a)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", a, err)
		}
		var names []string
		for _, en := range entries {
			if en.Type().IsRegular() {
				names = append(names, filepath.Join(a, en.Name()))
			}
		}
		if len(names) == 0 {
			return nil, fmt.Errorf("%s: no files to upload", a)
		}
		sort.Strings(names)
		out = append(out, names...)
	}
	return out, nil
}

// checkFile checks one file: a regular file within the size limit, in a
// format the platform reads (the hint, when given, must match), and not a
// secret scanner's raw report. It reads the file once for its digest.
func checkFile(path, hint string) (uploadFile, error) {
	uf := uploadFile{}
	mapped := strings.HasPrefix(hint, platform.MappingPrefix)
	fh, err := os.Open(path) // #nosec G304 -- a file the job's own command line names
	if err != nil {
		return uf, err
	}
	defer func() { _ = fh.Close() }()
	st, err := fh.Stat()
	if err != nil {
		return uf, err
	}
	switch {
	case !st.Mode().IsRegular():
		return uf, fmt.Errorf("%s: not a regular file", path)
	case st.Size() == 0:
		return uf, fmt.Errorf("%s: empty file", path)
	case st.Size() > platform.MaxFileBytes:
		return uf, fmt.Errorf("%s: %s, larger than the %s the platform accepts per file; split the report (one file per target or tool)",
			path, mib(st.Size()), mib(platform.MaxFileBytes))
	}
	head := make([]byte, importer.SniffLen)
	n, err := io.ReadFull(fh, head)
	if err != nil && !errors.Is(err, io.ErrUnexpectedEOF) {
		return uf, fmt.Errorf("%s: %w", path, err)
	}
	head = head[:n]
	if mapped {
		// A mapping reads CSV, JSON or XML the importers do not know: the
		// platform converts the file, so nothing is detected here. An
		// archive is not a mapping input.
		if importer.IsZip(head) {
			return uf, fmt.Errorf("%s: an archive cannot go through a mapping (--format %s)", path, hint)
		}
		uf.Mapping = hint
		return uf.finish(fh, path, st.Size(), hint, "")
	}
	format, err := detectFormat(fh, st.Size(), head)
	if err != nil {
		return uf, fmt.Errorf("%s: %w", path, err)
	}
	if hint != "auto" && !sameFormat(hint, format) {
		return uf, fmt.Errorf("%s: the file is %s, not %s (--format)", path, format, hint)
	}
	return uf.finish(fh, path, st.Size(), format, contentType(format))
}

// finish reads the file once for its digest and fills the upload.
func (uf uploadFile) finish(fh *os.File, path string, size int64, format, ctype string) (uploadFile, error) {
	if _, err := fh.Seek(0, io.SeekStart); err != nil {
		return uf, err
	}
	h := sha256.New()
	if _, err := io.Copy(h, fh); err != nil {
		return uf, fmt.Errorf("%s: %w", path, err)
	}
	copy(uf.SHA256[:], h.Sum(nil))
	uf.Path, uf.Size, uf.format = path, size, format
	uf.ContentType = ctype
	if uf.ContentType == "" {
		uf.ContentType = mappedContentType(path)
	}
	return uf, nil
}

// mappedContentType names the body of a file read through a mapping by
// its extension; the platform reads the content, not the header.
func mappedContentType(path string) string {
	switch strings.ToLower(filepath.Ext(path)) {
	case ".json":
		return "application/json"
	case ".xml":
		return "application/xml"
	case ".csv":
		return "text/csv"
	}
	return "application/octet-stream"
}

// detectFormat names the file's format with the importers' own detection;
// an archive is checked file by file.
func detectFormat(r io.ReaderAt, size int64, head []byte) (string, error) {
	if importer.IsZip(head) {
		entries, err := importer.OpenZip(r, size, zipLimits)
		if err != nil {
			return "", err
		}
		if len(entries) == 0 {
			return "", errors.New("the archive holds no files")
		}
		for _, en := range entries {
			if err := checkZipEntry(en); err != nil {
				return "", err
			}
		}
		return formatZip, nil
	}
	f, ok := importer.Detect(head)
	if !ok {
		return "", fmt.Errorf("unknown format; the platform reads %s, or a ZIP of them (a CTIS report goes up with 'openctem-ci scan')", formatNames())
	}
	if err := uploadable(f, false); err != nil {
		return "", err
	}
	return string(f), nil
}

func checkZipEntry(en importer.ArchiveFile) error {
	rc, err := en.Open()
	if err != nil {
		return err
	}
	defer func() { _ = rc.Close() }()
	head := make([]byte, importer.SniffLen)
	n, err := io.ReadFull(rc, head)
	if err != nil && !errors.Is(err, io.ErrUnexpectedEOF) && !errors.Is(err, io.EOF) {
		return fmt.Errorf("archive file %s: %w", platform.Sanitize(en.Name), err)
	}
	f, ok := importer.Detect(head[:n])
	if !ok {
		return fmt.Errorf("archive file %s: unknown format", platform.Sanitize(en.Name))
	}
	if err := uploadable(f, true); err != nil {
		return fmt.Errorf("archive file %s: %w", platform.Sanitize(en.Name), err)
	}
	return nil
}

// uploadable refuses what must not go up as a raw file: a secret scanner's
// report carries every secret's raw value, which openctem-ci never sends
// (scan --capability secrets sends a keyed hash instead).
func uploadable(f importer.Format, inArchive bool) error {
	switch f {
	case importer.FormatGitleaks, importer.FormatBetterleaks:
		return fmt.Errorf("a %s report holds the raw value of every secret it found and is not uploaded; "+
			"run 'openctem-ci scan --capability secrets', which sends each secret masked and as a keyed hash", f)
	case importer.FormatQualysKB:
		if inArchive {
			return nil // the companion of a detection file in the same archive
		}
		return errors.New("a Qualys KnowledgeBase file is read only with its detection file: upload both in one ZIP")
	}
	if !f.IsValid() {
		return fmt.Errorf("format %s is not read by the platform", f)
	}
	return nil
}

// sameFormat compares a --format hint with the detected format. Detection
// names the semgrep JSON shape semgrep, which opengrep also writes.
func sameFormat(hint, detected string) bool {
	if hint == detected {
		return true
	}
	return hint == string(importer.FormatOpengrep) && detected == string(importer.FormatSemgrep)
}

func contentType(format string) string {
	switch format {
	case string(importer.FormatSARIF):
		return "application/sarif+json"
	case formatZip:
		return "application/zip"
	}
	return "application/octet-stream"
}

// formatNames lists the formats an upload takes.
func formatNames() string {
	var names []string
	for _, f := range importer.AllFormats() {
		if f == importer.FormatGitleaks || f == importer.FormatBetterleaks {
			continue
		}
		names = append(names, string(f))
	}
	return strings.Join(names, ", ")
}

func mib(n int64) string {
	return strconv.FormatFloat(float64(n)/(1<<20), 'f', 1, 64) + " MiB"
}

// receipt is the result of an upload command.
type receipt struct {
	RunID string        `json:"run_id"`
	Files []fileOutcome `json:"files"`
	Total receiptTotal  `json:"total"`
}

type fileOutcome struct {
	Path    string                `json:"path"`
	Format  string                `json:"format"`
	SHA256  string                `json:"sha256"`
	Stored  bool                  `json:"stored"`
	Error   string                `json:"error,omitempty"`
	Note    string                `json:"note,omitempty"`
	Receipt *platform.FileReceipt `json:"receipt,omitempty"`
}

type receiptTotal struct {
	New           int  `json:"new"`
	StillDetected int  `json:"still_detected"`
	Resolved      *int `json:"resolved"`
	Reopened      *int `json:"reopened"`
	Skipped       int  `json:"skipped"`
	Dropped       int  `json:"dropped_out_of_scope"`
	Failed        int  `json:"failed"`
	FilesFailed   int  `json:"files_failed"`
}

type uploadJob struct {
	stdout, stderr io.Writer
	pr             *platform.Run
	receipt        receipt
	// authErr: the run could not be opened (the token exchange failed);
	// nothing was sent.
	authErr error
}

// run uploads the files one by one and prints the receipt.
func (u *uploadJob) run(ctx context.Context, files []uploadFile) {
	u.receipt.Files = []fileOutcome{}
	_, _ = fmt.Fprintf(u.stdout, "openctem-ci %s: uploading %d file(s) to OpenCTEM (partial: an upload never closes findings)\n", Version, len(files))
	for _, f := range files {
		out := fileOutcome{Path: f.Path, Format: f.format, SHA256: fmt.Sprintf("%x", f.SHA256)}
		if f.dupOf != "" {
			out.Stored, out.Note = true, "same content as "+f.dupOf+"; not sent again"
			u.receipt.Files = append(u.receipt.Files, out)
			continue
		}
		rec, err := u.pr.UploadFile(ctx, f.File)
		if err != nil && isAuthError(err) {
			// No later file can reach the run either; what was stored
			// before is still printed.
			u.authErr = err
			break
		}
		if err != nil {
			out.Error = platform.Sanitize(err.Error())
			u.receipt.Total.FilesFailed++
		} else {
			out.Stored, out.Receipt = true, rec
			u.add(rec)
			if rec.Failed > 0 {
				u.receipt.Total.FilesFailed++
			}
		}
		u.receipt.Files = append(u.receipt.Files, out)
	}
	u.receipt.RunID = u.pr.Info().RunID
	if len(u.receipt.Files) > 0 {
		u.print()
	}
}

// isAuthError: the run could not be opened, or the platform refused its
// token, so no later file can be sent either.
func isAuthError(err error) bool {
	var se *platform.StatusError
	return errors.Is(err, platform.ErrNoRun) || (errors.As(err, &se) && se.Status == 401)
}

func (u *uploadJob) add(r *platform.FileReceipt) {
	t := &u.receipt.Total
	t.New += r.New
	t.StillDetected += r.StillDetected
	t.Skipped += r.Skipped
	t.Dropped += r.Dropped
	t.Failed += r.Failed
	t.Resolved = addOpt(t.Resolved, r.Resolved)
	t.Reopened = addOpt(t.Reopened, r.Reopened)
}

func addOpt(sum, v *int) *int {
	if v == nil {
		return sum
	}
	n := *v
	if sum != nil {
		n += *sum
	}
	return &n
}

func opt(v *int) string {
	if v == nil {
		return "-"
	}
	return strconv.Itoa(*v)
}

func (u *uploadJob) print() {
	info := u.pr.Info()
	if info.RunID != "" {
		_, _ = fmt.Fprintf(u.stdout, "Run %s (%s @ %s)\n",
			platform.Sanitize(info.RunID), platform.Sanitize(info.Repository), short(info.CommitSHA))
	}
	tw := tabwriter.NewWriter(u.stdout, 0, 2, 2, ' ', 0)
	_, _ = fmt.Fprintln(tw, "FILE\tFORMAT\tNEW\tSTILL DETECTED\tRESOLVED\tREOPENED\tSKIPPED\tFAILED\tNOTE")
	for _, f := range u.receipt.Files {
		name := platform.Sanitize(filepath.Base(f.Path))
		switch {
		case f.Receipt == nil && f.Stored:
			_, _ = fmt.Fprintf(tw, "%s\t%s\t-\t-\t-\t-\t-\t-\t%s\n", name, f.Format, platform.Sanitize(f.Note))
		case f.Receipt == nil:
			_, _ = fmt.Fprintf(tw, "%s\t%s\t-\t-\t-\t-\t-\tfile\tnot stored: %s\n", name, f.Format, truncate(f.Error, 200))
		default:
			r := f.Receipt
			var notes []string
			if r.Replayed {
				notes = append(notes, "already uploaded to this run: the first import's result")
			}
			if r.Dropped > 0 {
				notes = append(notes, fmt.Sprintf("%d dropped (not on the run's repository)", r.Dropped))
			}
			for _, rf := range r.Files {
				if rf.Error != "" {
					notes = append(notes, rf.Name+": "+truncate(rf.Error, 120))
				}
			}
			_, _ = fmt.Fprintf(tw, "%s\t%s\t%d\t%d\t%s\t%s\t%d\t%d\t%s\n", name, f.Format, r.New, r.StillDetected,
				opt(r.Resolved), opt(r.Reopened), r.Skipped+r.Dropped, r.Failed, strings.Join(notes, "; "))
		}
	}
	t := u.receipt.Total
	_, _ = fmt.Fprintf(tw, "TOTAL\t\t%d\t%d\t%s\t%s\t%d\t%d\t%d file(s) not stored in full\n", t.New, t.StillDetected,
		opt(t.Resolved), opt(t.Reopened), t.Skipped+t.Dropped, t.Failed, t.FilesFailed)
	_ = tw.Flush()
	if t.Resolved == nil || t.Reopened == nil {
		_, _ = fmt.Fprintln(u.stdout, "RESOLVED and REOPENED show - when the platform does not report them; a CI upload never closes findings.")
	}
}

func writeReceipt(path string, r receipt) error {
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetIndent("", "  ")
	if err := enc.Encode(r); err != nil {
		return err
	}
	if dir := filepath.Dir(path); dir != "" {
		if err := os.MkdirAll(dir, 0o750); err != nil {
			return err
		}
	}
	return os.WriteFile(filepath.Clean(path), b.Bytes(), 0o600)
}
