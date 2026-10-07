package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"strings"
	"text/tabwriter"

	"github.com/openctemio/ci/internal/capability"
	"github.com/openctemio/ci/internal/ciinfo"
	"github.com/openctemio/ci/internal/gate"
	"github.com/openctemio/ci/internal/platform"
)

// cmdGate is the final job of a pipeline that ran several capability jobs
// in aggregate mode: it joins the same platform run and asks for the
// verdict on everything they reported. A capability that is expected but
// did not report (no status, a failed scan, a failed upload) is a scan
// failure, which fails the gate: a broken scan never passes.
func cmdGate(ctx context.Context, args []string, stdout, stderr io.Writer, e env) int {
	fs := flag.NewFlagSet("gate", flag.ContinueOnError)
	fs.SetOutput(stderr)
	dir := fs.String("status-dir", ".", "directory holding the *.status.json files of the capability jobs")
	expect := fs.String("expect", e.getenv("OPENCTEM_CAPABILITIES"), "capabilities that must have reported, e.g. sast,sca,secrets")
	failOn := fs.String("fail-on", e.getenv("OPENCTEM_FAIL_ON"), "local gate threshold, used when the platform gate cannot decide")
	noPush := fs.Bool("no-push", false, "do not ask the platform; decide locally with --fail-on")
	if err := fs.Parse(args); err != nil {
		return gate.ExitError
	}
	if *failOn != "" && !gate.ValidThreshold(*failOn) {
		_, _ = fmt.Fprintf(stderr, "Error: invalid --fail-on %q\n", *failOn)
		return gate.ExitError
	}
	caps, err := capability.Parse(*expect)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "Error: --expect: %v\n", err)
		return gate.ExitError
	}
	statuses, err := readStatuses(*dir)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "Error: %v\n", err)
		return gate.ExitError
	}

	info := ciinfo.Detect(e.getenv)
	var pr *platform.Run
	if !*noPush && !info.Fork {
		cfg := platform.ConfigFromEnv(e.getenv)
		cfg.Aggregate = true
		cfg.UserAgent = "openctem-ci/" + Version
		if r, err := platform.New(cfg); err == nil {
			pr = r
		} else if !errors.Is(err, platform.ErrNoOIDC) {
			_, _ = fmt.Fprintf(stderr, "Warning: reporting to OpenCTEM is not available: %v\n", err)
		}
	}

	failures, tally := 0, gate.Tally{}
	tw := tabwriter.NewWriter(stdout, 0, 2, 2, ' ', 0)
	_, _ = fmt.Fprintln(tw, "CAPABILITY\tTOOL\tSTATUS\tFINDINGS")
	for _, c := range caps {
		st, ok := statuses[c.Name]
		state := "ok"
		switch {
		case !ok:
			state, failures = "missing (the job did not report)", failures+1
		case !st.OK:
			state, failures = "failed: "+platform.Sanitize(st.Error), failures+1
		case pr != nil && !st.Pushed:
			// The platform judges only what reached it.
			state, failures = "not uploaded", failures+1
		}
		if ok {
			tally.Add(st.Tally)
		}
		_, _ = fmt.Fprintf(tw, "%s\t%s\t%s\t%d\n", c.Name, c.Tool, state, st.Tally.Total())
	}
	_ = tw.Flush()
	for name := range statuses {
		if !contains(caps, name) {
			_, _ = fmt.Fprintf(stderr, "Warning: a status for %q was found but not expected; it is ignored\n", platform.Sanitize(name))
		}
	}

	if pr != nil {
		v, err := pr.Evaluate(ctx, failures)
		if err == nil {
			platform.WriteVerdict(stdout, v)
			if v.Failed() {
				return gate.ExitFail
			}
			return gate.ExitPass
		}
		_, _ = fmt.Fprintf(stderr, "Warning: the OpenCTEM gate could not be reached: %v\n", err)
		if *failOn == "" {
			_, _ = fmt.Fprintln(stderr, "Error: the platform gate is unreachable and no --fail-on threshold is set")
			return gate.ExitError
		}
		_, _ = fmt.Fprintf(stdout, "Falling back to the local gate (--fail-on %s)\n", *failOn)
	}
	if failures > 0 {
		_, _ = fmt.Fprintf(stderr, "Error: %d capability scan(s) did not complete; the result is not trusted\n", failures)
		return gate.ExitError
	}
	if *failOn == "" {
		_, _ = fmt.Fprintln(stdout, "No gate: every capability reported (set --fail-on or report to OpenCTEM for a verdict).")
		return gate.ExitPass
	}
	r, err := gate.Decide(tally, *failOn)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "Error: %v\n", err)
		return gate.ExitError
	}
	return gate.Print(stdout, r)
}

func contains(caps []capability.Capability, name string) bool {
	for _, c := range caps {
		if c.Name == name {
			return true
		}
	}
	return false
}

// cmdCapabilities lists the capabilities.
func cmdCapabilities(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("capabilities", flag.ContinueOnError)
	fs.SetOutput(stderr)
	asJSON := fs.Bool("json", false, "print JSON")
	if err := fs.Parse(args); err != nil {
		return gate.ExitError
	}
	all := capability.All()
	if *asJSON {
		type row struct {
			Name         string `json:"name"`
			ID           string `json:"id"`
			Tool         string `json:"tool"`
			Image        string `json:"image"`
			GitLabReport string `json:"gitlab_report"`
			GitLabFile   string `json:"gitlab_file"`
			Target       string `json:"target"`
		}
		rows := make([]row, 0, len(all))
		for _, c := range all {
			rows = append(rows, row{c.Name, c.ID, c.Tool, capability.Registry + "/" + c.Image, c.GitLabReport, c.GitLabFile, string(c.Target)})
		}
		b, _ := json.MarshalIndent(rows, "", "  ")
		_, _ = fmt.Fprintln(stdout, string(b))
		return 0
	}
	tw := tabwriter.NewWriter(stdout, 0, 2, 2, ' ', 0)
	_, _ = fmt.Fprintln(tw, "NAME\tID\tTOOL\tIMAGE\tGITLAB REPORT\tTARGET")
	for _, c := range all {
		_, _ = fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\n", c.Name, c.ID, c.Tool, capability.Registry+"/"+c.Image,
			strings.Join([]string{c.GitLabReport, c.GitLabFile}, ": "), c.Target)
	}
	_ = tw.Flush()
	return 0
}
