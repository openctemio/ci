// Command openctem-ci runs one OpenCTEM scan capability in a CI job,
// uploads the result to an OpenCTEM CI run with the job's OIDC identity and
// asks the platform's gate for the verdict.
//
//	openctem-ci scan --capability sast [--sarif out.sarif] [--gitlab-report gl-sast-report.json]
//	openctem-ci gate --status-dir statuses --expect sast,sca,secrets
//	openctem-ci capabilities
//	openctem-ci version
//
// Exit codes: 0 the gate passed (or no gate was asked), 1 the gate failed,
// 2 the scan could not be trusted (a tool, parse, upload or configuration
// error).
package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"
)

// Version is set at build time (-X main.Version=...).
var Version = "dev"

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	code := run(ctx, os.Args[1:], os.Stdout, os.Stderr, os.Getenv, os.Environ)
	stop()
	os.Exit(code)
}

// env is the process environment (replaced in tests).
type env struct {
	getenv  func(string) string
	environ func() []string
}

func run(ctx context.Context, args []string, stdout, stderr io.Writer, getenv func(string) string, environ func() []string) int {
	e := env{getenv: getenv, environ: environ}
	if len(args) == 0 {
		usage(stderr)
		return 2
	}
	switch args[0] {
	case "scan":
		return cmdScan(ctx, args[1:], stdout, stderr, e)
	case "gate":
		return cmdGate(ctx, args[1:], stdout, stderr, e)
	case "capabilities":
		return cmdCapabilities(args[1:], stdout, stderr)
	case "version", "--version", "-version":
		_, _ = fmt.Fprintf(stdout, "openctem-ci %s\n", Version)
		return 0
	case "help", "-h", "--help":
		usage(stdout)
		return 0
	}
	_, _ = fmt.Fprintf(stderr, "unknown command %q\n\n", args[0])
	usage(stderr)
	return 2
}

func usage(w io.Writer) {
	_, _ = fmt.Fprint(w, `openctem-ci runs one OpenCTEM scan capability in a CI job.

Commands:
  scan          run a capability, write SARIF / GitLab reports, upload to OpenCTEM, gate
  gate          judge the results of several capability jobs (the final job of a pipeline)
  capabilities  list the capabilities, their tools and images
  version       print the version

Run "openctem-ci <command> -h" for the flags of a command.

Environment:
  OPENCTEM_API_URL        the OpenCTEM URL (https)
  OPENCTEM_TENANT_ID      the organization id: turns on reporting with the job's OIDC identity
  OPENCTEM_OIDC_AUDIENCE  the OIDC audience (default openctem:tenant:<id>)
  OPENCTEM_ID_TOKEN_VAR   the variable holding the job's token on GitLab, CircleCI and
                          Jenkins (default OPENCTEM_ID_TOKEN)

The job's token: GitHub Actions (id-token: write), GitLab CI (id_tokens),
Azure Pipelines (System.OidcRequestUri with SYSTEM_ACCESSTOKEN mapped from
$(System.AccessToken)), Bitbucket Pipelines (oidc: true), CircleCI
(circleci run oidc get into OPENCTEM_ID_TOKEN), Jenkins (the OpenID Connect
Provider plugin's credential bound to OPENCTEM_ID_TOKEN).

Exit codes: 0 pass, 1 the gate failed, 2 error (the scan is not trusted).
`)
}
