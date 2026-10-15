package main

import (
	"path/filepath"
	"strings"
	"testing"
)

// A job that names a tenant but has no OIDC token fails closed: it exits 2
// with the fix, uploads nothing, and records why in its status file. Before,
// it warned, ran as a scan only and passed without a --fail-on threshold.
func TestTenantWithoutOIDCFailsClosed(t *testing.T) {
	h := setup(t)
	delete(h.env, "OPENCTEM_ID_TOKEN")
	statusFile := filepath.Join(h.out, "secrets.status.json")
	code, _, stderr := h.run("scan", "--capability", "secrets", "--status", statusFile)
	if code != 2 {
		t.Fatalf("exit %d, want 2: %s", code, stderr)
	}
	for _, want := range []string{"OPENCTEM_TENANT_ID is set but this job has no OIDC token", "id-token: write",
		"id_tokens: OPENCTEM_ID_TOKEN", "OPENCTEM_ENFORCE=false"} {
		if !strings.Contains(stderr, want) {
			t.Errorf("stderr lacks %q:\n%s", want, stderr)
		}
	}
	if len(h.p.exchanges)+len(h.p.uploads)+len(h.p.evaluates) != 0 {
		t.Fatal("contacted the platform without a token")
	}
	st := h.file("secrets.status.json")
	if !strings.Contains(st, `"ok": false`) || !strings.Contains(st, "not uploaded: the job has no OIDC token") {
		t.Fatalf("status: %s", st)
	}

	// Aggregate jobs fail the same way.
	if code, _, _ := h.run("scan", "--capability", "secrets", "--aggregate"); code != 2 {
		t.Fatalf("aggregate: exit %d", code)
	}
	// Any value other than "false" keeps the default.
	h.env["OPENCTEM_ENFORCE"] = "no"
	if code, _, _ := h.run("scan", "--capability", "secrets"); code != 2 {
		t.Fatalf("OPENCTEM_ENFORCE=no: exit %d", code)
	}
}

// The explicit opt-outs: OPENCTEM_ENFORCE=false, --no-push, no tenant, and a
// fork (which never gets a token by design).
func TestTenantWithoutOIDCOptOuts(t *testing.T) {
	h := setup(t)
	delete(h.env, "OPENCTEM_ID_TOKEN")

	h.env["OPENCTEM_ENFORCE"] = "FALSE"
	code, _, stderr := h.run("scan", "--capability", "secrets")
	if code != 0 || !strings.Contains(stderr, "scan only (OPENCTEM_ENFORCE=false)") {
		t.Fatalf("OPENCTEM_ENFORCE=false: exit %d %s", code, stderr)
	}
	delete(h.env, "OPENCTEM_ENFORCE")

	if code, _, stderr := h.run("scan", "--capability", "secrets", "--no-push"); code != 0 {
		t.Fatalf("--no-push: exit %d %s", code, stderr)
	}

	h.env["CI_MERGE_REQUEST_IID"] = "4"
	h.env["CI_MERGE_REQUEST_SOURCE_PROJECT_ID"] = "999"
	h.env["CI_MERGE_REQUEST_PROJECT_ID"] = "1"
	if code, _, stderr := h.run("scan", "--capability", "secrets"); code != 0 || !strings.Contains(stderr, "fork") {
		t.Fatalf("fork: exit %d %s", code, stderr)
	}
	for _, k := range []string{"CI_MERGE_REQUEST_IID", "CI_MERGE_REQUEST_SOURCE_PROJECT_ID", "CI_MERGE_REQUEST_PROJECT_ID"} {
		delete(h.env, k)
	}

	delete(h.env, "OPENCTEM_TENANT_ID")
	if code, _, stderr := h.run("scan", "--capability", "secrets"); code != 0 || stderr != "" {
		t.Fatalf("no tenant: exit %d %q", code, stderr)
	}
}

// A token but no API URL is a misconfiguration too.
func TestTenantWithoutAPIURLFailsClosed(t *testing.T) {
	h := setup(t)
	delete(h.env, "OPENCTEM_API_URL")
	code, _, stderr := h.run("scan", "--capability", "secrets")
	if code != 2 || !strings.Contains(stderr, "OPENCTEM_API_URL is required") {
		t.Fatalf("exit %d: %s", code, stderr)
	}
}

// The gate job fails closed too: a local verdict is not what a pipeline
// that names a tenant asked for.
func TestGateWithoutOIDCFailsClosed(t *testing.T) {
	h := setup(t)
	st := filepath.Join(h.out, "statuses")
	if code, _, stderr := h.run("scan", "--capability", "secrets", "--aggregate", "--status", filepath.Join(st, "secrets.status.json")); code != 0 {
		t.Fatalf("scan: exit %d %s", code, stderr)
	}
	delete(h.env, "OPENCTEM_ID_TOKEN")
	evaluates := len(h.p.evaluates)
	code, _, stderr := h.run("gate", "--status-dir", st, "--expect", "secrets", "--fail-on", "critical")
	if code != 2 || !strings.Contains(stderr, "no OIDC token") || len(h.p.evaluates) != evaluates {
		t.Fatalf("exit %d: %s", code, stderr)
	}
	h.env["OPENCTEM_ENFORCE"] = "false"
	code, stdout, stderr := h.run("gate", "--status-dir", st, "--expect", "secrets", "--fail-on", "critical")
	if code != 0 || !strings.Contains(stderr, "local gate only") {
		t.Fatalf("opt-out: exit %d\n%s\n%s", code, stdout, stderr)
	}
}
