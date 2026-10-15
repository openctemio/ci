package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// A change that commits a trivy cache (a database whose metadata says it is
// fresh) and a pipeline whose TRIVY_CACHE_DIR points into the checkout, as
// the earlier GitLab templates did: the scan refuses to run, uploads
// nothing and records a scan failure, so the run fails instead of looking
// clean.
func TestCommittedTrivyCacheCannotSuppressResults(t *testing.T) {
	h := setup(t)
	cache := filepath.Join(h.ws, ".openctem-trivy-cache")
	if err := os.MkdirAll(filepath.Join(cache, "db"), 0o755); err != nil {
		t.Fatal(err)
	}
	poisoned := `{"Version":2,"NextUpdate":"2099-01-01T00:00:00Z","UpdatedAt":"2026-10-01T00:00:00Z"}`
	if err := os.WriteFile(filepath.Join(cache, "db", "metadata.json"), []byte(poisoned), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(cache, "db", "trivy.db"), []byte("empty"), 0o644); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{{"init", "-q"}, {"add", "."}, {"-c", "user.email=t@example.com", "-c", "user.name=t", "commit", "-qm", "cache"}} {
		cmd := exec.Command("git", args...)
		cmd.Dir = h.ws
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v %s", args, err, out)
		}
	}
	// The stand-in trivy would report nothing at all: it must never run.
	ran := filepath.Join(h.out, "trivy-ran")
	bin := t.TempDir()
	if err := os.WriteFile(filepath.Join(bin, "trivy"), []byte("#!/bin/sh\ntouch "+ran+"\necho '{\"Results\":[]}' > \"$5\"\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	h.env["PATH"] = bin + ":" + h.env["PATH"]
	h.env["TRIVY_CACHE_DIR"] = cache

	for _, c := range []string{"sca", "iac"} {
		status := filepath.Join(h.out, c+".status.json")
		code, _, stderr := h.run("scan", "--capability", c, "--status", status)
		if code != 2 || !strings.Contains(stderr, "trivy cache directory is inside the checkout") {
			t.Fatalf("%s: exit %d: %s", c, code, stderr)
		}
		if st := h.file(c + ".status.json"); !strings.Contains(st, `"ok": false`) {
			t.Fatalf("%s status: %s", c, st)
		}
	}
	if _, err := os.Stat(ran); !os.IsNotExist(err) {
		t.Fatal("trivy ran with the committed cache")
	}
	if len(h.p.uploads) != 0 {
		t.Fatalf("%d report(s) uploaded: an empty report would look clean", len(h.p.uploads))
	}
	for _, e := range h.p.evaluates {
		if e["scan_failures"] != 1 {
			t.Fatalf("evaluate %v: the failed scan was not reported", e)
		}
	}

	// The same committed directory is inert once the cache lives outside
	// the checkout (the templates now use the image's default).
	h.env["TRIVY_CACHE_DIR"] = filepath.Join(t.TempDir(), "trivy")
	if code, _, stderr := h.run("scan", "--capability", "iac", "--no-push"); code != 0 {
		t.Fatalf("cache outside the checkout: exit %d %s", code, stderr)
	}
}
