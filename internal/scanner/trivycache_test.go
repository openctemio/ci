package scanner

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestTrivyCacheDir(t *testing.T) {
	cases := []struct {
		env  []string
		want string
	}{
		{[]string{"TRIVY_CACHE_DIR=/c", "XDG_CACHE_HOME=/x", "HOME=/h"}, "/c"},
		{[]string{"XDG_CACHE_HOME=/x", "HOME=/h"}, "/x/trivy"},
		{[]string{"HOME=/h"}, "/h/.cache/trivy"},
		{[]string{"TRIVY_CACHE_DIR=rel/cache"}, "/run/rel/cache"},
		{[]string{"TRIVY_CACHE_DIR=/a", "TRIVY_CACHE_DIR=/b"}, "/b"},
		{nil, ""},
	}
	for _, c := range cases {
		if got := trivyCacheDir(c.env, "/run"); got != c.want {
			t.Errorf("%v: %q, want %q", c.env, got, c.want)
		}
	}
}

func TestCheckTrivyCache(t *testing.T) {
	ws := t.TempDir()
	outside := t.TempDir()
	if err := os.MkdirAll(filepath.Join(ws, "app"), 0o755); err != nil {
		t.Fatal(err)
	}
	// A link in the checkout that points into it, and one that points out.
	if err := os.Symlink(filepath.Join(ws, "app"), filepath.Join(outside, "into-ws")); err != nil {
		t.Fatal(err)
	}
	refused := [][]string{
		{"TRIVY_CACHE_DIR=" + filepath.Join(ws, ".openctem-trivy-cache")},
		{"TRIVY_CACHE_DIR=" + ws},
		{"TRIVY_CACHE_DIR=.cache"}, // relative: under the directory trivy runs in
		{"TRIVY_CACHE_DIR=" + filepath.Join(outside, "into-ws", "cache")},
		{"TRIVY_CACHE_DIR=" + filepath.Join(ws, "app", "..", "x")},
		{"XDG_CACHE_HOME=" + filepath.Join(ws, "xdg")},
		{"HOME=" + ws},
	}
	for _, env := range refused {
		if err := checkTrivyCache(env, filepath.Join(ws, "app"), filepath.Join(ws, "app"), ws); !errors.Is(err, ErrCacheInCheckout) {
			t.Errorf("%v: %v, want refused", env, err)
		}
	}
	allowed := [][]string{
		{"TRIVY_CACHE_DIR=" + filepath.Join(outside, "cache")},
		{"TRIVY_CACHE_DIR=" + ws + "-cache"}, // a sibling with the same prefix
		{"HOME=" + outside},
		nil,
	}
	for _, env := range allowed {
		if err := checkTrivyCache(env, ws, ws); err != nil {
			t.Errorf("%v: %v", env, err)
		}
	}
}

// A trivy cache in the checkout stops the scan before trivy runs: a
// committed database cannot decide what the scan finds.
func TestRunRefusesTrivyCacheInCheckout(t *testing.T) {
	bin := t.TempDir()
	ran := filepath.Join(t.TempDir(), "ran")
	if err := os.WriteFile(filepath.Join(bin, "trivy"), []byte("#!/bin/sh\ntouch "+ran+"\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	ws := t.TempDir()
	for _, name := range []string{"sca", "iac"} {
		_, err := Run(context.Background(), capOf(t, name), Options{Target: ws, Root: ws, Timeout: time.Minute,
			Environ: func() []string {
				return []string{"PATH=" + bin + ":/usr/bin:/bin", "TRIVY_CACHE_DIR=" + filepath.Join(ws, ".openctem-trivy-cache")}
			}})
		if !errors.Is(err, ErrCacheInCheckout) {
			t.Fatalf("%s: %v", name, err)
		}
	}
	if _, err := os.Stat(ran); !os.IsNotExist(err) {
		t.Fatal("trivy ran with a cache in the checkout")
	}
}
