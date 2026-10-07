package scope

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/openctemio/ctis"
)

func TestResolveTarget(t *testing.T) {
	ws := t.TempDir()
	if err := os.MkdirAll(filepath.Join(ws, "svc", "api"), 0o755); err != nil {
		t.Fatal(err)
	}
	outside := t.TempDir()
	if err := os.Symlink(outside, filepath.Join(ws, "escape")); err != nil {
		t.Fatal(err)
	}

	abs, rel, err := ResolveTarget(ws, ".")
	if err != nil || rel != "." || abs == "" {
		t.Fatalf("root: %q %q %v", abs, rel, err)
	}
	if _, rel, err = ResolveTarget(ws, "svc/api"); err != nil || rel != "svc/api" {
		t.Fatalf("subdir: %q %v", rel, err)
	}
	for _, bad := range []string{"..", "../..", outside, "escape", "svc/../../x"} {
		if _, _, err := ResolveTarget(ws, bad); err == nil {
			t.Errorf("%q accepted", bad)
		} else if bad == "escape" && !errors.Is(err, ErrOutsideWorkspace) {
			t.Errorf("symlink escape: %v", err)
		}
	}
	f := filepath.Join(ws, "file")
	if err := os.WriteFile(f, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := ResolveTarget(ws, "file"); err == nil {
		t.Error("a file target was accepted")
	}
}

func TestApplyRepository(t *testing.T) {
	r := &ctis.Report{
		Assets: []ctis.Asset{
			{ID: "a1", Type: ctis.AssetTypeRepository, Value: "github.com/evil/other"},
			{ID: "a2", Type: "host", Value: "10.0.0.1"},
		},
		Findings: []ctis.Finding{
			{AssetRef: "a1", AssetValue: "github.com/evil/other", Location: &ctis.FindingLocation{Path: "main.go"}},
			{AssetRef: "a2", Location: &ctis.FindingLocation{Path: "/ws/svc/api/x/y.go"},
				RelatedLocations: []*ctis.FindingLocation{{Path: "../../../etc/passwd"}}},
			{Location: &ctis.FindingLocation{Path: "/etc/shadow"}},
			{Location: &ctis.FindingLocation{Path: "./a/../b.go"}},
		},
		Dependencies: []ctis.Dependency{{Name: "x", Path: "go.mod"}},
	}
	st := Apply(r, Options{Repository: "github.com/acme/app", TargetRel: "svc/api", TargetAbs: "/ws/svc/api", RepositoryPaths: true})
	if len(r.Assets) != 1 || r.Assets[0].Value != "github.com/acme/app" || r.Assets[0].ID != RepoAssetID {
		t.Fatalf("assets %+v", r.Assets)
	}
	if st.AssetsDropped != 2 || st.PathsCleared != 2 {
		t.Fatalf("stats %+v", st)
	}
	want := []string{"svc/api/main.go", "svc/api/x/y.go", "", "svc/api/b.go"}
	for i, f := range r.Findings {
		if f.AssetRef != RepoAssetID || f.AssetValue != "" {
			t.Errorf("finding %d not attached to the repository: %+v", i, f)
		}
		if f.Location.Path != want[i] {
			t.Errorf("finding %d path %q, want %q", i, f.Location.Path, want[i])
		}
	}
	if r.Findings[1].RelatedLocations[0].Path != "" {
		t.Errorf("an escaping related location was kept: %q", r.Findings[1].RelatedLocations[0].Path)
	}
	if r.Dependencies[0].Path != "svc/api/go.mod" {
		t.Errorf("dependency path %q", r.Dependencies[0].Path)
	}
}

// Image paths are not repository files: kept (cleaned), never prefixed.
func TestApplyImagePaths(t *testing.T) {
	r := &ctis.Report{Findings: []ctis.Finding{
		{Location: &ctis.FindingLocation{Path: "usr/lib/libssl.so"}},
		{Location: &ctis.FindingLocation{Path: "../x"}},
	}}
	Apply(r, Options{Repository: "github.com/acme/app", TargetRel: "svc", RepositoryPaths: false})
	if r.Findings[0].Location.Path != "usr/lib/libssl.so" || r.Findings[1].Location.Path != "" {
		t.Fatalf("%+v %+v", r.Findings[0].Location, r.Findings[1].Location)
	}
}

func TestApplyWithoutRepository(t *testing.T) {
	r := &ctis.Report{Assets: []ctis.Asset{{ID: "x", Type: "repository", Value: "x"}},
		Findings: []ctis.Finding{{AssetRef: "x"}}}
	Apply(r, Options{RepositoryPaths: true})
	if len(r.Assets) != 0 || r.Findings[0].AssetRef != "" {
		t.Fatalf("%+v", r)
	}
	Apply(nil, Options{})
}
