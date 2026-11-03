package scope

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/openctemio/ctis/v2"
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
			{ID: "a2", Type: ctis.AssetTypeHost, Value: "10.0.0.1"},
		},
		Findings: []ctis.Finding{
			{AssetRef: "a1", Location: &ctis.FindingLocation{Path: "main.go"}},
			{AssetRef: "a2", Location: &ctis.FindingLocation{Path: "/ws/svc/api/x/y.go"},
				RelatedLocations: []*ctis.FindingLocation{{Path: "../../../etc/passwd"}}},
			{Location: &ctis.FindingLocation{Path: "/etc/shadow"}},
			{Location: &ctis.FindingLocation{Path: "./a/../b.go"}},
		},
		Dependencies: []ctis.Dependency{{Name: "x", Locations: []ctis.DependencyLocation{{Path: "go.mod"}}}},
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
		if f.AssetRef != RepoAssetID {
			t.Errorf("finding %d not attached to the repository: %+v", i, f)
		}
		if f.Location.Path != want[i] {
			t.Errorf("finding %d path %q, want %q", i, f.Location.Path, want[i])
		}
	}
	if r.Findings[1].RelatedLocations[0].Path != "" {
		t.Errorf("an escaping related location was kept: %q", r.Findings[1].RelatedLocations[0].Path)
	}
	if r.Dependencies[0].Locations[0].Path != "svc/api/go.mod" || r.Dependencies[0].AssetRef != RepoAssetID {
		t.Errorf("dependency %+v", r.Dependencies[0])
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

// Outside CI the report keeps one unclassified local asset (no repository,
// no asset of the tool's own), and every finding is filed on it.
func TestApplyWithoutRepository(t *testing.T) {
	r := &ctis.Report{Assets: []ctis.Asset{{ID: "x", Type: ctis.AssetTypeRepository, Value: "github.com/evil/x"}},
		Findings: []ctis.Finding{{AssetRef: "x"}}}
	Apply(r, Options{RepositoryPaths: true})
	if len(r.Assets) != 1 || r.Assets[0].Type != ctis.AssetTypeUnclassified || r.Findings[0].AssetRef != r.Assets[0].ID {
		t.Fatalf("%+v", r)
	}
	Apply(nil, Options{})
}

// The repository is named in its canonical form, whatever spelling the CI
// provider gave.
func TestApplyRepositoryCanonical(t *testing.T) {
	r := &ctis.Report{Findings: []ctis.Finding{{}}}
	Apply(r, Options{Repository: "GitHub.com/Acme/App", RepositoryPaths: true})
	if r.Assets[0].Value != "github.com/acme/app" {
		t.Fatalf("%q", r.Assets[0].Value)
	}
}

const digest = "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

// An image scan names the image as a container_image asset with its
// canonical digest form (Docker Hub expanded), findings are filed on it,
// and the scanner's other assets and relationships are dropped.
func TestApplyImageAsset(t *testing.T) {
	r := &ctis.Report{
		Assets: []ctis.Asset{
			{ID: "img", Type: ctis.AssetTypeContainerImage, Value: "nginx@" + digest, Name: "nginx:1.25",
				Properties: ctis.Properties{"image_id": "x"}},
			{ID: "h", Type: ctis.AssetTypeHost, Value: "host.example"},
		},
		Relationships: []ctis.Relationship{{Type: ctis.RelContains, FromRef: "img", ToRef: "h"}},
		Findings:      []ctis.Finding{{AssetRef: "h"}},
	}
	Apply(r, Options{Repository: "github.com/acme/app", Image: "nginx:1.25"})
	if len(r.Assets) != 2 || r.Assets[1].Type != ctis.AssetTypeContainerImage ||
		r.Assets[1].Value != "docker.io/library/nginx@"+digest || r.Assets[1].ID != ImageAssetID || r.Assets[1].Properties != nil {
		t.Fatalf("assets %+v", r.Assets)
	}
	if r.Findings[0].AssetRef != ImageAssetID || len(r.Relationships) != 0 {
		t.Fatalf("%+v", r)
	}
}

// With no digest from the scanner, the digest of the scanned reference
// names the image; with none anywhere a tag names no one image, so no image
// asset is written and the findings stay on the repository.
func TestApplyImageDigestSources(t *testing.T) {
	r := &ctis.Report{Findings: []ctis.Finding{{}}}
	Apply(r, Options{Repository: "github.com/acme/app", Image: "ghcr.io/acme/api@" + digest})
	if len(r.Assets) != 2 || r.Assets[1].Value != "ghcr.io/acme/api@"+digest {
		t.Fatalf("%+v", r.Assets)
	}
	r = &ctis.Report{
		Assets:   []ctis.Asset{{ID: "img", Type: ctis.AssetTypeContainerImage, Value: "nginx"}},
		Findings: []ctis.Finding{{}},
	}
	Apply(r, Options{Repository: "github.com/acme/app", Image: "nginx:latest"})
	if len(r.Assets) != 1 || r.Assets[0].Type != ctis.AssetTypeRepository || r.Findings[0].AssetRef != RepoAssetID {
		t.Fatalf("%+v", r)
	}
	for _, a := range r.Assets {
		if strings.Contains(a.Value, ":latest") {
			t.Fatalf("a tag is not an image identity: %+v", a)
		}
	}
}

// No asset, finding or dependency reference of a scoped report is UUID-shaped
// or a platform key.
func TestApplyRefsAreDocumentLocal(t *testing.T) {
	r := &ctis.Report{Findings: []ctis.Finding{{AssetRef: "6f1c2b9e-1234-4abc-8def-0123456789ab"}}}
	Apply(r, Options{Repository: "github.com/acme/app", RepositoryPaths: true})
	for _, ref := range []string{r.Assets[0].ID, r.Findings[0].AssetRef} {
		if ctis.IsUUIDShaped(ref) {
			t.Fatalf("UUID-shaped reference %q", ref)
		}
	}
}
