// Package scope keeps a scan inside the CI job's repository: the scanned
// directory must be inside the workspace, and the report names only that
// repository, with file paths relative to its root that never point
// outside it.
//
// The platform applies the same rule again (a CI run accepts only its own
// repository, taken from the verified OIDC token); this is the client half,
// so a report that would be refused is never built or written.
package scope

import (
	"errors"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/openctemio/ctis/v2"
)

// RepoAssetID is the report-local id of the repository asset.
const RepoAssetID = "repository"

// ErrOutsideWorkspace: the target is not inside the workspace.
var ErrOutsideWorkspace = errors.New("the scan target is outside the workspace")

// ResolveTarget resolves target (relative to workspace when not absolute)
// with every symbolic link followed, and refuses it unless it is the
// workspace or a directory inside it. It returns the absolute target and
// its path relative to the workspace ("." for the workspace itself), in
// slash form.
func ResolveTarget(workspace, target string) (abs, rel string, err error) {
	if workspace == "" {
		if workspace, err = os.Getwd(); err != nil {
			return "", "", err
		}
	}
	ws, err := filepath.EvalSymlinks(workspace)
	if err != nil {
		return "", "", fmt.Errorf("workspace %q: %w", workspace, err)
	}
	if ws, err = filepath.Abs(ws); err != nil {
		return "", "", err
	}
	if target == "" {
		target = "."
	}
	if !filepath.IsAbs(target) {
		target = filepath.Join(ws, target)
	}
	t, err := filepath.EvalSymlinks(target)
	if err != nil {
		return "", "", fmt.Errorf("target %q: %w", target, err)
	}
	if t, err = filepath.Abs(t); err != nil {
		return "", "", err
	}
	st, err := os.Stat(t)
	if err != nil {
		return "", "", err
	}
	if !st.IsDir() {
		return "", "", fmt.Errorf("target %q is not a directory", target)
	}
	r, err := filepath.Rel(ws, t)
	if err != nil || r == ".." || strings.HasPrefix(r, ".."+string(filepath.Separator)) || filepath.IsAbs(r) {
		return "", "", ErrOutsideWorkspace
	}
	return t, filepath.ToSlash(r), nil
}

// Options describe the job a report belongs to.
type Options struct {
	// Repository is the repository name (host/owner/name) taken from the
	// CI provider. Empty outside CI: the report then names one
	// unclassified local asset and no repository.
	Repository string
	// TargetRel is the scanned directory relative to the repository root
	// ("." for the root). Repository file paths are prefixed with it.
	TargetRel string
	// TargetAbs is the absolute scanned directory: an absolute path a tool
	// reports inside it is made relative.
	TargetAbs string
	// RepositoryPaths is false for a scan whose paths are not repository
	// files (a container image): they are kept as the tool wrote them,
	// cleaned, and never prefixed.
	RepositoryPaths bool
	// Image is the image reference the job scanned (RepositoryPaths false).
	// A report names the image as a container_image asset only when its
	// content digest is known, from the scanner or from this reference.
	Image string
}

// Stats counts what Apply changed.
type Stats struct {
	// AssetsDropped counts report assets other than the repository (and the
	// scanned image).
	AssetsDropped int
	// PathsCleared counts file paths that pointed outside the repository.
	PathsCleared int
}

// LocalAssetID is the report-local id of the asset a scan outside CI is
// filed on.
const LocalAssetID = "local-scan"

// ImageAssetID is the report-local id of the scanned image asset.
const ImageAssetID = "image"

// Apply limits report to the job's own subject: the repository asset (in
// its canonical form) and, for an image scan whose digest is known, the
// image asset; every finding and dependency attached to one of them (the
// image for an image scan, else the repository); and file paths relative to
// the repository root. Relationships and endpoints of dropped assets are
// removed. Without a repository the report holds one unclassified local
// asset instead.
func Apply(report *ctis.Report, o Options) Stats {
	var st Stats
	if report == nil {
		return st
	}
	repo := strings.TrimSpace(o.Repository)
	if repo != "" {
		if c, err := ctis.CanonicalRepository(repo); err == nil {
			repo = c
		}
	}
	var image *ctis.Asset
	if !o.RepositoryPaths {
		image = imageAsset(report, o.Image)
	}
	for _, a := range report.Assets {
		keep := (a.Type == ctis.AssetTypeRepository && repo != "" && a.Value == repo) ||
			(image != nil && a.ID == image.ID)
		if !keep {
			st.AssetsDropped++
		}
	}
	report.Assets = nil
	subject := RepoAssetID
	switch {
	case repo != "":
		report.Assets = []ctis.Asset{{ID: RepoAssetID, Type: ctis.AssetTypeRepository, Value: repo, Name: repo}}
	default:
		subject = LocalAssetID
		report.Assets = []ctis.Asset{{ID: LocalAssetID, Type: ctis.AssetTypeUnclassified, Value: "local scan", Name: "local scan"}}
	}
	if image != nil {
		image.ID = ImageAssetID
		report.Assets = append(report.Assets, *image)
		subject = ImageAssetID
	}
	report.Relationships, report.Endpoints = nil, nil
	fix := func(p string) string {
		np, ok := normalize(p, o)
		if !ok {
			st.PathsCleared++
		}
		return np
	}
	for i := range report.Findings {
		f := &report.Findings[i]
		f.AssetRef = subject
		fixLocation(f.Location, fix)
		for _, l := range f.RelatedLocations {
			fixLocation(l, fix)
		}
		for _, s := range f.Stacks {
			if s == nil {
				continue
			}
			for _, fr := range s.Frames {
				if fr != nil {
					fixLocation(fr.Location, fix)
				}
			}
		}
		for _, a := range f.Attachments {
			if a == nil {
				continue
			}
			for _, rg := range a.Regions {
				fixLocation(rg, fix)
			}
			if al := a.ArtifactLocation; al != nil && al.URI != "" {
				al.URI = fix(al.URI)
			}
		}
		if df := f.DataFlow; df != nil {
			for _, set := range [][]ctis.DataFlowLocation{df.Sources, df.Intermediates, df.Sinks, df.Sanitizers} {
				for i := range set {
					if set[i].Path != "" {
						set[i].Path = fix(set[i].Path)
					}
				}
			}
		}
	}
	for i := range report.Dependencies {
		d := &report.Dependencies[i]
		d.AssetRef = subject
		for j := range d.Locations {
			if d.Locations[j].Path != "" {
				d.Locations[j].Path = fix(d.Locations[j].Path)
			}
		}
	}
	return st
}

func fixLocation(l *ctis.FindingLocation, fix func(string) string) {
	if l != nil && l.Path != "" {
		l.Path = fix(l.Path)
	}
}

// normalize returns the path relative to the repository root, or "" and
// false when it points outside the repository.
func normalize(p string, o Options) (string, bool) {
	p = strings.TrimSpace(strings.ReplaceAll(p, "\\", "/"))
	p = strings.TrimPrefix(p, "file://")
	if p == "" {
		return "", true
	}
	if !o.RepositoryPaths {
		c := path.Clean(p)
		if strings.HasPrefix(c, "../") || c == ".." {
			return "", false
		}
		return c, true
	}
	if path.IsAbs(p) {
		base := filepath.ToSlash(o.TargetAbs)
		if base == "" || (p != base && !strings.HasPrefix(p, strings.TrimSuffix(base, "/")+"/")) {
			return "", false
		}
		p = strings.TrimPrefix(strings.TrimPrefix(p, base), "/")
	}
	rel := o.TargetRel
	if rel == "" {
		rel = "."
	}
	c := path.Clean(path.Join(rel, p))
	if c == ".." || strings.HasPrefix(c, "../") || path.IsAbs(c) {
		return "", false
	}
	return c, true
}

// imageAsset is the report's container_image asset with its content digest:
// the scanner's own when its value names a digest, else the digest of the
// reference the job scanned. nil when the digest is unknown (a tag names no
// one image). The copy is detached from the report.
func imageAsset(r *ctis.Report, ref string) *ctis.Asset {
	var found *ctis.Asset
	for i := range r.Assets {
		if r.Assets[i].Type == ctis.AssetTypeContainerImage {
			found = &r.Assets[i]
			break
		}
	}
	if found != nil {
		if c, err := ctis.CanonicalImage(found.Value); err == nil && strings.Contains(c, "@sha256:") {
			a := *found
			a.Value, a.Properties = c, nil
			return &a
		}
	}
	if c, err := ctis.CanonicalImage(strings.TrimSpace(ref)); err == nil && strings.Contains(c, "@sha256:") {
		a := ctis.Asset{ID: ImageAssetID, Type: ctis.AssetTypeContainerImage, Value: c, Name: c}
		if found != nil {
			a = *found
			a.Value, a.Name, a.Properties = c, nonEmpty(found.Name, c), nil
		}
		return &a
	}
	return nil
}

func nonEmpty(s, fallback string) string {
	if s == "" {
		return fallback
	}
	return s
}
