package main

import (
	"github.com/openctemio/ctis/v2"
)

// maxReportDependencies bounds the dependencies one SCA report uploads. The
// dependency paths stay on the findings either way.
const maxReportDependencies = 10_000

// keepFindingDependencies trims an SCA report's dependencies to the packages
// a finding names and the packages on the findings' dependency paths, plus
// the project entries (relationship root or workspace) that mark the direct
// dependencies. trivy --list-all-pkgs lists every package of the lockfiles;
// the report keeps what the findings need, so its size follows the findings,
// not the size of the dependency tree. depends_on keeps only references to
// kept packages. It returns how many dependencies it removed.
func keepFindingDependencies(r *ctis.Report) int {
	if r == nil || len(r.Dependencies) == 0 {
		return 0
	}
	// refs: the dependencies findings name by dependency_ref; sources: the
	// tool's own package ids a finding's pkg_id and dependency path name.
	refs, sources := map[string]bool{}, map[string]bool{}
	for i := range r.Findings {
		f := &r.Findings[i]
		if f.DependencyRef != "" {
			refs[f.DependencyRef] = true
		}
		v := f.Vulnerability
		if v == nil {
			continue
		}
		if id := f.SourceExtra["pkg_id"]; id != "" {
			sources[id] = true
		}
		for _, id := range v.DependencyPath {
			sources[id] = true
		}
	}
	kept := r.Dependencies[:0]
	for _, d := range r.Dependencies {
		if len(kept) >= maxReportDependencies {
			break
		}
		if refs[d.ID] || (d.SourceID != "" && sources[d.SourceID]) || d.Relationship == ctis.DependencyRoot {
			kept = append(kept, d)
		}
	}
	present := make(map[string]bool, len(kept))
	for _, d := range kept {
		present[d.ID] = true
	}
	for i := range kept {
		on := kept[i].DependsOn[:0]
		for _, id := range kept[i].DependsOn {
			if present[id] {
				on = append(on, id)
			}
		}
		if len(on) == 0 {
			on = nil
		}
		kept[i].DependsOn = on
	}
	removed := len(r.Dependencies) - len(kept)
	clear(r.Dependencies[len(kept):])
	r.Dependencies = kept
	return removed
}
