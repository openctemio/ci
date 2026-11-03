package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/openctemio/ctis/v2"
	"github.com/openctemio/ctis/v2/importer"

	"github.com/openctemio/ci/internal/capability"
	"github.com/openctemio/ci/internal/ciinfo"
	"github.com/openctemio/ci/internal/scanner"
)

const imgDigest = "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

// trivyImage is a trivy image report: one vulnerable package, the image's
// registry digest and operating system.
const trivyImage = `{"SchemaVersion":2,"ArtifactName":"nginx:1.25","ArtifactType":"container_image",
"Metadata":{"ImageID":"sha256:aaaa","RepoDigests":["nginx@` + imgDigest + `"],"OS":{"Family":"debian","Name":"12.5"}},
"Results":[{"Target":"nginx:1.25 (debian 12.5)","Class":"os-pkgs","Type":"debian","Vulnerabilities":[
{"VulnerabilityID":"CVE-2024-0001","PkgName":"libssl3","InstalledVersion":"3.0.1","FixedVersion":"3.0.2","Severity":"HIGH","Title":"openssl flaw"}]}]}`

func jobFor(t *testing.T, capName string, image string) (*scanJob, *bytes.Buffer) {
	t.Helper()
	c, ok := capability.Lookup(capName)
	if !ok {
		t.Fatal(capName)
	}
	var out bytes.Buffer
	s := &scanJob{c: c, stdout: &out, stderr: &out, info: ciinfo.Info{Repository: "github.com/acme/shop", Branch: "main", Commit: "3f1c2a9e", DefaultBranch: "main"}}
	s.f.image = image
	return s, &out
}

// assertDocumentClean checks what no CTIS 2.0 document of this job may hold:
// a platform id anywhere in its references, properties as a channel, an
// unbounded or misplaced extension.
func assertDocumentClean(t *testing.T, r *ctis.Report) {
	t.Helper()
	if err := r.Validate(); err != nil {
		t.Fatalf("not valid CTIS %s: %v", ctis.SchemaVersion, err)
	}
	if r.Version != ctis.SchemaVersion || !ctis.IsReportID(r.Metadata.ID) || r.Metadata.Channel != ctis.ChannelScanner || r.Metadata.GeneratedAt.IsZero() {
		t.Fatalf("metadata %+v version %q", r.Metadata, r.Version)
	}
	if len(r.Metadata.Properties) != 0 {
		t.Fatalf("metadata.properties carries meaning: %v", r.Metadata.Properties)
	}
	refs := []string{}
	for _, a := range r.Assets {
		refs = append(refs, a.ID)
	}
	for _, f := range r.Findings {
		refs = append(refs, f.AssetRef, f.ID, f.DependencyRef, f.RuleRef)
	}
	for _, d := range r.Dependencies {
		refs = append(refs, d.ID, d.AssetRef)
	}
	for _, ref := range refs {
		if ctis.IsUUIDShaped(ref) {
			t.Fatalf("UUID-shaped reference %q", ref)
		}
	}
	b, _ := json.Marshal(r)
	for _, banned := range []string{`"tenant`, `"run_id"`, `"scan_id"`, `"asset_` + `value"`, `"source_` + `type"`, `"image_` + `digest"`, `"container_` + `image":`} {
		if strings.Contains(string(b), banned) {
			t.Fatalf("the document holds %s: %s", banned, b)
		}
	}
	if v, ok := r.Metadata.Extensions.Get(ctis.OpenCTEMNamespace, "capability"); !ok || v == "" {
		t.Fatalf("no capability in the io.openctem extension: %v", r.Metadata.Extensions)
	}
}

func TestConvertImageScanNamesTheImageAsset(t *testing.T) {
	s, _ := jobFor(t, "container", "nginx:1.25")
	r, err := s.convert(context.Background(), &scanner.Result{Tool: "trivy", Output: []byte(trivyImage), Format: importer.FormatTrivy}, nil, nil, t.TempDir(), ".")
	if err != nil {
		t.Fatal(err)
	}
	assertDocumentClean(t, r)
	var img *ctis.Asset
	for i := range r.Assets {
		if r.Assets[i].Type == ctis.AssetTypeContainerImage {
			img = &r.Assets[i]
		}
	}
	if img == nil || img.Value != "docker.io/library/nginx@"+imgDigest {
		t.Fatalf("assets %+v", r.Assets)
	}
	for _, f := range r.Findings {
		if f.AssetRef != img.ID {
			t.Fatalf("finding on %q, want the image asset %q", f.AssetRef, img.ID)
		}
	}
	if len(r.Metadata.Targets) != 2 || r.Metadata.Targets[1].Kind != ctis.AssetTypeContainerImage || r.Metadata.Targets[1].State != ctis.TargetDone {
		t.Fatalf("targets %+v", r.Metadata.Targets)
	}
	if got := operatingSystem(r); !strings.Contains(got, "debian") {
		t.Fatalf("operating system %q", got)
	}
	if r.Metadata.CoverageType != ctis.CoveragePartial {
		t.Fatalf("an image scan covers no repository: %q", r.Metadata.CoverageType)
	}
}

// A tag alone is no image identity: no image asset, findings on the repository.
func TestConvertImageByTagOnlyHasNoImageAsset(t *testing.T) {
	noDigest := strings.Replace(trivyImage, `"RepoDigests":["nginx@`+imgDigest+`"],`, "", 1)
	s, _ := jobFor(t, "container", "nginx:1.25")
	r, err := s.convert(context.Background(), &scanner.Result{Tool: "trivy", Output: []byte(noDigest), Format: importer.FormatTrivy}, nil, nil, t.TempDir(), ".")
	if err != nil {
		t.Fatal(err)
	}
	assertDocumentClean(t, r)
	for _, a := range r.Assets {
		if a.Type == ctis.AssetTypeContainerImage {
			t.Fatalf("image asset without a digest: %+v", a)
		}
	}
	if len(r.Findings) == 0 || r.Findings[0].AssetRef != "repository" {
		t.Fatalf("%+v", r.Findings)
	}
}

func TestConvertSecretsFingerprintOnlyWithAKey(t *testing.T) {
	data, err := os.ReadFile("testdata/betterleaks.json")
	if err != nil {
		t.Fatal(err)
	}
	const raw = "Zq8vT3xK9mB2nR7wL4pY6sD1fH5jC0gA"
	key := bytes.Repeat([]byte{7}, 32)
	res := &scanner.Result{Tool: "betterleaks", Output: data, Format: importer.FormatBetterleaks}
	known := []string{raw}

	s, _ := jobFor(t, "secrets", "")
	withKey, err := s.convert(context.Background(), res, key, known, t.TempDir(), ".")
	if err != nil {
		t.Fatal(err)
	}
	assertDocumentClean(t, withKey)
	fp := withKey.Findings[0].Fingerprint
	if !strings.HasPrefix(fp, "ctis-fp/2:") {
		t.Fatalf("fingerprint %q", fp)
	}
	b, _ := json.Marshal(withKey)
	if strings.Contains(string(b), raw) || strings.Contains(string(b), string(key)) {
		t.Fatal("a raw secret or the key reached the document")
	}

	// Without a key (or with one too short) there is no secret fingerprint:
	// no unsalted hash of the value exists.
	for _, k := range [][]byte{nil, []byte("short")} {
		noKey, err := s.convert(context.Background(), res, k, known, t.TempDir(), ".")
		if err != nil {
			t.Fatal(err)
		}
		if f := noKey.Findings[0].Fingerprint; f != "" {
			t.Fatalf("fingerprint %q without a key", f)
		}
		for _, v := range noKey.Findings[0].PartialFingerprints {
			if len(v) == 64 {
				t.Fatalf("a bare digest %q in partial fingerprints", v)
			}
		}
	}
}

func TestConvertDefaultBranchFullCoverageNamesTheTarget(t *testing.T) {
	data, err := os.ReadFile("../../testdata/trivy/npm-lockfile.json")
	if err != nil {
		t.Fatal(err)
	}
	s, _ := jobFor(t, "sca", "")
	r, err := s.convert(context.Background(), &scanner.Result{Tool: "trivy", Output: data, Format: importer.FormatTrivy}, nil, nil, t.TempDir(), ".")
	if err != nil {
		t.Fatal(err)
	}
	assertDocumentClean(t, r)
	if r.Metadata.CoverageType != ctis.CoverageFull || len(r.Metadata.Targets) != 1 ||
		r.Metadata.Targets[0].Target != "github.com/acme/shop" || r.Metadata.Targets[0].State != ctis.TargetDone ||
		r.Metadata.Targets[0].Kind != ctis.AssetTypeRepository {
		t.Fatalf("%q %+v", r.Metadata.CoverageType, r.Metadata.Targets)
	}
	if len(r.Assets) != 1 || r.Assets[0].Type != ctis.AssetTypeRepository || r.Assets[0].Value != "github.com/acme/shop" {
		t.Fatalf("%+v", r.Assets)
	}
	if r.Tool == nil || len(r.Tool.Techniques) != 1 || r.Tool.Techniques[0] != ctis.TechniqueSCA {
		t.Fatalf("tool %+v", r.Tool)
	}
}

// A tool that failed after writing a partial report is a failed target, never
// a clean one.
func TestMarkPartialIsAFailedTarget(t *testing.T) {
	r, _ := convertTrivy(t, "npm-lockfile.json")
	markPartial(r, "timeout")
	if r.Metadata.CoverageType != ctis.CoveragePartial || len(r.Metadata.Targets) != 1 ||
		r.Metadata.Targets[0].State != ctis.TargetFailed || r.Metadata.Targets[0].Class != ctis.TargetClassTimeout {
		t.Fatalf("%q %+v", r.Metadata.CoverageType, r.Metadata.Targets)
	}
	if err := r.Validate(); err != nil {
		t.Fatal(err)
	}
	markPartial(r, "scan_failed")
	if r.Metadata.Targets[0].Class != ctis.TargetClassToolError {
		t.Fatalf("%+v", r.Metadata.Targets)
	}
}

// A pending report from an older openctem-ci is refused with the upgrade
// message, never uploaded.
func TestUploadPendingRefusesACTIS1Report(t *testing.T) {
	old := "1." + "6"
	_, _, err := ctis.Decode(strings.NewReader(`{"version":"` + old + `","metadata":{"id":"x"},"findings":[]}`))
	if err == nil {
		t.Fatal("a 1.x document was accepted")
	}
}

// SAST results without an advisory id are weaknesses; a rule_ref the
// importer writes names an entry of rules[] for the same rule_id; and the
// fingerprint is the CTIS 2.0 recipe, never the retired one.
func TestScanSASTUploadsWeaknessesWithRules(t *testing.T) {
	h := setupSAST(t)
	h.p.verdict = "pass"
	if code, stdout, stderr := h.run("scan", "--capability", "sast"); code != 0 {
		t.Fatalf("exit %d\n%s\n%s", code, stdout, stderr)
	}
	if len(h.p.uploads) != 1 {
		t.Fatalf("uploads: %d", len(h.p.uploads))
	}
	rep, _, err := ctis.Decode(bytes.NewReader(h.p.uploads[0]))
	if err != nil {
		t.Fatal(err)
	}
	if err := rep.Validate(); err != nil {
		t.Fatal(err)
	}
	if v, _ := rep.Metadata.Extensions.Get(ctis.OpenCTEMNamespace, "capability"); v != "sast.code@1" {
		t.Fatalf("capability %v", v)
	}
	byRef := map[string]ctis.Rule{}
	for _, r := range rep.Rules {
		byRef[r.ID] = r
	}
	if len(rep.Findings) == 0 {
		t.Fatal("no findings")
	}
	for _, f := range rep.Findings {
		if f.Type != ctis.FindingTypeWeakness {
			t.Fatalf("%s is %s, want weakness", f.RuleID, f.Type)
		}
		if r, ok := byRef[f.RuleRef]; f.RuleRef != "" && (!ok || r.RuleID != f.RuleID) {
			t.Fatalf("%s: rule_ref %q -> %+v", f.RuleID, f.RuleRef, r)
		}
		if f.Fingerprint != "" && !strings.HasPrefix(f.Fingerprint, "ctis-fp/2:") {
			t.Fatalf("%s: fingerprint %q", f.RuleID, f.Fingerprint)
		}
	}
	if rep.Tool == nil || len(rep.Tool.Techniques) != 1 || rep.Tool.Techniques[0] != ctis.TechniqueSAST {
		t.Fatalf("tool %+v", rep.Tool)
	}
}
