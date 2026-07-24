package supplychain

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type fixture struct {
	root     string
	manifest Manifest
	anchor   TrustAnchor
	private  ed25519.PrivateKey
	opts     VerifyOptions
}

func newFixture(t *testing.T) fixture {
	t.Helper()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	now := time.Date(2026, 7, 23, 12, 0, 0, 0, time.UTC)
	f := fixture{
		root:    root,
		private: privateKey,
		anchor: TrustAnchor{
			Version:      1,
			KeyID:        "operator-release-2026-q3",
			PublicKeyB64: base64.StdEncoding.EncodeToString(publicKey),
			NotBefore:    now.Add(-time.Hour),
			NotAfter:     now.Add(365 * 24 * time.Hour),
		},
		opts: VerifyOptions{
			ExpectedSourceRepo:   "https://github.com/ArowuTest/Nirvet",
			ExpectedSourceCommit: strings.Repeat("a", 40),
			MinimumSequence:      12,
			InstalledSequence:    12,
			Now:                  now,
		},
	}
	f.manifest = Manifest{
		Version:         ManifestVersion,
		Release:         "2026.07.23",
		ReleaseSequence: 12,
		SourceRepo:      f.opts.ExpectedSourceRepo,
		SourceCommit:    f.opts.ExpectedSourceCommit,
		KeyID:           f.anchor.KeyID,
	}
	for i, kind := range RequiredArtifactKinds {
		f.manifest.Artifacts = append(f.manifest.Artifacts, f.writeArtifact(t, kind, i))
	}
	if err := WriteCanonicalJSON(filepath.Join(root, "trust-anchor.json"), f.anchor); err != nil {
		t.Fatal(err)
	}
	if err := WriteCanonicalJSON(filepath.Join(root, "release.manifest.json"), f.manifest); err != nil {
		t.Fatal(err)
	}
	manifestDigest, err := FileDigest(filepath.Join(root, "release.manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "release.manifest.sig"), []byte(SignDigest(privateKey, "manifest", manifestDigest)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	f.opts.AllowExtra = map[string]bool{}
	return f
}

func (f fixture) writeArtifact(t *testing.T, kind string, index int) Artifact {
	t.Helper()
	base := fmt.Sprintf("artifacts/%02d-%s", index, kind)
	paths := []string{base, base + ".sig", base + ".cdx.json", base + ".cdx.sig", base + ".provenance.json", base + ".provenance.sig", base + ".deps"}
	for _, path := range paths {
		if err := os.MkdirAll(filepath.Dir(filepath.Join(f.root, path)), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(f.root, base), []byte("deployable:"+kind+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	artifactDigest, err := FileDigest(filepath.Join(f.root, base))
	if err != nil {
		t.Fatal(err)
	}
	dependencies := []string{"dep.example/core@1.2.3", "dep.example/runtime@4.5.6"}
	if err := os.WriteFile(filepath.Join(f.root, base+".deps"), []byte(strings.Join(dependencies, "\n")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	dependencyDigest, err := FileDigest(filepath.Join(f.root, base+".deps"))
	if err != nil {
		t.Fatal(err)
	}
	sbom := SBOM{
		BOMFormat:    "CycloneDX",
		SpecVersion:  "1.6",
		SerialNumber: "urn:uuid:" + fmt.Sprintf("%08d-0000-4000-8000-000000000000", index),
		Metadata:     SBOMMetadata{Component: SBOMComponent{Type: "application", Name: kind, Version: artifactDigest}},
		Components: []SBOMComponent{
			{Type: "library", Name: "dep.example/core", Version: "1.2.3"},
			{Type: "library", Name: "dep.example/runtime", Version: "4.5.6"},
		},
	}
	if err := WriteCanonicalJSON(filepath.Join(f.root, base+".cdx.json"), sbom); err != nil {
		t.Fatal(err)
	}
	sbomDigest, err := FileDigest(filepath.Join(f.root, base+".cdx.json"))
	if err != nil {
		t.Fatal(err)
	}
	provenance := Provenance{
		Version:         1,
		SubjectDigest:   artifactDigest,
		ArtifactKind:    kind,
		SourceRepo:      f.manifest.SourceRepo,
		SourceCommit:    f.manifest.SourceCommit,
		BuilderIdentity: "github-actions://ArowuTest/Nirvet/release",
		BuildRecipe:     ".github/workflows/supply-chain.yml",
		BuildParameters: map[string]string{"target": kind},
		ReleaseSequence: f.manifest.ReleaseSequence,
	}
	if err := WriteCanonicalJSON(filepath.Join(f.root, base+".provenance.json"), provenance); err != nil {
		t.Fatal(err)
	}
	provenanceDigest, err := FileDigest(filepath.Join(f.root, base+".provenance.json"))
	if err != nil {
		t.Fatal(err)
	}
	writeSignature := func(path, objectType, digest string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(f.root, path), []byte(SignDigest(f.private, objectType, digest)+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	writeSignature(base+".sig", "artifact", artifactDigest)
	writeSignature(base+".cdx.sig", "sbom", sbomDigest)
	writeSignature(base+".provenance.sig", "provenance", provenanceDigest)
	return Artifact{
		Kind:               kind,
		Path:               base,
		Digest:             artifactDigest,
		SignaturePath:      base + ".sig",
		SBOMPath:           base + ".cdx.json",
		SBOMDigest:         sbomDigest,
		SBOMSignaturePath:  base + ".cdx.sig",
		ProvenancePath:     base + ".provenance.json",
		ProvenanceDigest:   provenanceDigest,
		ProvenanceSigPath:  base + ".provenance.sig",
		DependencyListPath: base + ".deps",
		DependencyListHash: dependencyDigest,
	}
}

func verifyFixture(t *testing.T, f fixture) error {
	t.Helper()
	manifestDigest, err := FileDigest(filepath.Join(f.root, "release.manifest.json"))
	if err != nil {
		return err
	}
	signature, err := os.ReadFile(filepath.Join(f.root, "release.manifest.sig"))
	if err != nil {
		return err
	}
	publicBytes, err := base64.StdEncoding.DecodeString(f.anchor.PublicKeyB64)
	if err != nil {
		return err
	}
	if err := VerifyDigest(ed25519.PublicKey(publicBytes), "manifest", manifestDigest, string(signature)); err != nil {
		return err
	}
	return VerifyRelease(f.root, f.manifest, f.anchor, f.opts)
}

func TestVerifyReleaseAcceptsCompleteOfflineFixture(t *testing.T) {
	f := newFixture(t)
	if err := verifyFixture(t, f); err != nil {
		t.Fatal(err)
	}
}

func TestVerifyReleaseRefusesUnsignedArtifact(t *testing.T) {
	f := newFixture(t)
	if err := os.Remove(filepath.Join(f.root, f.manifest.Artifacts[0].SignaturePath)); err != nil {
		t.Fatal(err)
	}
	if err := verifyFixture(t, f); err == nil {
		t.Fatal("unsigned artifact was accepted")
	}
}

func TestVerifyReleaseRefusesTamperedArtifact(t *testing.T) {
	f := newFixture(t)
	if err := os.WriteFile(filepath.Join(f.root, f.manifest.Artifacts[0].Path), []byte("tampered"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := verifyFixture(t, f); err == nil || !strings.Contains(err.Error(), "digest mismatch") {
		t.Fatalf("tampered artifact was not refused: %v", err)
	}
}

func TestVerifyReleaseRefusesWrongOrRevokedKey(t *testing.T) {
	f := newFixture(t)
	publicKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	f.anchor.PublicKeyB64 = base64.StdEncoding.EncodeToString(publicKey)
	if err := verifyFixture(t, f); err == nil {
		t.Fatal("wrong trust anchor was accepted")
	}
	f = newFixture(t)
	f.anchor.Revoked = true
	if err := verifyFixture(t, f); err == nil || !strings.Contains(err.Error(), "revoked") {
		t.Fatalf("revoked key was accepted: %v", err)
	}
}

func TestVerifyReleaseRefusesForgedProvenance(t *testing.T) {
	f := newFixture(t)
	a := f.manifest.Artifacts[0]
	var provenance Provenance
	if err := readJSON(filepath.Join(f.root, a.ProvenancePath), &provenance); err != nil {
		t.Fatal(err)
	}
	provenance.SourceCommit = strings.Repeat("b", 40)
	if err := WriteCanonicalJSON(filepath.Join(f.root, a.ProvenancePath), provenance); err != nil {
		t.Fatal(err)
	}
	if err := verifyFixture(t, f); err == nil {
		t.Fatal("forged provenance was accepted")
	}
}

func TestVerifyReleaseRefusesLyingSBOM(t *testing.T) {
	f := newFixture(t)
	a := f.manifest.Artifacts[0]
	if err := os.WriteFile(filepath.Join(f.root, a.DependencyListPath), []byte("dep.example/core@1.2.3\ndep.example/runtime@4.5.6\ndep.example/unlisted@9.9.9\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	newDigest, err := FileDigest(filepath.Join(f.root, a.DependencyListPath))
	if err != nil {
		t.Fatal(err)
	}
	f.manifest.Artifacts[0].DependencyListHash = newDigest
	if err := verifyFixture(t, f); err == nil || !strings.Contains(err.Error(), "SBOM missing") {
		t.Fatalf("lying SBOM was accepted: %v", err)
	}
}

func TestVerifyReleaseRefusesDowngrade(t *testing.T) {
	f := newFixture(t)
	f.opts.MinimumSequence = 13
	if err := verifyFixture(t, f); err == nil || !strings.Contains(err.Error(), "downgrade") {
		t.Fatalf("downgrade was accepted: %v", err)
	}
}

func TestVerifyReleaseRefusesUnlistedFile(t *testing.T) {
	f := newFixture(t)
	if err := os.WriteFile(filepath.Join(f.root, "artifacts/unlisted-plugin.so"), []byte("dependency"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := verifyFixture(t, f); err == nil || !strings.Contains(err.Error(), "unlisted file") {
		t.Fatalf("unlisted file was accepted: %v", err)
	}
}
