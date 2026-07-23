package supplychain

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

var ErrVerification = errors.New("supply-chain verification failed")

const ManifestVersion = 1

var RequiredArtifactKinds = []string{
	"container-backend", "container-frontend", "container-migrate",
	"binary-api", "binary-worker", "binary-migrate",
	"helm-chart", "airgap-bundle",
}

type TrustAnchor struct {
	Version      int       `json:"version"`
	KeyID        string    `json:"key_id"`
	PublicKeyB64 string    `json:"public_key_b64"`
	NotBefore    time.Time `json:"not_before"`
	NotAfter     time.Time `json:"not_after"`
	Revoked      bool      `json:"revoked"`
}

type Provenance struct {
	Version         int               `json:"version"`
	SubjectDigest   string            `json:"subject_digest"`
	ArtifactKind    string            `json:"artifact_kind"`
	SourceRepo      string            `json:"source_repo"`
	SourceCommit    string            `json:"source_commit"`
	BuilderIdentity string            `json:"builder_identity"`
	BuildRecipe     string            `json:"build_recipe"`
	BuildParameters map[string]string `json:"build_parameters"`
	ReleaseSequence uint64            `json:"release_sequence"`
}

type SBOM struct {
	BOMFormat    string          `json:"bomFormat"`
	SpecVersion  string          `json:"specVersion"`
	SerialNumber string          `json:"serialNumber"`
	Metadata     SBOMMetadata    `json:"metadata"`
	Components   []SBOMComponent `json:"components"`
}

type SBOMMetadata struct {
	Component SBOMComponent `json:"component"`
}

type SBOMComponent struct {
	Type     string `json:"type"`
	Name     string `json:"name"`
	Version  string `json:"version"`
	PURL     string `json:"purl,omitempty"`
	Licenses []any  `json:"licenses,omitempty"`
}

type Artifact struct {
	Kind               string `json:"kind"`
	Path               string `json:"path"`
	Digest             string `json:"digest"`
	SignaturePath      string `json:"signature_path"`
	SBOMPath           string `json:"sbom_path"`
	SBOMDigest         string `json:"sbom_digest"`
	SBOMSignaturePath  string `json:"sbom_signature_path"`
	ProvenancePath     string `json:"provenance_path"`
	ProvenanceDigest   string `json:"provenance_digest"`
	ProvenanceSigPath  string `json:"provenance_signature_path"`
	DependencyListPath string `json:"dependency_list_path"`
	DependencyListHash string `json:"dependency_list_digest"`
}

type Manifest struct {
	Version         int        `json:"version"`
	Release         string     `json:"release"`
	ReleaseSequence uint64     `json:"release_sequence"`
	SourceRepo      string     `json:"source_repo"`
	SourceCommit    string     `json:"source_commit"`
	KeyID           string     `json:"key_id"`
	Artifacts       []Artifact `json:"artifacts"`
}

type VerifyOptions struct {
	ExpectedSourceRepo   string
	ExpectedSourceCommit string
	MinimumSequence      uint64
	InstalledSequence    uint64
	Now                  time.Time
	AllowExtra           map[string]bool
}

func SignDigest(privateKey ed25519.PrivateKey, objectType, digest string) string {
	payload := []byte("nirvet-artifact-v1\n" + objectType + "\n" + digest + "\n")
	return base64.StdEncoding.EncodeToString(ed25519.Sign(privateKey, payload))
}

func VerifyDigest(publicKey ed25519.PublicKey, objectType, digest, signature string) error {
	sig, err := base64.StdEncoding.DecodeString(strings.TrimSpace(signature))
	if err != nil || !ed25519.Verify(publicKey, []byte("nirvet-artifact-v1\n"+objectType+"\n"+digest+"\n"), sig) {
		return fmt.Errorf("%w: invalid %s signature", ErrVerification, objectType)
	}
	return nil
}

func VerifyRelease(root string, manifest Manifest, anchor TrustAnchor, opts VerifyOptions) error {
	if manifest.Version != ManifestVersion || anchor.Version != 1 {
		return fmt.Errorf("%w: unsupported manifest or trust-anchor version", ErrVerification)
	}
	if anchor.Revoked || anchor.KeyID == "" || manifest.KeyID != anchor.KeyID {
		return fmt.Errorf("%w: untrusted or revoked signing key", ErrVerification)
	}
	now := opts.Now.UTC()
	if now.IsZero() { now = time.Now().UTC() }
	if now.Before(anchor.NotBefore) || !now.Before(anchor.NotAfter) {
		return fmt.Errorf("%w: trust anchor outside validity period", ErrVerification)
	}
	pubBytes, err := base64.StdEncoding.DecodeString(anchor.PublicKeyB64)
	if err != nil || len(pubBytes) != ed25519.PublicKeySize {
		return fmt.Errorf("%w: malformed trust anchor", ErrVerification)
	}
	pub := ed25519.PublicKey(pubBytes)
	if manifest.ReleaseSequence < opts.MinimumSequence || manifest.ReleaseSequence < opts.InstalledSequence {
		return fmt.Errorf("%w: downgrade release sequence %d", ErrVerification, manifest.ReleaseSequence)
	}
	if opts.ExpectedSourceRepo != "" && manifest.SourceRepo != opts.ExpectedSourceRepo {
		return fmt.Errorf("%w: source repository mismatch", ErrVerification)
	}
	if opts.ExpectedSourceCommit != "" && manifest.SourceCommit != opts.ExpectedSourceCommit {
		return fmt.Errorf("%w: source commit mismatch", ErrVerification)
	}
	if err := verifyKinds(manifest.Artifacts); err != nil { return err }
	listed := map[string]bool{"release.manifest.json": true, "release.manifest.sig": true, "trust-anchor.json": true}
	for _, a := range manifest.Artifacts {
		paths := []string{a.Path, a.SignaturePath, a.SBOMPath, a.SBOMSignaturePath, a.ProvenancePath, a.ProvenanceSigPath, a.DependencyListPath}
		for _, p := range paths {
			if err := safeRelative(p); err != nil { return err }
			if listed[p] { return fmt.Errorf("%w: duplicate manifest path %q", ErrVerification, p) }
			listed[p] = true
		}
		if err := verifyOne(root, a, manifest, pub); err != nil { return err }
	}
	for p := range opts.AllowExtra { listed[p] = true }
	return verifyClosedTree(root, listed)
}

func verifyOne(root string, a Artifact, m Manifest, pub ed25519.PublicKey) error {
	artifactDigest, err := FileDigest(filepath.Join(root, a.Path)); if err != nil { return err }
	if artifactDigest != a.Digest { return fmt.Errorf("%w: artifact digest mismatch for %s", ErrVerification, a.Path) }
	if err := verifySignatureFile(root, a.SignaturePath, pub, "artifact", a.Digest); err != nil { return err }

	sbomDigest, err := FileDigest(filepath.Join(root, a.SBOMPath)); if err != nil { return err }
	if sbomDigest != a.SBOMDigest { return fmt.Errorf("%w: SBOM digest mismatch for %s", ErrVerification, a.Path) }
	if err := verifySignatureFile(root, a.SBOMSignaturePath, pub, "sbom", a.SBOMDigest); err != nil { return err }
	var sbom SBOM
	if err := readJSON(filepath.Join(root, a.SBOMPath), &sbom); err != nil { return fmt.Errorf("%w: invalid SBOM: %v", ErrVerification, err) }
	if sbom.BOMFormat != "CycloneDX" || sbom.Metadata.Component.Name == "" || sbom.Metadata.Component.Version != a.Digest {
		return fmt.Errorf("%w: SBOM not bound to artifact digest", ErrVerification)
	}
	if err := verifyDependencyCompleteness(filepath.Join(root, a.DependencyListPath), a.DependencyListHash, sbom); err != nil { return err }

	provDigest, err := FileDigest(filepath.Join(root, a.ProvenancePath)); if err != nil { return err }
	if provDigest != a.ProvenanceDigest { return fmt.Errorf("%w: provenance digest mismatch for %s", ErrVerification, a.Path) }
	if err := verifySignatureFile(root, a.ProvenanceSigPath, pub, "provenance", a.ProvenanceDigest); err != nil { return err }
	var p Provenance
	if err := readJSON(filepath.Join(root, a.ProvenancePath), &p); err != nil { return fmt.Errorf("%w: invalid provenance: %v", ErrVerification, err) }
	if p.Version != 1 || p.SubjectDigest != a.Digest || p.ArtifactKind != a.Kind || p.SourceRepo != m.SourceRepo || p.SourceCommit != m.SourceCommit || p.ReleaseSequence != m.ReleaseSequence || p.BuilderIdentity == "" || p.BuildRecipe == "" {
		return fmt.Errorf("%w: forged or mismatched provenance for %s", ErrVerification, a.Path)
	}
	return nil
}

func verifyKinds(artifacts []Artifact) error {
	seen := map[string]int{}
	for _, a := range artifacts { seen[a.Kind]++ }
	for _, kind := range RequiredArtifactKinds {
		if seen[kind] != 1 { return fmt.Errorf("%w: artifact kind %s count=%d want 1", ErrVerification, kind, seen[kind]) }
	}
	if len(artifacts) != len(RequiredArtifactKinds) { return fmt.Errorf("%w: unexpected artifact kind", ErrVerification) }
	return nil
}

func verifyDependencyCompleteness(path, expectedHash string, sbom SBOM) error {
	digest, err := FileDigest(path); if err != nil { return err }
	if digest != expectedHash { return fmt.Errorf("%w: dependency inventory digest mismatch", ErrVerification) }
	data, err := os.ReadFile(path); if err != nil { return fmt.Errorf("%w: dependency inventory: %v", ErrVerification, err) }
	components := map[string]bool{}
	for _, c := range sbom.Components { components[c.Name+"@"+c.Version] = true }
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line); if line == "" || strings.HasPrefix(line, "#") { continue }
		if !components[line] { return fmt.Errorf("%w: SBOM missing real dependency %s", ErrVerification, line) }
	}
	return nil
}

func verifySignatureFile(root, path string, pub ed25519.PublicKey, typ, digest string) error {
	data, err := os.ReadFile(filepath.Join(root, path)); if err != nil { return fmt.Errorf("%w: missing %s signature", ErrVerification, typ) }
	return VerifyDigest(pub, typ, digest, string(data))
}

func verifyClosedTree(root string, listed map[string]bool) error {
	return filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil { return err }
		if d.IsDir() { return nil }
		rel, err := filepath.Rel(root, path); if err != nil { return err }
		rel = filepath.ToSlash(rel)
		if !listed[rel] { return fmt.Errorf("%w: unlisted file %s", ErrVerification, rel) }
		return nil
	})
}

func safeRelative(p string) error {
	if p == "" || filepath.IsAbs(p) || strings.Contains(filepath.ToSlash(p), "../") || filepath.Clean(p) == "." {
		return fmt.Errorf("%w: unsafe manifest path %q", ErrVerification, p)
	}
	return nil
}

func FileDigest(path string) (string, error) {
	f, err := os.Open(path); if err != nil { return "", fmt.Errorf("%w: open %s: %v", ErrVerification, path, err) }
	defer f.Close()
	h := sha256.New(); if _, err := io.Copy(h, f); err != nil { return "", fmt.Errorf("%w: hash %s: %v", ErrVerification, path, err) }
	return "sha256:" + hex.EncodeToString(h.Sum(nil)), nil
}

func readJSON(path string, out any) error {
	f, err := os.Open(path); if err != nil { return err }
	defer f.Close()
	dec := json.NewDecoder(io.LimitReader(f, 16<<20)); dec.DisallowUnknownFields()
	if err := dec.Decode(out); err != nil { return err }
	var trailing any; if err := dec.Decode(&trailing); err != io.EOF { return errors.New("trailing JSON") }
	return nil
}

func WriteCanonicalJSON(path string, v any) error {
	data, err := json.Marshal(v); if err != nil { return err }
	return os.WriteFile(path, append(data, '\n'), 0o600)
}

func SortedDependencies(values []string) []string {
	set := map[string]bool{}
	for _, v := range values { v = strings.TrimSpace(v); if v != "" { set[v] = true } }
	out := make([]string, 0, len(set)); for v := range set { out = append(out, v) }; sort.Strings(out); return out
}
