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
	payload := []byte("nirvet-artifact-v1\n" + objectType + "\n" + digest + "\n")
	if err != nil || !ed25519.Verify(publicKey, payload, sig) {
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
	if now.IsZero() {
		now = time.Now().UTC()
	}
	if now.Before(anchor.NotBefore) || !now.Before(anchor.NotAfter) {
		return fmt.Errorf("%w: trust anchor outside validity period", ErrVerification)
	}
	publicBytes, err := base64.StdEncoding.DecodeString(anchor.PublicKeyB64)
	if err != nil || len(publicBytes) != ed25519.PublicKeySize {
		return fmt.Errorf("%w: malformed trust anchor", ErrVerification)
	}
	if manifest.ReleaseSequence < opts.MinimumSequence || manifest.ReleaseSequence < opts.InstalledSequence {
		return fmt.Errorf("%w: downgrade release sequence %d", ErrVerification, manifest.ReleaseSequence)
	}
	if opts.ExpectedSourceRepo != "" && manifest.SourceRepo != opts.ExpectedSourceRepo {
		return fmt.Errorf("%w: source repository mismatch", ErrVerification)
	}
	if opts.ExpectedSourceCommit != "" && manifest.SourceCommit != opts.ExpectedSourceCommit {
		return fmt.Errorf("%w: source commit mismatch", ErrVerification)
	}
	if err := verifyKinds(manifest.Artifacts); err != nil {
		return err
	}

	listed := map[string]bool{
		"release.manifest.json": true,
		"release.manifest.sig":  true,
		"trust-anchor.json":     true,
	}
	publicKey := ed25519.PublicKey(publicBytes)
	for _, artifact := range manifest.Artifacts {
		paths := []string{
			artifact.Path,
			artifact.SignaturePath,
			artifact.SBOMPath,
			artifact.SBOMSignaturePath,
			artifact.ProvenancePath,
			artifact.ProvenanceSigPath,
			artifact.DependencyListPath,
		}
		for _, path := range paths {
			if err := safeRelative(path); err != nil {
				return err
			}
			if listed[path] {
				return fmt.Errorf("%w: duplicate manifest path %q", ErrVerification, path)
			}
			listed[path] = true
		}
		if err := verifyOne(root, artifact, manifest, publicKey); err != nil {
			return err
		}
	}
	for path := range opts.AllowExtra {
		listed[path] = true
	}
	return verifyClosedTree(root, listed)
}

func verifyOne(root string, artifact Artifact, manifest Manifest, publicKey ed25519.PublicKey) error {
	artifactDigest, err := FileDigest(filepath.Join(root, artifact.Path))
	if err != nil {
		return err
	}
	if artifactDigest != artifact.Digest {
		return fmt.Errorf("%w: artifact digest mismatch for %s", ErrVerification, artifact.Path)
	}
	if err := verifySignatureFile(root, artifact.SignaturePath, publicKey, "artifact", artifact.Digest); err != nil {
		return err
	}

	sbomDigest, err := FileDigest(filepath.Join(root, artifact.SBOMPath))
	if err != nil {
		return err
	}
	if sbomDigest != artifact.SBOMDigest {
		return fmt.Errorf("%w: SBOM digest mismatch for %s", ErrVerification, artifact.Path)
	}
	if err := verifySignatureFile(root, artifact.SBOMSignaturePath, publicKey, "sbom", artifact.SBOMDigest); err != nil {
		return err
	}
	var sbom SBOM
	if err := readJSON(filepath.Join(root, artifact.SBOMPath), &sbom); err != nil {
		return fmt.Errorf("%w: invalid SBOM: %v", ErrVerification, err)
	}
	if sbom.BOMFormat != "CycloneDX" || sbom.Metadata.Component.Name == "" || sbom.Metadata.Component.Version != artifact.Digest {
		return fmt.Errorf("%w: SBOM not bound to artifact digest", ErrVerification)
	}
	if err := verifyDependencyCompleteness(filepath.Join(root, artifact.DependencyListPath), artifact.DependencyListHash, sbom); err != nil {
		return err
	}

	provenanceDigest, err := FileDigest(filepath.Join(root, artifact.ProvenancePath))
	if err != nil {
		return err
	}
	if provenanceDigest != artifact.ProvenanceDigest {
		return fmt.Errorf("%w: provenance digest mismatch for %s", ErrVerification, artifact.Path)
	}
	if err := verifySignatureFile(root, artifact.ProvenanceSigPath, publicKey, "provenance", artifact.ProvenanceDigest); err != nil {
		return err
	}
	var provenance Provenance
	if err := readJSON(filepath.Join(root, artifact.ProvenancePath), &provenance); err != nil {
		return fmt.Errorf("%w: invalid provenance: %v", ErrVerification, err)
	}
	if provenance.Version != 1 ||
		provenance.SubjectDigest != artifact.Digest ||
		provenance.ArtifactKind != artifact.Kind ||
		provenance.SourceRepo != manifest.SourceRepo ||
		provenance.SourceCommit != manifest.SourceCommit ||
		provenance.ReleaseSequence != manifest.ReleaseSequence ||
		provenance.BuilderIdentity == "" ||
		provenance.BuildRecipe == "" {
		return fmt.Errorf("%w: forged or mismatched provenance for %s", ErrVerification, artifact.Path)
	}
	return nil
}

func verifyKinds(artifacts []Artifact) error {
	seen := map[string]int{}
	for _, artifact := range artifacts {
		seen[artifact.Kind]++
	}
	for _, kind := range RequiredArtifactKinds {
		if seen[kind] != 1 {
			return fmt.Errorf("%w: artifact kind %s count=%d want 1", ErrVerification, kind, seen[kind])
		}
	}
	if len(artifacts) != len(RequiredArtifactKinds) {
		return fmt.Errorf("%w: unexpected artifact kind", ErrVerification)
	}
	return nil
}

func verifyDependencyCompleteness(path, expectedHash string, sbom SBOM) error {
	digest, err := FileDigest(path)
	if err != nil {
		return err
	}
	if digest != expectedHash {
		return fmt.Errorf("%w: dependency inventory digest mismatch", ErrVerification)
	}
	// #nosec G304,G703 -- path is a manifest-relative path already validated by safeRelative.
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("%w: dependency inventory: %v", ErrVerification, err)
	}
	components := map[string]bool{}
	for _, component := range sbom.Components {
		components[component.Name+"@"+component.Version] = true
	}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if !components[line] {
			return fmt.Errorf("%w: SBOM missing real dependency %s", ErrVerification, line)
		}
	}
	return nil
}

func verifySignatureFile(root, path string, publicKey ed25519.PublicKey, objectType, digest string) error {
	fullPath := filepath.Join(root, path)
	// #nosec G304,G703 -- path is a manifest-relative path already validated by safeRelative.
	data, err := os.ReadFile(fullPath)
	if err != nil {
		return fmt.Errorf("%w: missing %s signature", ErrVerification, objectType)
	}
	return VerifyDigest(publicKey, objectType, digest, string(data))
}

func verifyClosedTree(root string, listed map[string]bool) error {
	return filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			return nil
		}
		relative, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		relative = filepath.ToSlash(relative)
		if !listed[relative] {
			return fmt.Errorf("%w: unlisted file %s", ErrVerification, relative)
		}
		return nil
	})
}

func safeRelative(path string) error {
	clean := filepath.Clean(path)
	if path == "" || filepath.IsAbs(path) || clean == "." || strings.HasPrefix(filepath.ToSlash(clean), "../") {
		return fmt.Errorf("%w: unsafe manifest path %q", ErrVerification, path)
	}
	return nil
}

func FileDigest(path string) (string, error) {
	// #nosec G304,G703 -- callers supply either operator-selected release roots or safe manifest-relative paths.
	file, err := os.Open(path)
	if err != nil {
		return "", fmt.Errorf("%w: open %s: %v", ErrVerification, path, err)
	}
	defer file.Close()
	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return "", fmt.Errorf("%w: hash %s: %v", ErrVerification, path, err)
	}
	return "sha256:" + hex.EncodeToString(hash.Sum(nil)), nil
}

func readJSON(path string, out any) error {
	// #nosec G304,G703 -- callers pass operator-selected or safe manifest-relative paths.
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()
	decoder := json.NewDecoder(io.LimitReader(file, 16<<20))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(out); err != nil {
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return errors.New("trailing JSON")
	}
	return nil
}

func WriteCanonicalJSON(path string, value any) error {
	data, err := json.Marshal(value)
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(data, '\n'), 0o600)
}

func SortedDependencies(values []string) []string {
	set := map[string]bool{}
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value != "" {
			set[value] = true
		}
	}
	out := make([]string, 0, len(set))
	for value := range set {
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}
