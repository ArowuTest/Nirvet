package contentlifecycle

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

var (
	ErrMalformedEnvelope   = errors.New("content: malformed envelope")
	ErrUnknownPublisher    = errors.New("content: untrusted publisher")
	ErrInvalidSignature    = errors.New("content: invalid signature")
	ErrMalformedManifest   = errors.New("content: malformed manifest")
	ErrPublisherMismatch   = errors.New("content: publisher mismatch")
	ErrHashMismatch        = errors.New("content: content hash mismatch")
	ErrExpired             = errors.New("content: package expired")
	ErrInvalidVersion      = errors.New("content: invalid version")
	ErrMalformedContent    = errors.New("content: malformed content")
	ErrUnsupportedType     = errors.New("content: unsupported content type")
	ErrSemanticValidation  = errors.New("content: semantic validation failed")
)

// Envelope contains only routing metadata and opaque signed bytes. The manifest
// and content are not parsed until the detached Ed25519 signature verifies.
type Envelope struct {
	PublisherID string `json:"publisher_id"`
	ManifestB64 string `json:"manifest_b64"`
	ContentB64  string `json:"content_b64"`
	SignatureB64 string `json:"signature_b64"`
}

type Manifest struct {
	PublisherID string    `json:"publisher_id"`
	ContentType string    `json:"content_type"`
	Version     int64     `json:"version"`
	IssuedAt    time.Time `json:"issued_at"`
	ExpiresAt   time.Time `json:"expires_at"`
	ContentSHA256 string  `json:"content_sha256"`
	Scope       string    `json:"scope"`
	TenantID    string    `json:"tenant_id,omitempty"`
}

type Artifact struct {
	ID   string          `json:"id"`
	Kind string          `json:"kind"`
	Data json.RawMessage `json:"data"`
}

type Content struct {
	Artifacts []Artifact `json:"artifacts"`
}

type VerifiedPack struct {
	Manifest      Manifest
	Artifacts     []Artifact
	ManifestBytes []byte
	ContentBytes  []byte
	Signature     []byte
}

type ArtifactValidator interface {
	ValidateArtifact(manifest Manifest, artifact Artifact) error
}

type ArtifactValidatorFunc func(manifest Manifest, artifact Artifact) error

func (f ArtifactValidatorFunc) ValidateArtifact(manifest Manifest, artifact Artifact) error {
	return f(manifest, artifact)
}

type Verifier struct {
	Publishers map[string]ed25519.PublicKey
	Validators map[string]ArtifactValidator
}

func signatureInput(publisherID string, manifestBytes, contentBytes []byte) []byte {
	out := make([]byte, 0, len(publisherID)+len(manifestBytes)+len(contentBytes)+2)
	out = append(out, publisherID...)
	out = append(out, 0)
	out = append(out, manifestBytes...)
	out = append(out, 0)
	out = append(out, contentBytes...)
	return out
}

// VerifyAndParse is deliberately ordered: decode envelope -> verify signature ->
// parse manifest -> verify hash/expiry -> parse content -> validate every artifact.
// One invalid artifact rejects the whole pack; no partial result is returned.
func (v Verifier) VerifyAndParse(raw []byte, now time.Time) (*VerifiedPack, error) {
	var env Envelope
	if err := json.Unmarshal(raw, &env); err != nil || env.PublisherID == "" || env.ManifestB64 == "" || env.ContentB64 == "" || env.SignatureB64 == "" {
		return nil, ErrMalformedEnvelope
	}
	pub, ok := v.Publishers[env.PublisherID]
	if !ok || len(pub) != ed25519.PublicKeySize {
		return nil, ErrUnknownPublisher
	}
	manifestBytes, err := base64.StdEncoding.DecodeString(env.ManifestB64)
	if err != nil {
		return nil, ErrMalformedEnvelope
	}
	contentBytes, err := base64.StdEncoding.DecodeString(env.ContentB64)
	if err != nil {
		return nil, ErrMalformedEnvelope
	}
	sig, err := base64.StdEncoding.DecodeString(env.SignatureB64)
	if err != nil || len(sig) != ed25519.SignatureSize {
		return nil, ErrInvalidSignature
	}
	if !ed25519.Verify(pub, signatureInput(env.PublisherID, manifestBytes, contentBytes), sig) {
		return nil, ErrInvalidSignature
	}

	var manifest Manifest
	if err := json.Unmarshal(manifestBytes, &manifest); err != nil {
		return nil, ErrMalformedManifest
	}
	if manifest.PublisherID != env.PublisherID {
		return nil, ErrPublisherMismatch
	}
	if manifest.Version <= 0 {
		return nil, ErrInvalidVersion
	}
	if !manifest.ExpiresAt.After(now) {
		return nil, ErrExpired
	}
	digest := sha256.Sum256(contentBytes)
	if manifest.ContentSHA256 != hex.EncodeToString(digest[:]) {
		return nil, ErrHashMismatch
	}
	validator, ok := v.Validators[manifest.ContentType]
	if !ok || validator == nil {
		return nil, fmt.Errorf("%w: %s", ErrUnsupportedType, manifest.ContentType)
	}

	var content Content
	if err := json.Unmarshal(contentBytes, &content); err != nil || len(content.Artifacts) == 0 {
		return nil, ErrMalformedContent
	}
	for _, artifact := range content.Artifacts {
		if artifact.ID == "" || artifact.Kind == "" || len(artifact.Data) == 0 {
			return nil, ErrMalformedContent
		}
		if err := validator.ValidateArtifact(manifest, artifact); err != nil {
			return nil, fmt.Errorf("%w: artifact %s: %v", ErrSemanticValidation, artifact.ID, err)
		}
	}

	return &VerifiedPack{
		Manifest: manifest,
		Artifacts: append([]Artifact(nil), content.Artifacts...),
		ManifestBytes: append([]byte(nil), manifestBytes...),
		ContentBytes: append([]byte(nil), contentBytes...),
		Signature: append([]byte(nil), sig...),
	}, nil
}
