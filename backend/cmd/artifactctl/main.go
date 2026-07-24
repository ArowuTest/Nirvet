package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/ArowuTest/nirvet/internal/platform/supplychain"
)

func main() {
	if len(os.Args) < 2 {
		fatalf("usage: artifactctl <verify|sign>")
	}
	var err error
	switch os.Args[1] {
	case "verify":
		err = verify(os.Args[2:])
	case "sign":
		err = sign(os.Args[2:])
	default:
		err = fmt.Errorf("unknown command %q", os.Args[1])
	}
	if err != nil {
		fatalf("%v", err)
	}
}

func verify(args []string) error {
	fs := flag.NewFlagSet("verify", flag.ContinueOnError)
	root := fs.String("root", "", "release directory")
	manifestPath := fs.String("manifest", "release.manifest.json", "manifest path relative to root")
	manifestSigPath := fs.String("manifest-signature", "release.manifest.sig", "manifest signature path relative to root")
	anchorPath := fs.String("trust-anchor", "trust-anchor.json", "trust anchor path relative to root")
	expectedRepo := fs.String("source-repo", "", "required source repository")
	expectedCommit := fs.String("source-commit", "", "required reviewed commit")
	minimumSequence := fs.Uint64("minimum-sequence", 0, "minimum approved release sequence")
	installedSequence := fs.Uint64("installed-sequence", 0, "locally installed release sequence")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if strings.TrimSpace(*root) == "" {
		return errors.New("--root is required")
	}
	var manifest supplychain.Manifest
	if err := readJSON(filepath.Join(*root, *manifestPath), &manifest); err != nil {
		return fmt.Errorf("read manifest: %w", err)
	}
	var anchor supplychain.TrustAnchor
	if err := readJSON(filepath.Join(*root, *anchorPath), &anchor); err != nil {
		return fmt.Errorf("read trust anchor: %w", err)
	}
	manifestDigest, err := supplychain.FileDigest(filepath.Join(*root, *manifestPath))
	if err != nil {
		return err
	}
	signature, err := os.ReadFile(filepath.Join(*root, *manifestSigPath))
	if err != nil {
		return fmt.Errorf("manifest signature: %w", err)
	}
	publicBytes, err := base64.StdEncoding.DecodeString(anchor.PublicKeyB64)
	if err != nil || len(publicBytes) != ed25519.PublicKeySize {
		return errors.New("malformed trust anchor public key")
	}
	if err := supplychain.VerifyDigest(ed25519.PublicKey(publicBytes), "manifest", manifestDigest, string(signature)); err != nil {
		return err
	}
	return supplychain.VerifyRelease(*root, manifest, anchor, supplychain.VerifyOptions{
		ExpectedSourceRepo:   *expectedRepo,
		ExpectedSourceCommit: *expectedCommit,
		MinimumSequence:      *minimumSequence,
		InstalledSequence:    *installedSequence,
		Now:                  time.Now().UTC(),
	})
}

func sign(args []string) error {
	fs := flag.NewFlagSet("sign", flag.ContinueOnError)
	objectType := fs.String("type", "", "artifact, sbom, provenance, or manifest")
	filePath := fs.String("file", "", "file to sign")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *objectType == "" || *filePath == "" {
		return errors.New("--type and --file are required")
	}
	keyRaw := strings.TrimSpace(os.Getenv("NIRVET_ARTIFACT_SIGNING_KEY_B64"))
	if keyRaw == "" {
		return errors.New("NIRVET_ARTIFACT_SIGNING_KEY_B64 is required")
	}
	privateBytes, err := base64.StdEncoding.DecodeString(keyRaw)
	if err != nil || len(privateBytes) != ed25519.PrivateKeySize {
		return errors.New("artifact signing key must be a base64 Ed25519 private key")
	}
	digest, err := supplychain.FileDigest(*filePath)
	if err != nil {
		return err
	}
	signature := supplychain.SignDigest(ed25519.PrivateKey(privateBytes), *objectType, digest)
	_, err = fmt.Fprintln(os.Stdout, signature)
	return err
}

func readJSON(path string, out any) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	decoder := json.NewDecoder(strings.NewReader(string(data)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(out); err != nil {
		return err
	}
	return nil
}

func fatalf(format string, args ...any) {
	_, _ = fmt.Fprintf(os.Stderr, "artifactctl: "+format+"\n", args...)
	os.Exit(1)
}
