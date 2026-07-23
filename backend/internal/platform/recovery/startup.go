package recovery

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
)

const (
	EnvRestoredMode              = "NIRVET_RESTORED_MODE"
	EnvCertificationDocumentB64  = "NIRVET_RECOVERY_CERTIFICATION_B64"
	EnvCertificationKeyBase64    = "NIRVET_RECOVERY_CERTIFICATION_KEY_B64"
	maxCertificationBytes        = 1 << 20
)

// RequireServingFromEnv is the production startup boundary for restored
// instances. Restored mode is explicit and fail-closed: the process may serve
// only when a complete, authenticated certification can be loaded and rechecked.
func RequireServingFromEnv() error {
	restored, err := parseRestoredMode(os.Getenv(EnvRestoredMode))
	if err != nil {
		return err
	}
	if !restored {
		return nil
	}

	certification, err := decodeCertificationDocument(os.Getenv(EnvCertificationDocumentB64))
	if err != nil {
		return err
	}
	key, err := decodeCertificationKey(os.Getenv(EnvCertificationKeyBase64))
	if err != nil {
		return err
	}
	if err := VerifyCertificationSignature(certification, key); err != nil {
		return err
	}
	return RequireServingCertification(true, &certification)
}

func decodeCertificationDocument(raw string) (Certification, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return Certification{}, fmt.Errorf("%w: %s is required in restored mode", ErrUncertifiedRestore, EnvCertificationDocumentB64)
	}
	if len(raw) > base64.StdEncoding.EncodedLen(maxCertificationBytes) {
		return Certification{}, fmt.Errorf("%w: certification document is too large", ErrUncertifiedRestore)
	}
	data, err := base64.StdEncoding.DecodeString(raw)
	if err != nil || len(data) == 0 || len(data) > maxCertificationBytes {
		return Certification{}, fmt.Errorf("%w: certification document is invalid", ErrUncertifiedRestore)
	}
	return decodeCertification(data)
}

func decodeCertification(data []byte) (Certification, error) {
	var certification Certification
	decoder := json.NewDecoder(strings.NewReader(string(data)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&certification); err != nil {
		return Certification{}, fmt.Errorf("%w: decode certification: %v", ErrUncertifiedRestore, err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		if err == nil {
			return Certification{}, fmt.Errorf("%w: multiple certification documents", ErrUncertifiedRestore)
		}
		return Certification{}, fmt.Errorf("%w: trailing certification data: %v", ErrUncertifiedRestore, err)
	}
	return certification, nil
}

func decodeCertificationKey(raw string) ([]byte, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, fmt.Errorf("%w: %s is required in restored mode", ErrUncertifiedRestore, EnvCertificationKeyBase64)
	}
	key, err := base64.StdEncoding.DecodeString(raw)
	if err != nil || len(key) < minimumCertificationKeyBytes {
		return nil, fmt.Errorf("%w: %s must contain at least %d base64-encoded bytes", ErrUncertifiedRestore, EnvCertificationKeyBase64, minimumCertificationKeyBytes)
	}
	return key, nil
}

func parseRestoredMode(raw string) (bool, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return false, nil
	}
	value, err := strconv.ParseBool(raw)
	if err != nil {
		return false, fmt.Errorf("recovery: invalid %s value %q", EnvRestoredMode, raw)
	}
	return value, nil
}
