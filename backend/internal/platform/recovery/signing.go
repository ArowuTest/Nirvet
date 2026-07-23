package recovery

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
)

const minimumCertificationKeyBytes = 32

// SignCertification authenticates the complete certification document with an
// operator-held recovery key that is stored outside the restored application
// data. The signature prevents a writable JSON file from becoming a bypass.
func SignCertification(certification Certification, key []byte) (Certification, error) {
	if len(key) < minimumCertificationKeyBytes {
		return Certification{}, fmt.Errorf("%w: recovery certification key must be at least %d bytes", ErrUncertifiedRestore, minimumCertificationKeyBytes)
	}
	if err := RequireServingCertification(true, &certification); err != nil {
		return Certification{}, err
	}
	payload, err := certificationSigningPayload(certification)
	if err != nil {
		return Certification{}, err
	}
	mac := hmac.New(sha256.New, key)
	if _, err := mac.Write(payload); err != nil {
		return Certification{}, fmt.Errorf("%w: sign certification: %v", ErrUncertifiedRestore, err)
	}
	certification.Signature = base64.RawStdEncoding.EncodeToString(mac.Sum(nil))
	return certification, nil
}

// VerifyCertificationSignature authenticates the loaded document before the
// restored-serving gate trusts any assertion in it.
func VerifyCertificationSignature(certification Certification, key []byte) error {
	if len(key) < minimumCertificationKeyBytes {
		return fmt.Errorf("%w: recovery certification key must be at least %d bytes", ErrUncertifiedRestore, minimumCertificationKeyBytes)
	}
	provided, err := base64.RawStdEncoding.DecodeString(certification.Signature)
	if err != nil || len(provided) != sha256.Size {
		return fmt.Errorf("%w: recovery certification signature is invalid", ErrUncertifiedRestore)
	}
	payload, err := certificationSigningPayload(certification)
	if err != nil {
		return err
	}
	mac := hmac.New(sha256.New, key)
	if _, err := mac.Write(payload); err != nil {
		return fmt.Errorf("%w: verify certification: %v", ErrUncertifiedRestore, err)
	}
	if !hmac.Equal(provided, mac.Sum(nil)) {
		return fmt.Errorf("%w: recovery certification signature mismatch", ErrUncertifiedRestore)
	}
	return nil
}

func certificationSigningPayload(certification Certification) ([]byte, error) {
	certification.Signature = ""
	payload, err := json.Marshal(certification)
	if err != nil {
		return nil, fmt.Errorf("%w: encode certification signing payload: %v", ErrUncertifiedRestore, err)
	}
	return payload, nil
}
