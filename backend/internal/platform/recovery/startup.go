package recovery

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
)

const (
	EnvRestoredMode      = "NIRVET_RESTORED_MODE"
	EnvCertificationFile = "NIRVET_RECOVERY_CERTIFICATION_FILE"
)

// RequireServingFromEnv is the production startup boundary for restored
// instances. Restored mode is explicit and fail-closed: the process may serve
// only when a complete certification can be loaded and independently rechecked.
func RequireServingFromEnv() error {
	restored, err := parseRestoredMode(os.Getenv(EnvRestoredMode))
	if err != nil {
		return err
	}
	if !restored {
		return nil
	}

	path := strings.TrimSpace(os.Getenv(EnvCertificationFile))
	if path == "" {
		return fmt.Errorf("%w: %s is required in restored mode", ErrUncertifiedRestore, EnvCertificationFile)
	}
	certification, err := LoadCertification(path)
	if err != nil {
		return err
	}
	return RequireServingCertification(true, &certification)
}

// LoadCertification reads a bounded JSON certification document. It does not
// trust the serialized Certified boolean; RequireServingCertification rechecks
// every required assertion before serving is allowed.
func LoadCertification(path string) (Certification, error) {
	info, err := os.Stat(path)
	if err != nil {
		return Certification{}, fmt.Errorf("%w: certification file: %v", ErrUncertifiedRestore, err)
	}
	if !info.Mode().IsRegular() {
		return Certification{}, fmt.Errorf("%w: certification path is not a regular file", ErrUncertifiedRestore)
	}
	const maxCertificationBytes = 1 << 20
	if info.Size() <= 0 || info.Size() > maxCertificationBytes {
		return Certification{}, fmt.Errorf("%w: certification file size is invalid", ErrUncertifiedRestore)
	}

	data, err := os.ReadFile(path) // #nosec G304 -- explicit operator recovery input; regular-file and 1 MiB checks above.
	if err != nil {
		return Certification{}, fmt.Errorf("%w: read certification: %v", ErrUncertifiedRestore, err)
	}
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
