package recovery

import (
	"bytes"
	"fmt"
	"sort"
	"strings"

	platformcrypto "github.com/ArowuTest/nirvet/internal/platform/crypto"
	"github.com/google/uuid"
)

// CryptoProbe is one encrypted-domain sample restored from backup. Recovery is
// uncertifiable unless every required domain is represented and decrypts exactly.
type CryptoProbe struct {
	Domain     string
	TenantID   uuid.UUID
	Ciphertext []byte
	Expected   []byte
}

// ValidateCryptoContinuity proves that restored ciphertext remains decryptable
// under the restored/re-provisioned KEK and that tenant AAD binding is intact.
// It never treats an empty domain set as success.
func ValidateCryptoContinuity(cipher platformcrypto.SecretCipher, requiredDomains []string, probes []CryptoProbe) (string, error) {
	if cipher == nil {
		return "", fmt.Errorf("recovery: crypto provider is required")
	}
	if len(requiredDomains) == 0 {
		return "", fmt.Errorf("recovery: encrypted-domain inventory is empty")
	}

	required := make(map[string]struct{}, len(requiredDomains))
	for _, domain := range requiredDomains {
		domain = strings.TrimSpace(domain)
		if domain == "" {
			return "", fmt.Errorf("recovery: encrypted-domain inventory contains an empty name")
		}
		if _, duplicate := required[domain]; duplicate {
			return "", fmt.Errorf("recovery: duplicate encrypted domain %q", domain)
		}
		required[domain] = struct{}{}
	}

	seen := make(map[string]struct{}, len(probes))
	for _, probe := range probes {
		domain := strings.TrimSpace(probe.Domain)
		if _, ok := required[domain]; !ok {
			return "", fmt.Errorf("recovery: unexpected crypto probe domain %q", domain)
		}
		if _, duplicate := seen[domain]; duplicate {
			return "", fmt.Errorf("recovery: duplicate crypto probe for domain %q", domain)
		}
		seen[domain] = struct{}{}
		if probe.TenantID == uuid.Nil || len(probe.Ciphertext) == 0 || len(probe.Expected) == 0 {
			return "", fmt.Errorf("recovery: incomplete crypto probe for domain %q", domain)
		}
		plaintext, err := cipher.Decrypt(probe.TenantID, probe.Ciphertext)
		if err != nil {
			return "", fmt.Errorf("recovery: decrypt domain %q failed closed: %w", domain, err)
		}
		if !bytes.Equal(plaintext, probe.Expected) {
			return "", fmt.Errorf("recovery: decrypt domain %q returned mismatched plaintext", domain)
		}
	}

	var missing []string
	for domain := range required {
		if _, ok := seen[domain]; !ok {
			missing = append(missing, domain)
		}
	}
	if len(missing) > 0 {
		sort.Strings(missing)
		return "", fmt.Errorf("recovery: missing crypto probes: %s", strings.Join(missing, ", "))
	}
	return fmt.Sprintf("%d encrypted domains decrypted exactly with tenant-bound AAD", len(required)), nil
}
