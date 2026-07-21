//go:build !hsm

package crypto

import (
	"errors"
	"testing"
)

func TestPKCS11NotCompiledFailsClearly(t *testing.T) {
	_, _, err := buildPKCS11Wrapper(Config{Provider: "pkcs11"})
	if !errors.Is(err, errPKCS11NotCompiled) {
		t.Fatalf("provider=pkcs11 in a non-hsm build must return the compile-fence error, got %v", err)
	}
}
