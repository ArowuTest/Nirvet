//go:build !hsm

package crypto

import "errors"

var errPKCS11NotCompiled = errors.New("crypto: HSM support not compiled in — build with hsm tag")

func buildPKCS11Wrapper(Config) (keyWrapper, providerTag, error) {
	return nil, 0, errPKCS11NotCompiled
}
