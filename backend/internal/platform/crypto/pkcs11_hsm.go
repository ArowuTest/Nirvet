//go:build hsm

package crypto

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"

	"github.com/miekg/pkcs11"
)

const (
	defaultPKCS11PINEnv        = "NIRVET_HSM_PIN"
	defaultPKCS11ModuleEnv     = "NIRVET_HSM_MODULE_PATH"
	defaultPKCS11SlotEnv       = "NIRVET_HSM_SLOT_ID"
	defaultPKCS11TokenLabelEnv = "NIRVET_HSM_TOKEN_LABEL"
	defaultPKCS11ProbeKeyEnv   = "NIRVET_HSM_PROBE_KEY_LABEL"
)

type pkcs11Wrapper struct {
	ctx       *pkcs11.Ctx
	slotID    uint
	pin       string
	mechanism uint
	mu        sync.Mutex
}

func buildPKCS11Wrapper(cfg Config) (keyWrapper, providerTag, error) {
	modulePath := firstNonBlank(cfg.HSMModulePath, os.Getenv(defaultPKCS11ModuleEnv))
	if modulePath == "" {
		return nil, 0, errors.New("crypto: pkcs11 provider requires NIRVET_HSM_MODULE_PATH")
	}
	pin := firstNonBlank(cfg.HSMPIN, os.Getenv(defaultPKCS11PINEnv))
	if pin == "" {
		return nil, 0, errors.New("crypto: pkcs11 provider requires NIRVET_HSM_PIN from a secret source")
	}
	slot := firstNonBlank(cfg.HSMSlotID, os.Getenv(defaultPKCS11SlotEnv))
	tokenLabel := firstNonBlank(cfg.HSMTokenLabel, os.Getenv(defaultPKCS11TokenLabelEnv))

	p := pkcs11.New(modulePath)
	if p == nil {
		return nil, 0, fmt.Errorf("crypto: load PKCS#11 module %q", modulePath)
	}
	if err := p.Initialize(); err != nil && err != pkcs11.Error(pkcs11.CKR_CRYPTOKI_ALREADY_INITIALIZED) {
		p.Destroy()
		return nil, 0, fmt.Errorf("crypto: initialize PKCS#11 module: %w", err)
	}

	slotID, err := resolvePKCS11Slot(p, slot, tokenLabel)
	if err != nil {
		_ = p.Finalize()
		p.Destroy()
		return nil, 0, err
	}

	w := &pkcs11Wrapper{
		ctx:       p,
		slotID:    slotID,
		pin:       pin,
		mechanism: pkcs11.CKM_AES_KEY_WRAP_PAD,
	}
	if err := w.probeSession(); err != nil {
		_ = p.Finalize()
		p.Destroy()
		return nil, 0, err
	}
	return w, tagPKCS11, nil
}

func firstNonBlank(values ...string) string {
	for _, value := range values {
		if trimmed := strings.TrimSpace(value); trimmed != "" {
			return trimmed
		}
	}
	return ""
}

func resolvePKCS11Slot(p *pkcs11.Ctx, configured string, tokenLabel string) (uint, error) {
	slots, err := p.GetSlotList(true)
	if err != nil {
		return 0, fmt.Errorf("crypto: list PKCS#11 token slots: %w", err)
	}
	if len(slots) == 0 {
		return 0, errors.New("crypto: no PKCS#11 token slots available")
	}
	if configured != "" {
		v, err := strconv.ParseUint(configured, 10, 64)
		if err != nil {
			return 0, fmt.Errorf("crypto: invalid NIRVET_HSM_SLOT_ID %q: %w", configured, err)
		}
		for _, slot := range slots {
			if uint64(slot) == v {
				return slot, nil
			}
		}
		return 0, fmt.Errorf("crypto: configured PKCS#11 slot %d is not present", v)
	}
	if tokenLabel != "" {
		for _, slot := range slots {
			info, err := p.GetTokenInfo(slot)
			if err != nil {
				continue
			}
			if strings.TrimSpace(info.Label) == strings.TrimSpace(tokenLabel) {
				return slot, nil
			}
		}
		return 0, fmt.Errorf("crypto: PKCS#11 token label %q not found", tokenLabel)
	}
	if len(slots) != 1 {
		return 0, errors.New("crypto: multiple PKCS#11 token slots found; set NIRVET_HSM_SLOT_ID or NIRVET_HSM_TOKEN_LABEL")
	}
	return slots[0], nil
}

func (w *pkcs11Wrapper) probeSession() error {
	return w.withSession(func(pkcs11.SessionHandle) error { return nil })
}

func (w *pkcs11Wrapper) Wrap(ctx context.Context, keyName string, plaintext, _ []byte) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	var out []byte
	err := w.withSession(func(session pkcs11.SessionHandle) error {
		key, err := w.findKEK(session, keyName)
		if err != nil {
			return err
		}
		if err := w.ctx.EncryptInit(session, []*pkcs11.Mechanism{pkcs11.NewMechanism(w.mechanism, nil)}, key); err != nil {
			return fmt.Errorf("crypto: PKCS#11 wrap init: %w", err)
		}
		out, err = w.ctx.Encrypt(session, plaintext)
		if err != nil {
			return fmt.Errorf("crypto: PKCS#11 wrap: %w", err)
		}
		return nil
	})
	return out, err
}

func (w *pkcs11Wrapper) Unwrap(ctx context.Context, keyName string, ciphertext, _ []byte) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	var out []byte
	err := w.withSession(func(session pkcs11.SessionHandle) error {
		key, err := w.findKEK(session, keyName)
		if err != nil {
			return err
		}
		if err := w.ctx.DecryptInit(session, []*pkcs11.Mechanism{pkcs11.NewMechanism(w.mechanism, nil)}, key); err != nil {
			return fmt.Errorf("crypto: PKCS#11 unwrap init: %w", err)
		}
		out, err = w.ctx.Decrypt(session, ciphertext)
		if err != nil {
			return fmt.Errorf("crypto: PKCS#11 unwrap: %w", err)
		}
		return nil
	})
	return out, err
}

func (w *pkcs11Wrapper) withSession(fn func(pkcs11.SessionHandle) error) error {
	w.mu.Lock()
	defer w.mu.Unlock()

	session, err := w.ctx.OpenSession(w.slotID, pkcs11.CKF_SERIAL_SESSION|pkcs11.CKF_RW_SESSION)
	if err != nil {
		return fmt.Errorf("crypto: open PKCS#11 session: %w", err)
	}
	defer func() { _ = w.ctx.CloseSession(session) }()

	if err := w.ctx.Login(session, pkcs11.CKU_USER, w.pin); err != nil && err != pkcs11.Error(pkcs11.CKR_USER_ALREADY_LOGGED_IN) {
		return fmt.Errorf("crypto: PKCS#11 login failed: %w", err)
	}
	defer func() { _ = w.ctx.Logout(session) }()

	return fn(session)
}

func (w *pkcs11Wrapper) findKEK(session pkcs11.SessionHandle, keyName string) (pkcs11.ObjectHandle, error) {
	id := sha256.Sum256([]byte(keyName))
	template := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_SECRET_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_AES),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, keyName),
		pkcs11.NewAttribute(pkcs11.CKA_ID, id[:16]),
	}
	if err := w.ctx.FindObjectsInit(session, template); err != nil {
		return 0, fmt.Errorf("crypto: PKCS#11 key search init: %w", err)
	}
	objects, more, err := w.ctx.FindObjects(session, 2)
	finalErr := w.ctx.FindObjectsFinal(session)
	if err != nil {
		return 0, fmt.Errorf("crypto: PKCS#11 key search: %w", err)
	}
	if finalErr != nil {
		return 0, fmt.Errorf("crypto: PKCS#11 key search final: %w", finalErr)
	}
	if len(objects) == 0 {
		return 0, fmt.Errorf("crypto: PKCS#11 KEK %q not found", keyName)
	}
	if len(objects) != 1 || more {
		return 0, fmt.Errorf("crypto: PKCS#11 KEK %q is ambiguous", keyName)
	}
	if err := w.validateKEK(session, objects[0], keyName); err != nil {
		return 0, err
	}
	return objects[0], nil
}

func (w *pkcs11Wrapper) validateKEK(session pkcs11.SessionHandle, key pkcs11.ObjectHandle, keyName string) error {
	attrs, err := w.ctx.GetAttributeValue(session, key, []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_SENSITIVE, nil),
		pkcs11.NewAttribute(pkcs11.CKA_EXTRACTABLE, nil),
		pkcs11.NewAttribute(pkcs11.CKA_ENCRYPT, nil),
		pkcs11.NewAttribute(pkcs11.CKA_DECRYPT, nil),
	})
	if err != nil {
		return fmt.Errorf("crypto: read PKCS#11 KEK security attributes for %q: %w", keyName, err)
	}
	if len(attrs) != 4 || len(attrs[0].Value) == 0 || attrs[0].Value[0] == 0 {
		return fmt.Errorf("crypto: PKCS#11 KEK %q must have CKA_SENSITIVE=true", keyName)
	}
	if len(attrs[1].Value) == 0 || attrs[1].Value[0] != 0 {
		return fmt.Errorf("crypto: PKCS#11 KEK %q must have CKA_EXTRACTABLE=false", keyName)
	}
	if len(attrs[2].Value) == 0 || attrs[2].Value[0] == 0 || len(attrs[3].Value) == 0 || attrs[3].Value[0] == 0 {
		return fmt.Errorf("crypto: PKCS#11 KEK %q must permit token-side wrap and unwrap operations", keyName)
	}
	return nil
}
