package crypto

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"time"
)

// KeyStatus represents the lifecycle state of an encryption key.
type KeyStatus string

const (
	KeyActive    KeyStatus = "active"
	KeyRetired   KeyStatus = "retired"
	KeyDestroyed KeyStatus = "destroyed"
)

// KeyMeta holds metadata about an encryption key.
// The actual key material is never stored in this struct.
type KeyMeta struct {
	ID        string    `json:"id"`
	Version   int       `json:"version"`
	Status    KeyStatus `json:"status"`
	Algorithm string    `json:"algorithm"` // always "AES-256-GCM"
	CreatedAt time.Time `json:"createdAt"`
	RotatedAt time.Time `json:"rotatedAt,omitempty"`
	RetiredAt time.Time `json:"retiredAt,omitempty"`
}

// GenerateKeyID creates a unique key identifier.
func GenerateKeyID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("vault/crypto: key ID generation failed: %w", err)
	}
	return "key_" + hex.EncodeToString(b), nil
}

// KeyManager manages encryption key lifecycle.
// In production this wraps an HSM (AWS CloudHSM / PKCS#11).
// For development it manages keys in memory.
type KeyManager struct {
	// activeKeyID is the current key used for encryption.
	activeKeyID string
	keys        map[string]*managedKey
}

type managedKey struct {
	meta      KeyMeta
	encryptor *Encryptor
}

// NewKeyManager creates a new in-memory key manager.
// For production, use NewHSMKeyManager instead.
func NewKeyManager() (*KeyManager, error) {
	km := &KeyManager{
		keys: make(map[string]*managedKey),
	}

	// Generate initial key
	if err := km.GenerateNewKey(); err != nil {
		return nil, err
	}

	return km, nil
}

// GenerateNewKey creates a new encryption key and makes it active.
// The previous active key is retired.
func (km *KeyManager) GenerateNewKey() error {
	keyBytes, err := GenerateKey()
	if err != nil {
		return err
	}

	id, err := GenerateKeyID()
	if err != nil {
		return err
	}

	encryptor, err := NewEncryptor(keyBytes)
	if err != nil {
		return err
	}

	// Retire current active key
	if km.activeKeyID != "" {
		if mk, ok := km.keys[km.activeKeyID]; ok {
			mk.meta.Status = KeyRetired
			mk.meta.RetiredAt = time.Now()
		}
	}

	version := len(km.keys) + 1
	km.keys[id] = &managedKey{
		meta: KeyMeta{
			ID:        id,
			Version:   version,
			Status:    KeyActive,
			Algorithm: "AES-256-GCM",
			CreatedAt: time.Now(),
		},
		encryptor: encryptor,
	}
	km.activeKeyID = id

	return nil
}

// ActiveKeyID returns the ID of the current active key.
func (km *KeyManager) ActiveKeyID() string {
	return km.activeKeyID
}

// Encrypt encrypts data with the active key.
// Returns the key ID used alongside the ciphertext.
func (km *KeyManager) Encrypt(plaintext []byte) (keyID, ciphertext string, err error) {
	mk, ok := km.keys[km.activeKeyID]
	if !ok {
		return "", "", fmt.Errorf("vault/crypto: no active key")
	}

	ct, err := mk.encryptor.Encrypt(plaintext)
	if err != nil {
		return "", "", err
	}

	return km.activeKeyID, ct, nil
}

// Decrypt decrypts data with the specified key.
func (km *KeyManager) Decrypt(keyID, ciphertext string) ([]byte, error) {
	mk, ok := km.keys[keyID]
	if !ok {
		return nil, fmt.Errorf("vault/crypto: key %s not found", keyID)
	}

	if mk.meta.Status == KeyDestroyed {
		return nil, fmt.Errorf("vault/crypto: key %s has been destroyed", keyID)
	}

	return mk.encryptor.Decrypt(ciphertext)
}

// KeyMetas returns metadata for all keys.
func (km *KeyManager) KeyMetas() []KeyMeta {
	metas := make([]KeyMeta, 0, len(km.keys))
	for _, mk := range km.keys {
		metas = append(metas, mk.meta)
	}
	return metas
}

// DestroyKey permanently marks a key as destroyed.
// Data encrypted with this key can no longer be decrypted.
func (km *KeyManager) DestroyKey(keyID string) error {
	mk, ok := km.keys[keyID]
	if !ok {
		return fmt.Errorf("vault/crypto: key %s not found", keyID)
	}

	if keyID == km.activeKeyID {
		return fmt.Errorf("vault/crypto: cannot destroy active key")
	}

	mk.meta.Status = KeyDestroyed
	mk.encryptor = nil // clear key material
	return nil
}
