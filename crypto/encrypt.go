// Package crypto provides AES-256-GCM encryption for PAN data and
// token generation for the vault service.
package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
)

var (
	ErrInvalidKey        = errors.New("vault/crypto: invalid key size (must be 32 bytes)")
	ErrInvalidCiphertext = errors.New("vault/crypto: invalid ciphertext")
	ErrDecryptFailed     = errors.New("vault/crypto: decryption failed")
)

// Encryptor handles AES-256-GCM encryption/decryption.
type Encryptor struct {
	key []byte
}

// NewEncryptor creates an Encryptor with the given 32-byte key.
func NewEncryptor(key []byte) (*Encryptor, error) {
	if len(key) != 32 {
		return nil, ErrInvalidKey
	}
	return &Encryptor{key: key}, nil
}

// Encrypt encrypts plaintext using AES-256-GCM.
// Returns base64-encoded ciphertext (nonce prepended).
func (e *Encryptor) Encrypt(plaintext []byte) (string, error) {
	block, err := aes.NewCipher(e.key)
	if err != nil {
		return "", fmt.Errorf("vault/crypto: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("vault/crypto: %w", err)
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", fmt.Errorf("vault/crypto: %w", err)
	}

	ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

// Decrypt decrypts base64-encoded AES-256-GCM ciphertext.
func (e *Encryptor) Decrypt(encoded string) ([]byte, error) {
	ciphertext, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, ErrInvalidCiphertext
	}

	block, err := aes.NewCipher(e.key)
	if err != nil {
		return nil, fmt.Errorf("vault/crypto: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("vault/crypto: %w", err)
	}

	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, ErrInvalidCiphertext
	}

	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, ErrDecryptFailed
	}

	return plaintext, nil
}

// GenerateKey generates a random 32-byte AES-256 key.
func GenerateKey() ([]byte, error) {
	key := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return nil, fmt.Errorf("vault/crypto: key generation failed: %w", err)
	}
	return key, nil
}
