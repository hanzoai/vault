package crypto

import (
	"bytes"
	"testing"
)

func TestGenerateKey(t *testing.T) {
	key, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}
	if len(key) != 32 {
		t.Errorf("expected 32-byte key, got %d", len(key))
	}
}

func TestNewEncryptorInvalidKey(t *testing.T) {
	_, err := NewEncryptor([]byte("short"))
	if err != ErrInvalidKey {
		t.Errorf("expected ErrInvalidKey, got %v", err)
	}
}

func TestEncryptDecrypt(t *testing.T) {
	key, _ := GenerateKey()
	enc, err := NewEncryptor(key)
	if err != nil {
		t.Fatalf("NewEncryptor failed: %v", err)
	}

	plaintext := []byte("4111111111111111")
	ciphertext, err := enc.Encrypt(plaintext)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	if ciphertext == "" {
		t.Error("expected non-empty ciphertext")
	}

	decrypted, err := enc.Decrypt(ciphertext)
	if err != nil {
		t.Fatalf("Decrypt failed: %v", err)
	}

	if !bytes.Equal(plaintext, decrypted) {
		t.Errorf("decrypted doesn't match plaintext: %s vs %s", decrypted, plaintext)
	}
}

func TestDecryptInvalidCiphertext(t *testing.T) {
	key, _ := GenerateKey()
	enc, _ := NewEncryptor(key)

	_, err := enc.Decrypt("not-valid-base64!!!")
	if err != ErrInvalidCiphertext {
		t.Errorf("expected ErrInvalidCiphertext, got %v", err)
	}

	// Valid base64 but wrong content
	_, err = enc.Decrypt("dGVzdA==")
	if err == nil {
		t.Error("expected error for invalid ciphertext")
	}
}

func TestDecryptWrongKey(t *testing.T) {
	key1, _ := GenerateKey()
	key2, _ := GenerateKey()
	enc1, _ := NewEncryptor(key1)
	enc2, _ := NewEncryptor(key2)

	ciphertext, _ := enc1.Encrypt([]byte("secret"))
	_, err := enc2.Decrypt(ciphertext)
	if err != ErrDecryptFailed {
		t.Errorf("expected ErrDecryptFailed, got %v", err)
	}
}

func TestEncryptDifferentOutputs(t *testing.T) {
	key, _ := GenerateKey()
	enc, _ := NewEncryptor(key)

	// Two encryptions of same plaintext should produce different ciphertexts (random nonce)
	ct1, _ := enc.Encrypt([]byte("same"))
	ct2, _ := enc.Encrypt([]byte("same"))

	if ct1 == ct2 {
		t.Error("expected different ciphertexts for same plaintext (random nonce)")
	}
}
