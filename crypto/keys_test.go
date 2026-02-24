package crypto

import "testing"

func TestKeyManager(t *testing.T) {
	km, err := NewKeyManager()
	if err != nil {
		t.Fatalf("NewKeyManager failed: %v", err)
	}

	activeID := km.ActiveKeyID()
	if activeID == "" {
		t.Error("expected non-empty active key ID")
	}

	metas := km.KeyMetas()
	if len(metas) != 1 {
		t.Errorf("expected 1 key, got %d", len(metas))
	}
	if metas[0].Status != KeyActive {
		t.Errorf("expected active status, got %s", metas[0].Status)
	}
	if metas[0].Algorithm != "AES-256-GCM" {
		t.Errorf("expected AES-256-GCM, got %s", metas[0].Algorithm)
	}
}

func TestKeyManagerEncryptDecrypt(t *testing.T) {
	km, _ := NewKeyManager()

	plaintext := []byte("4111111111111111")
	keyID, ciphertext, err := km.Encrypt(plaintext)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	if keyID == "" {
		t.Error("expected non-empty key ID")
	}

	decrypted, err := km.Decrypt(keyID, ciphertext)
	if err != nil {
		t.Fatalf("Decrypt failed: %v", err)
	}

	if string(decrypted) != string(plaintext) {
		t.Errorf("decrypted doesn't match: %s vs %s", decrypted, plaintext)
	}
}

func TestKeyRotation(t *testing.T) {
	km, _ := NewKeyManager()

	firstID := km.ActiveKeyID()

	// Encrypt with first key
	keyID1, ct1, _ := km.Encrypt([]byte("data1"))

	// Rotate
	if err := km.GenerateNewKey(); err != nil {
		t.Fatalf("GenerateNewKey failed: %v", err)
	}

	secondID := km.ActiveKeyID()
	if firstID == secondID {
		t.Error("expected different active key after rotation")
	}

	// New encryption uses new key
	keyID2, _, _ := km.Encrypt([]byte("data2"))
	if keyID2 != secondID {
		t.Error("expected new encryption to use new key")
	}

	// Old data can still be decrypted with old key
	decrypted, err := km.Decrypt(keyID1, ct1)
	if err != nil {
		t.Fatalf("Decrypt with old key failed: %v", err)
	}
	if string(decrypted) != "data1" {
		t.Error("old data decryption mismatch")
	}

	// First key should be retired
	metas := km.KeyMetas()
	for _, m := range metas {
		if m.ID == firstID && m.Status != KeyRetired {
			t.Errorf("expected first key to be retired, got %s", m.Status)
		}
	}
}

func TestKeyDestroy(t *testing.T) {
	km, _ := NewKeyManager()

	firstID := km.ActiveKeyID()
	_, ct, _ := km.Encrypt([]byte("secret"))

	// Can't destroy active key
	if err := km.DestroyKey(firstID); err == nil {
		t.Error("expected error destroying active key")
	}

	// Rotate and destroy old key
	km.GenerateNewKey()
	if err := km.DestroyKey(firstID); err != nil {
		t.Fatalf("DestroyKey failed: %v", err)
	}

	// Can't decrypt with destroyed key
	_, err := km.Decrypt(firstID, ct)
	if err == nil {
		t.Error("expected error decrypting with destroyed key")
	}
}

func TestKeyDestroyNotFound(t *testing.T) {
	km, _ := NewKeyManager()
	if err := km.DestroyKey("nonexistent"); err == nil {
		t.Error("expected error for nonexistent key")
	}
}

func TestDecryptNotFoundKey(t *testing.T) {
	km, _ := NewKeyManager()
	_, err := km.Decrypt("nonexistent", "data")
	if err == nil {
		t.Error("expected error for nonexistent key")
	}
}

func TestGenerateKeyID(t *testing.T) {
	id, err := GenerateKeyID()
	if err != nil {
		t.Fatalf("GenerateKeyID failed: %v", err)
	}
	if len(id) < 5 {
		t.Error("expected key ID with prefix")
	}
}
