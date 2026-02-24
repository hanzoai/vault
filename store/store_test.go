package store

import (
	"testing"

	"github.com/hanzoai/vault/crypto"
)

func setupVault(t *testing.T) *Vault {
	t.Helper()
	km, err := crypto.NewKeyManager()
	if err != nil {
		t.Fatalf("NewKeyManager failed: %v", err)
	}
	return NewVault(NewMemoryStore(), km)
}

func TestTokenize(t *testing.T) {
	v := setupVault(t)

	resp, err := v.Tokenize(&TokenizeRequest{
		PAN:        "4111111111111111",
		ExpMonth:   12,
		ExpYear:    2030,
		CustomerId: "cust_1",
		TenantId:   "tenant_1",
	})
	if err != nil {
		t.Fatalf("Tokenize failed: %v", err)
	}

	if !crypto.ValidateToken(resp.Token) {
		t.Errorf("invalid token: %s", resp.Token)
	}
	if resp.Brand != "visa" {
		t.Errorf("expected visa, got %s", resp.Brand)
	}
	if resp.Last4 != "1111" {
		t.Errorf("expected last4 '1111', got %s", resp.Last4)
	}
	if resp.Fingerprint == "" {
		t.Error("expected non-empty fingerprint")
	}
}

func TestTokenizeDedup(t *testing.T) {
	v := setupVault(t)

	req := &TokenizeRequest{
		PAN:        "4111111111111111",
		ExpMonth:   12,
		ExpYear:    2030,
		CustomerId: "cust_1",
		TenantId:   "tenant_1",
	}

	resp1, _ := v.Tokenize(req)
	resp2, _ := v.Tokenize(req)

	if resp1.Token != resp2.Token {
		t.Error("expected same token for duplicate PAN")
	}
}

func TestTokenizeValidation(t *testing.T) {
	v := setupVault(t)

	tests := []struct {
		name string
		req  TokenizeRequest
	}{
		{"empty PAN", TokenizeRequest{PAN: "", ExpMonth: 12, ExpYear: 2030}},
		{"invalid month", TokenizeRequest{PAN: "4111111111111111", ExpMonth: 13, ExpYear: 2030}},
		{"expired", TokenizeRequest{PAN: "4111111111111111", ExpMonth: 12, ExpYear: 2020}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := v.Tokenize(&tt.req)
			if err == nil {
				t.Error("expected validation error")
			}
		})
	}
}

func TestDetokenize(t *testing.T) {
	v := setupVault(t)

	resp, _ := v.Tokenize(&TokenizeRequest{
		PAN:        "4242424242424242",
		ExpMonth:   6,
		ExpYear:    2028,
		CustomerId: "cust_2",
		TenantId:   "tenant_1",
	})

	pan, err := v.Detokenize(resp.Token)
	if err != nil {
		t.Fatalf("Detokenize failed: %v", err)
	}

	if pan != "4242424242424242" {
		t.Errorf("expected PAN 4242424242424242, got %s", pan)
	}
}

func TestDetokenizeNotFound(t *testing.T) {
	v := setupVault(t)

	_, err := v.Detokenize("tok_nonexistent")
	if err == nil {
		t.Error("expected error for nonexistent token")
	}
}

func TestGetMetadata(t *testing.T) {
	v := setupVault(t)

	resp, _ := v.Tokenize(&TokenizeRequest{
		PAN:        "5111111111111118",
		ExpMonth:   3,
		ExpYear:    2029,
		CustomerId: "cust_3",
		TenantId:   "tenant_1",
	})

	meta, err := v.GetMetadata(resp.Token)
	if err != nil {
		t.Fatalf("GetMetadata failed: %v", err)
	}

	if meta.Brand != "mastercard" {
		t.Errorf("expected mastercard, got %s", meta.Brand)
	}
	if meta.Last4 != "1118" {
		t.Errorf("expected last4 '1118', got %s", meta.Last4)
	}
	if meta.CustomerId != "cust_3" {
		t.Errorf("expected customerId 'cust_3', got %s", meta.CustomerId)
	}
}

func TestGetMetadataNotFound(t *testing.T) {
	v := setupVault(t)

	_, err := v.GetMetadata("tok_nonexistent")
	if err == nil {
		t.Error("expected error for nonexistent token")
	}
}

func TestDeleteCard(t *testing.T) {
	v := setupVault(t)

	resp, _ := v.Tokenize(&TokenizeRequest{
		PAN:        "4111111111111111",
		ExpMonth:   12,
		ExpYear:    2030,
		CustomerId: "cust_1",
		TenantId:   "tenant_1",
	})

	if err := v.DeleteCard(resp.Token); err != nil {
		t.Fatalf("DeleteCard failed: %v", err)
	}

	_, err := v.GetMetadata(resp.Token)
	if err == nil {
		t.Error("expected error after deletion")
	}
}

func TestRotateToken(t *testing.T) {
	v := setupVault(t)

	resp, _ := v.Tokenize(&TokenizeRequest{
		PAN:        "4111111111111111",
		ExpMonth:   12,
		ExpYear:    2030,
		CustomerId: "cust_1",
		TenantId:   "tenant_1",
	})

	oldToken := resp.Token

	newToken, err := v.RotateToken(oldToken)
	if err != nil {
		t.Fatalf("RotateToken failed: %v", err)
	}

	if newToken == oldToken {
		t.Error("expected different token after rotation")
	}

	// Old token should not work
	_, err = v.GetMetadata(oldToken)
	if err == nil {
		t.Error("expected error for old token after rotation")
	}

	// New token should work
	meta, err := v.GetMetadata(newToken)
	if err != nil {
		t.Fatalf("GetMetadata for new token failed: %v", err)
	}
	if meta.Last4 != "1111" {
		t.Errorf("expected last4 '1111', got %s", meta.Last4)
	}

	// PAN should still be retrievable
	pan, err := v.Detokenize(newToken)
	if err != nil {
		t.Fatalf("Detokenize for new token failed: %v", err)
	}
	if pan != "4111111111111111" {
		t.Errorf("expected PAN, got %s", pan)
	}
}

func TestRotateTokenNotFound(t *testing.T) {
	v := setupVault(t)

	_, err := v.RotateToken("tok_nonexistent")
	if err == nil {
		t.Error("expected error for nonexistent token")
	}
}

// MemoryStore tests

func TestMemoryStoreListByCustomer(t *testing.T) {
	s := NewMemoryStore()

	s.Put(&Card{Token: "tok_1", CustomerId: "c1", TenantId: "t1"})
	s.Put(&Card{Token: "tok_2", CustomerId: "c1", TenantId: "t1"})
	s.Put(&Card{Token: "tok_3", CustomerId: "c2", TenantId: "t1"})
	s.Put(&Card{Token: "tok_4", CustomerId: "c1", TenantId: "t2"})

	cards, err := s.ListByCustomer("t1", "c1")
	if err != nil {
		t.Fatal(err)
	}
	if len(cards) != 2 {
		t.Errorf("expected 2 cards for c1/t1, got %d", len(cards))
	}
}

func TestMemoryStoreGetByFingerprint(t *testing.T) {
	s := NewMemoryStore()

	fp := crypto.Fingerprint("4111111111111111")
	s.Put(&Card{Token: "tok_1", Fingerprint: fp, TenantId: "t1"})

	card, err := s.GetByFingerprint("t1", fp)
	if err != nil {
		t.Fatal(err)
	}
	if card == nil {
		t.Error("expected card")
	}

	// Different tenant should not find it
	card, err = s.GetByFingerprint("t2", fp)
	if err != nil {
		t.Fatal(err)
	}
	if card != nil {
		t.Error("expected nil for different tenant")
	}
}
