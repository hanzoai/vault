// Package store provides encrypted card storage for the vault.
package store

import (
	"fmt"
	"sync"
	"time"

	"github.com/hanzoai/vault/crypto"
)

// Card represents a vaulted card record.
type Card struct {
	Token       string    `json:"token"`             // tok_... token
	Brand       string    `json:"brand"`             // visa, mastercard, etc.
	Last4       string    `json:"last4"`             // last 4 digits
	ExpMonth    int       `json:"expMonth"`          // 1-12
	ExpYear     int       `json:"expYear"`           // 4-digit year
	Fingerprint string    `json:"fingerprint"`       // SHA-256 of PAN
	KeyID       string    `json:"keyId"`             // encryption key ID
	Ciphertext  string    `json:"ciphertext"`        // encrypted PAN
	CustomerId  string    `json:"customerId"`        // owner reference
	TenantId    string    `json:"tenantId"`          // multi-tenant isolation
	CreatedAt   time.Time `json:"createdAt"`
	UpdatedAt   time.Time `json:"updatedAt"`
}

// CardMetadata is the non-sensitive view returned by the metadata endpoint.
type CardMetadata struct {
	Token       string    `json:"token"`
	Brand       string    `json:"brand"`
	Last4       string    `json:"last4"`
	ExpMonth    int       `json:"expMonth"`
	ExpYear     int       `json:"expYear"`
	Fingerprint string    `json:"fingerprint"`
	CustomerId  string    `json:"customerId"`
	CreatedAt   time.Time `json:"createdAt"`
}

// Store is the interface for card storage backends.
type Store interface {
	// Put stores or updates a vaulted card.
	Put(card *Card) error

	// Get retrieves a card by token.
	Get(token string) (*Card, error)

	// GetByFingerprint retrieves a card by fingerprint (dedup).
	GetByFingerprint(tenantId, fingerprint string) (*Card, error)

	// Delete removes a vaulted card.
	Delete(token string) error

	// ListByCustomer returns all cards for a customer.
	ListByCustomer(tenantId, customerId string) ([]*Card, error)
}

// MemoryStore is an in-memory store for development/testing.
type MemoryStore struct {
	mu    sync.RWMutex
	cards map[string]*Card // token → card
}

// NewMemoryStore creates a new in-memory card store.
func NewMemoryStore() *MemoryStore {
	return &MemoryStore{
		cards: make(map[string]*Card),
	}
}

func (s *MemoryStore) Put(card *Card) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.cards[card.Token] = card
	return nil
}

func (s *MemoryStore) Get(token string) (*Card, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	card, ok := s.cards[token]
	if !ok {
		return nil, fmt.Errorf("card not found: %s", token)
	}
	return card, nil
}

func (s *MemoryStore) GetByFingerprint(tenantId, fingerprint string) (*Card, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, card := range s.cards {
		if card.TenantId == tenantId && card.Fingerprint == fingerprint {
			return card, nil
		}
	}
	return nil, nil // not found is not an error
}

func (s *MemoryStore) Delete(token string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.cards, token)
	return nil
}

func (s *MemoryStore) ListByCustomer(tenantId, customerId string) ([]*Card, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var result []*Card
	for _, card := range s.cards {
		if card.TenantId == tenantId && card.CustomerId == customerId {
			result = append(result, card)
		}
	}
	return result, nil
}

// TokenizeRequest is the input for card tokenization.
type TokenizeRequest struct {
	PAN        string `json:"pan"`
	ExpMonth   int    `json:"expMonth"`
	ExpYear    int    `json:"expYear"`
	CustomerId string `json:"customerId"`
	TenantId   string `json:"tenantId"`
}

// TokenizeResponse is the output of card tokenization.
type TokenizeResponse struct {
	Token       string `json:"token"`
	Brand       string `json:"brand"`
	Last4       string `json:"last4"`
	ExpMonth    int    `json:"expMonth"`
	ExpYear     int    `json:"expYear"`
	Fingerprint string `json:"fingerprint"`
}

// Vault is the core tokenization service.
type Vault struct {
	store      Store
	keyManager *crypto.KeyManager
}

// NewVault creates a new vault service.
func NewVault(store Store, km *crypto.KeyManager) *Vault {
	return &Vault{
		store:      store,
		keyManager: km,
	}
}

// Tokenize encrypts and stores a card, returning a token.
func (v *Vault) Tokenize(req *TokenizeRequest) (*TokenizeResponse, error) {
	// Validate PAN
	if req.PAN == "" {
		return nil, fmt.Errorf("vault: PAN is required")
	}
	if req.ExpMonth < 1 || req.ExpMonth > 12 {
		return nil, fmt.Errorf("vault: invalid expMonth")
	}
	if req.ExpYear < time.Now().Year() {
		return nil, fmt.Errorf("vault: card is expired")
	}

	// Check for duplicate via fingerprint
	fp := crypto.Fingerprint(req.PAN)
	existing, err := v.store.GetByFingerprint(req.TenantId, fp)
	if err != nil {
		return nil, err
	}
	if existing != nil {
		return &TokenizeResponse{
			Token:       existing.Token,
			Brand:       existing.Brand,
			Last4:       existing.Last4,
			ExpMonth:    existing.ExpMonth,
			ExpYear:     existing.ExpYear,
			Fingerprint: existing.Fingerprint,
		}, nil
	}

	// Generate token
	token, err := crypto.GenerateToken()
	if err != nil {
		return nil, err
	}

	// Encrypt PAN
	keyID, ciphertext, err := v.keyManager.Encrypt([]byte(req.PAN))
	if err != nil {
		return nil, err
	}

	// Detect brand and extract last4
	brand := crypto.DetectBrand(req.PAN)
	last4 := crypto.Last4(req.PAN)

	now := time.Now()
	card := &Card{
		Token:       token,
		Brand:       brand,
		Last4:       last4,
		ExpMonth:    req.ExpMonth,
		ExpYear:     req.ExpYear,
		Fingerprint: fp,
		KeyID:       keyID,
		Ciphertext:  ciphertext,
		CustomerId:  req.CustomerId,
		TenantId:    req.TenantId,
		CreatedAt:   now,
		UpdatedAt:   now,
	}

	if err := v.store.Put(card); err != nil {
		return nil, err
	}

	return &TokenizeResponse{
		Token:       token,
		Brand:       brand,
		Last4:       last4,
		ExpMonth:    req.ExpMonth,
		ExpYear:     req.ExpYear,
		Fingerprint: fp,
	}, nil
}

// Detokenize retrieves the original PAN for a token.
// This is a highly restricted operation (CDE zone only).
func (v *Vault) Detokenize(token string) (string, error) {
	card, err := v.store.Get(token)
	if err != nil {
		return "", err
	}

	plaintext, err := v.keyManager.Decrypt(card.KeyID, card.Ciphertext)
	if err != nil {
		return "", err
	}

	return string(plaintext), nil
}

// GetMetadata returns non-sensitive card metadata.
func (v *Vault) GetMetadata(token string) (*CardMetadata, error) {
	card, err := v.store.Get(token)
	if err != nil {
		return nil, err
	}

	return &CardMetadata{
		Token:       card.Token,
		Brand:       card.Brand,
		Last4:       card.Last4,
		ExpMonth:    card.ExpMonth,
		ExpYear:     card.ExpYear,
		Fingerprint: card.Fingerprint,
		CustomerId:  card.CustomerId,
		CreatedAt:   card.CreatedAt,
	}, nil
}

// DeleteCard removes a vaulted card.
func (v *Vault) DeleteCard(token string) error {
	return v.store.Delete(token)
}

// RotateToken generates a new token for an existing card.
func (v *Vault) RotateToken(oldToken string) (string, error) {
	card, err := v.store.Get(oldToken)
	if err != nil {
		return "", err
	}

	newToken, err := crypto.GenerateToken()
	if err != nil {
		return "", err
	}

	// Delete old, store with new token
	if err := v.store.Delete(oldToken); err != nil {
		return "", err
	}

	card.Token = newToken
	card.UpdatedAt = time.Now()

	if err := v.store.Put(card); err != nil {
		return "", err
	}

	return newToken, nil
}
