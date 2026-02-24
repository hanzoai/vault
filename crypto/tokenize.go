package crypto

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
)

const (
	// TokenPrefix is prepended to all vault tokens.
	TokenPrefix = "tok_"

	// TokenLength is the length of the random part of a token.
	TokenLength = 24
)

// GenerateToken creates a unique vault token with the tok_ prefix.
func GenerateToken() (string, error) {
	b := make([]byte, TokenLength)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("vault/crypto: token generation failed: %w", err)
	}
	return TokenPrefix + hex.EncodeToString(b), nil
}

// ValidateToken checks that a token has the correct format.
func ValidateToken(token string) bool {
	if !strings.HasPrefix(token, TokenPrefix) {
		return false
	}
	// tok_ + 48 hex chars = 52 total
	return len(token) == len(TokenPrefix)+TokenLength*2
}

// Fingerprint generates a SHA-256 fingerprint of a PAN.
// Used for deduplication without storing the actual PAN.
func Fingerprint(pan string) string {
	// Normalize: strip spaces and dashes
	normalized := strings.ReplaceAll(pan, " ", "")
	normalized = strings.ReplaceAll(normalized, "-", "")

	h := sha256.Sum256([]byte(normalized))
	return hex.EncodeToString(h[:])
}

// Last4 extracts the last 4 digits of a PAN.
func Last4(pan string) string {
	normalized := strings.ReplaceAll(pan, " ", "")
	normalized = strings.ReplaceAll(normalized, "-", "")
	if len(normalized) < 4 {
		return normalized
	}
	return normalized[len(normalized)-4:]
}

// DetectBrand detects the card brand from the PAN (BIN range).
func DetectBrand(pan string) string {
	normalized := strings.ReplaceAll(pan, " ", "")
	normalized = strings.ReplaceAll(normalized, "-", "")

	if len(normalized) < 1 {
		return "unknown"
	}

	switch {
	case strings.HasPrefix(normalized, "4"):
		return "visa"
	case len(normalized) >= 2:
		prefix2 := normalized[:2]
		switch {
		case prefix2 >= "51" && prefix2 <= "55":
			return "mastercard"
		case prefix2 == "34" || prefix2 == "37":
			return "amex"
		case prefix2 == "36" || prefix2 == "38":
			return "diners"
		case prefix2 == "65":
			return "discover"
		}
		if len(normalized) >= 4 {
			prefix4 := normalized[:4]
			if prefix4 >= "2221" && prefix4 <= "2720" {
				return "mastercard"
			}
			if prefix4 == "6011" {
				return "discover"
			}
			if prefix4 >= "3528" && prefix4 <= "3589" {
				return "jcb"
			}
			if prefix4 == "6200" || prefix4 == "6201" {
				return "unionpay"
			}
		}
	}

	return "unknown"
}
