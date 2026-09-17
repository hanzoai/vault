package crypto

import "testing"

func TestGenerateToken(t *testing.T) {
	token, err := GenerateToken()
	if err != nil {
		t.Fatalf("GenerateToken failed: %v", err)
	}

	if !ValidateToken(token) {
		t.Errorf("generated token should be valid: %s", token)
	}
}

func TestValidateToken(t *testing.T) {
	tests := []struct {
		token string
		valid bool
	}{
		{"tok_" + "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6", true},
		{"tok_short", false},
		{"bad_a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6", false},
		{"", false},
	}

	for _, tt := range tests {
		if got := ValidateToken(tt.token); got != tt.valid {
			t.Errorf("ValidateToken(%q) = %v, want %v", tt.token, got, tt.valid)
		}
	}
}

func TestFingerprint(t *testing.T) {
	fp1 := Fingerprint("4111111111111111")
	fp2 := Fingerprint("4111 1111 1111 1111")
	fp3 := Fingerprint("4111-1111-1111-1111")
	fp4 := Fingerprint("4242424242424242")

	// Same PAN different formats → same fingerprint
	if fp1 != fp2 {
		t.Error("spaces should not affect fingerprint")
	}
	if fp1 != fp3 {
		t.Error("dashes should not affect fingerprint")
	}

	// Different PANs → different fingerprints
	if fp1 == fp4 {
		t.Error("different PANs should have different fingerprints")
	}

	if fp1 == "" {
		t.Error("fingerprint should not be empty")
	}
}

func TestLast4(t *testing.T) {
	tests := []struct {
		pan    string
		expect string
	}{
		{"4111111111111111", "1111"},
		{"4111 1111 1111 1111", "1111"},
		{"4242424242424242", "4242"},
		{"123", "123"},
		{"", ""},
	}

	for _, tt := range tests {
		if got := Last4(tt.pan); got != tt.expect {
			t.Errorf("Last4(%q) = %q, want %q", tt.pan, got, tt.expect)
		}
	}
}

func TestDetectBrand(t *testing.T) {
	tests := []struct {
		pan   string
		brand string
	}{
		{"4111111111111111", "visa"},
		{"4242424242424242", "visa"},
		{"5111111111111118", "mastercard"},
		{"5500000000000004", "mastercard"},
		{"2221000000000009", "mastercard"},
		{"2720000000000005", "mastercard"},
		{"371449635398431", "amex"},
		{"340000000000009", "amex"},
		{"36000000000008", "diners"},
		{"38000000000006", "diners"},
		{"6511111111111118", "discover"},
		{"6011111111111117", "discover"},
		{"3528000000000007", "jcb"},
		{"3589000000000003", "jcb"},
		{"6200000000000005", "unionpay"},
		{"9999999999999999", "unknown"},
		{"", "unknown"},
	}

	for _, tt := range tests {
		if got := DetectBrand(tt.pan); got != tt.brand {
			t.Errorf("DetectBrand(%q) = %q, want %q", tt.pan, got, tt.brand)
		}
	}
}

func TestTokenUniqueness(t *testing.T) {
	tokens := make(map[string]bool)
	for range 100 {
		token, err := GenerateToken()
		if err != nil {
			t.Fatalf("GenerateToken failed: %v", err)
		}
		if tokens[token] {
			t.Fatalf("duplicate token generated: %s", token)
		}
		tokens[token] = true
	}
}
