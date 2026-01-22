package types

import (
	"encoding/json"
	"testing"
	"time"
)

func TestFieldEncrypted_MarshalJSON(t *testing.T) {
	tests := []struct {
		name     string
		field    FieldEncrypted
		expected string
	}{
		{
			name: "marshals plaintext only",
			field: FieldEncrypted{
				Plaintext:  "test@example.com",
				Ciphertext: "encrypted-data",
				IV:         "iv-data",
				SearchHash: "hash-data",
				Version:    1,
				UpdatedAt:  time.Now(),
			},
			expected: `"test@example.com"`,
		},
		{
			name: "marshals empty plaintext as empty string",
			field: FieldEncrypted{
				Plaintext:  "",
				Ciphertext: "encrypted-data",
			},
			expected: `""`,
		},
		{
			name: "marshals zero value field",
			field: FieldEncrypted{},
			expected: `""`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := json.Marshal(tt.field)
			if err != nil {
				t.Fatalf("MarshalJSON failed: %v", err)
			}
			if string(result) != tt.expected {
				t.Errorf("MarshalJSON = %s, want %s", string(result), tt.expected)
			}
		})
	}
}

func TestFieldEncrypted_UnmarshalJSON(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		expected  string
		expectErr bool
	}{
		{
			name:     "unmarshals simple string",
			input:    `"test@example.com"`,
			expected: "test@example.com",
		},
		{
			name:     "unmarshals empty string",
			input:    `""`,
			expected: "",
		},
		{
			name:     "unmarshals object with plaintext",
			input:    `{"plaintext":"test@example.com","ciphertext":"encrypted"}`,
			expected: "test@example.com",
		},
		{
			name:     "unmarshals object with only plaintext",
			input:    `{"plaintext":"value"}`,
			expected: "value",
		},
		{
			name:      "fails on invalid JSON",
			input:     `{invalid}`,
			expectErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var field FieldEncrypted
			err := json.Unmarshal([]byte(tt.input), &field)
			if tt.expectErr {
				if err == nil {
					t.Error("expected error but got none")
				}
				return
			}
			if err != nil {
				t.Fatalf("UnmarshalJSON failed: %v", err)
			}
			if field.Plaintext != tt.expected {
				t.Errorf("UnmarshalJSON Plaintext = %q, want %q", field.Plaintext, tt.expected)
			}
		})
	}
}

func TestFieldEncrypted_RoundTrip(t *testing.T) {
	// Test that marshal -> unmarshal preserves plaintext
	original := FieldEncrypted{
		Plaintext:  "sensitive-data",
		Ciphertext: "encrypted",
		IV:         "iv",
		SearchHash: "hash",
		Version:    2,
		UpdatedAt:  time.Now(),
	}

	// Marshal (should only output plaintext as string)
	marshaled, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("Marshal failed: %v", err)
	}

	// Unmarshal back
	var result FieldEncrypted
	err = json.Unmarshal(marshaled, &result)
	if err != nil {
		t.Fatalf("Unmarshal failed: %v", err)
	}

	// Only plaintext should be preserved (ciphertext, IV, etc. are stripped)
	if result.Plaintext != original.Plaintext {
		t.Errorf("Plaintext = %q, want %q", result.Plaintext, original.Plaintext)
	}
	if result.Ciphertext != "" {
		t.Errorf("Ciphertext should be empty after round-trip, got %q", result.Ciphertext)
	}
	if result.IV != "" {
		t.Errorf("IV should be empty after round-trip, got %q", result.IV)
	}
}

func TestFieldEncrypted_InStruct(t *testing.T) {
	// Test that FieldEncrypted works correctly when embedded in a struct
	type User struct {
		Name  string         `json:"name"`
		Email FieldEncrypted `json:"email"`
	}

	user := User{
		Name: "John Doe",
		Email: FieldEncrypted{
			Plaintext:  "john@example.com",
			Ciphertext: "encrypted-email",
			IV:         "iv-data",
		},
	}

	// Marshal
	data, err := json.Marshal(user)
	if err != nil {
		t.Fatalf("Marshal failed: %v", err)
	}

	expected := `{"name":"John Doe","email":"john@example.com"}`
	if string(data) != expected {
		t.Errorf("Marshal = %s, want %s", string(data), expected)
	}

	// Unmarshal
	var result User
	err = json.Unmarshal([]byte(`{"name":"Jane Doe","email":"jane@example.com"}`), &result)
	if err != nil {
		t.Fatalf("Unmarshal failed: %v", err)
	}
	if result.Email.Plaintext != "jane@example.com" {
		t.Errorf("Email.Plaintext = %q, want %q", result.Email.Plaintext, "jane@example.com")
	}
}

func TestFieldEncrypted_SecurityNoLeakage(t *testing.T) {
	// Security test: Ensure ciphertext, IV, and searchHash are NEVER in JSON output
	field := FieldEncrypted{
		Plaintext:  "visible",
		Ciphertext: "SECRET_CIPHERTEXT",
		IV:         "SECRET_IV",
		SearchHash: "SECRET_HASH",
		Version:    1,
	}

	data, err := json.Marshal(field)
	if err != nil {
		t.Fatalf("Marshal failed: %v", err)
	}

	output := string(data)
	
	// Ensure no sensitive data leaks
	if containsAny(output, []string{"SECRET_CIPHERTEXT", "SECRET_IV", "SECRET_HASH", "ciphertext", "iv", "searchHash"}) {
		t.Errorf("JSON output contains sensitive data: %s", output)
	}
}

func containsAny(s string, substrings []string) bool {
	for _, sub := range substrings {
		if len(sub) > 0 && len(s) >= len(sub) {
			for i := 0; i <= len(s)-len(sub); i++ {
				if s[i:i+len(sub)] == sub {
					return true
				}
			}
		}
	}
	return false
}
