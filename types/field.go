package types

import (
	"encoding/json"
	"time"
)

// Encrypted represents a value that can be encrypted or plaintext.
// In JSON responses, this type serializes to a plain string (only the plaintext value).
// swagger:strfmt string
// @Description Encrypted field that serializes to a plain string in API responses
type FieldEncrypted struct {
	Version    uint32    `json:"version,omitempty" bson:"version,omitempty" swaggerignore:"true"`       // DEK version used for encryption
	Ciphertext string    `json:"ciphertext,omitempty" bson:"ciphertext,omitempty" swaggerignore:"true"` // Base64 encoded encrypted value
	IV         string    `json:"iv,omitempty" bson:"iv,omitempty" swaggerignore:"true"`                 // Base64 encoded initialization vector
	Plaintext  string    `json:"plaintext,omitempty" bson:"plaintext,omitempty"`                        // Original unencrypted value
	SearchHash string    `json:"searchHash,omitempty" bson:"searchHash,omitempty" swaggerignore:"true"` // Optional Base64 encoded hash for searching
	UpdatedAt  time.Time `json:"updatedAt" bson:"updatedAt" swaggerignore:"true"`                       // Last update timestamp
}

// MarshalJSON customizes JSON serialization to only output the plaintext value.
// This prevents sensitive encryption metadata (ciphertext, IV, searchHash) from
// being exposed in API responses while maintaining BSON storage of all fields.
func (f FieldEncrypted) MarshalJSON() ([]byte, error) {
	// For API responses, only return the plaintext value as a simple string
	// Empty strings are marshaled as empty strings (not null)
	return json.Marshal(f.Plaintext)
}

// UnmarshalJSON customizes JSON deserialization to handle both:
// 1. Simple string values (from API requests): "value"
// 2. Object format with plaintext field: {"plaintext": "value"}
func (f *FieldEncrypted) UnmarshalJSON(data []byte) error {
	// First try to unmarshal as a simple string
	var plainString string
	if err := json.Unmarshal(data, &plainString); err == nil {
		f.Plaintext = plainString
		return nil
	}

	// If not a string, try the full object format
	type fieldAlias FieldEncrypted
	var obj fieldAlias
	if err := json.Unmarshal(data, &obj); err != nil {
		return err
	}
	*f = FieldEncrypted(obj)
	return nil
}

// FieldStats holds statistics about field encryption operations
type FieldStats struct {
	TotalEncrypts   uint64    `json:"totalEncrypts" bson:"totalEncrypts"`
	TotalDecrypts   uint64    `json:"totalDecrypts" bson:"totalDecrypts"`
	LastEncryptTime time.Time `json:"lastEncryptTime" bson:"lastEncryptTime"`
	LastDecryptTime time.Time `json:"lastDecryptTime" bson:"lastDecryptTime"`
	LastOpTime      time.Time `json:"lastOpTime" bson:"lastOpTime"`
}
