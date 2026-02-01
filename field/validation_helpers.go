package field

import (
	"context"
	"fmt"

	"github.com/root-sector-ltd-and-co-kg/payment-gateway-lib-crypto/types"
)

// ValidateEncryptedField is a helper function to validate an encrypted field
func ValidateEncryptedField(ctx context.Context, field *types.FieldEncrypted, decryptFunc func(context.Context, *types.FieldEncrypted) error) error {
	if field == nil {
		return fmt.Errorf("field is nil")
	}

	// If there's no ciphertext, nothing to validate
	if field.Ciphertext == "" {
		return fmt.Errorf("no ciphertext to validate")
	}

	// Store original plaintext for validation
	originalPlaintext := field.Plaintext

	// Try to decrypt the field
	if err := decryptFunc(ctx, field); err != nil {
		// Restore original plaintext since decryption failed
		field.Plaintext = originalPlaintext
		return fmt.Errorf("failed to decrypt field for validation: %w", err)
	}

	// Validate decrypted value matches original plaintext
	if field.Plaintext != originalPlaintext {
		// Restore original plaintext since validation failed
		field.Plaintext = originalPlaintext
		return fmt.Errorf("decrypted value does not match original plaintext")
	}

	// Clear plaintext after successful validation
	field.Plaintext = ""
	return nil
}
