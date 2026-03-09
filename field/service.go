package field

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"
	"sync/atomic"
	"time"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"

	"github.com/root-sector-ltd-and-co-kg/payment-gateway-lib-crypto/audit"
	"github.com/root-sector-ltd-and-co-kg/payment-gateway-lib-crypto/interfaces"
	"github.com/root-sector-ltd-and-co-kg/payment-gateway-lib-crypto/types"
)

var (
	// ErrEncryptionDisabled indicates that encryption is not enabled
	ErrEncryptionDisabled = fmt.Errorf("encryption is disabled")
	// ErrMissingSearchKey indicates that a search key is required for searchable encryption
	ErrMissingSearchKey = fmt.Errorf("search key is required for searchable encryption")
)

// fieldService implements the interfaces.FieldService interface
type fieldService struct {
	dekService interfaces.DEKService
	logger     interfaces.AuditLogger
	stats      types.FieldStats
	scope      string
	orgID      string
	zLogger    zerolog.Logger
}

// NewFieldService creates a new field encryption service
func NewFieldService(dekSvc interfaces.DEKService, logger interfaces.AuditLogger, zLogger zerolog.Logger, scope string, orgID string) interfaces.FieldService {
	// Use provided zLogger or default to global log.Logger
	opLogger := zLogger
	if opLogger.GetLevel() == zerolog.Disabled {
		opLogger = log.Logger
	}

	opLogger.Trace().
		Bool("hasDEKService", dekSvc != nil).
		Bool("hasLogger", logger != nil).
		Str("scope", scope).
		Str("orgID", orgID).
		Msg("Creating new field service")

	// If DEK service is nil, create a no-op service that only handles plaintext
	if dekSvc == nil {
		opLogger.Trace().
			Msg("Creating no-op field service (DEK service is nil)")
		return &fieldService{
			logger:  logger,
			zLogger: opLogger,
			scope:   scope,
			orgID:   orgID,
		}
	}

	svc := &fieldService{
		dekService: dekSvc,
		logger:     logger,
		zLogger:    opLogger,
		scope:      scope,
		orgID:      orgID,
	}

	opLogger.Trace().
		Msg("Field service created successfully")

	return svc
}

// GenerateSearchHash creates a consistent hash for searchable encrypted fields.
// It uses HMAC-SHA256 with a provided secret key.
func generateSearchHash(value string, searchKey []byte) string {
	if len(searchKey) == 0 {
		log.Error().Msg("Search key is empty, cannot generate search hash.")
		return ""
	}
	if value == "" {
		return ""
	}

	// Normalize: Convert to lowercase and trim whitespace
	normalizedValue := strings.ToLower(strings.TrimSpace(value))
	if normalizedValue == "" {
		log.Warn().Str("originalValue", value).Msg("Value became empty after normalization, returning empty search hash.")
		return "" // Return empty if value was only whitespace
	}

	h := hmac.New(sha256.New, searchKey)
	// Use the normalized value for hashing
	h.Write([]byte(normalizedValue))
	return base64.StdEncoding.EncodeToString(h.Sum(nil))
}

// buildAAD constructs the Additional Authenticated Data (AAD) string
// using the full context: scope, id, collection, fieldName, and version.
func (s *fieldService) buildAAD(ctx context.Context, version uint32) ([]byte, error) {
	// Extract scope, scopeID, collection, and fieldName from context using helpers
	scope, scopeID := GetScopeAndIDFromContext(ctx)
	collection, _, fieldName, _ := ExtractFieldInfoFromContext(ctx)

	// Log extracted/passed values for debugging AAD issues
	log.Trace().
		Str("scope", scope).
		Str("scopeID", scopeID).
		Str("collection", collection).
		Str("fieldName", fieldName).
		Uint32("version", version).
		Msg("Building AAD with extracted context")

	// Validate that we extracted necessary context
	if scope == "unknown" || collection == "unknown" || fieldName == "unknown" || (scope == "organization" && scopeID == "") {
		log.Error().
			Str("scope", scope).
			Str("scopeID", scopeID).
			Str("extractedCollection", collection).
			Str("extractedFieldName", fieldName).
			Uint32("version", version).
			Msgf("Failed to build AAD: Missing required context (scope=%s, scopeID=%s, collection=%s, fieldName=%s) for AAD construction", scope, scopeID, collection, fieldName)
		return nil, fmt.Errorf("missing required context (scope=%s, scopeID=%s, collection=%s, fieldName=%s) for AAD construction", scope, scopeID, collection, fieldName)
	}

	aadString := fmt.Sprintf("collection=%s:field=%s:id=%s:scope=%s:v=%d",
		collection, fieldName, scopeID, scope, version)

	log.Trace().Str("aad", aadString).Msg("Constructed AAD")
	return []byte(aadString), nil
}

// Encrypt encrypts a field value if encryption is enabled
func (s *fieldService) Encrypt(ctx context.Context, field *types.FieldEncrypted) error {
	if field == nil {
		return fmt.Errorf("field is nil")
	}

	// Create audit event
	auditEvent := CreateAuditEvent(ctx, field, audit.EventTypeFieldEncrypt, audit.OperationEncrypt)

	// Always update timestamp
	field.UpdatedAt = time.Now().UTC()

	// If there's no plaintext, nothing to encrypt
	if field.Plaintext == "" {
		if s.logger != nil {
			auditEvent.Status = audit.StatusSuccess
			auditEvent.Context["reason"] = "no_plaintext"
			s.logger.LogEvent(ctx, auditEvent)
		}
		return nil
	}

	// If DEK service is nil, encryption is disabled - just keep plaintext
	if s.dekService == nil {
		// Clear any existing encryption fields to ensure consistency
		field.Ciphertext = ""
		field.IV = ""
		field.Version = 0

		if s.logger != nil {
			auditEvent.Status = audit.StatusSuccess
			auditEvent.Context["reason"] = "encryption_disabled"
			s.logger.LogEvent(ctx, auditEvent)
		}
		return nil
	}

	// Get the current DEK status using scope/ID from context
	scope, scopeID := GetScopeAndIDFromContext(ctx)
	dekStatus, err := s.dekService.GetDEKStatus(ctx, scope, scopeID)
	if err != nil {
		if s.logger != nil {
			auditEvent.Status = audit.StatusFailed
			auditEvent.Context["error"] = fmt.Sprintf("failed_get_dek_status: %v", err)
			s.logger.LogEvent(ctx, auditEvent)
		}
		return fmt.Errorf("failed to get DEK status for scope %s/%s: %w", scope, scopeID, err)
	}

	// If DEK is not active, operate in plaintext mode
	if !dekStatus.Active {
		// Clear any existing encryption fields
		field.Ciphertext = ""
		field.IV = ""
		field.Version = 0

		if s.logger != nil {
			auditEvent.Status = audit.StatusSuccess
			auditEvent.Context["reason"] = "dek_not_active"
			s.logger.LogEvent(ctx, auditEvent)
		}
		return nil
	}

	// Set version from the current active DEK version
	field.Version = uint32(dekStatus.Version)
	auditEvent.DEKVersion = dekStatus.Version

	// Additional authenticated data (AAD) includes version for integrity
	aad, err := s.buildAAD(ctx, field.Version)
	if err != nil {
		// Log error and update audit event status
		log.Error().Err(err).Str("scope", scope).Str("scopeID", scopeID).Uint32("version", field.Version).Msg("Failed to build AAD during encryption")
		if s.logger != nil {
			auditEvent.Status = audit.StatusFailed
			auditEvent.Context["error"] = fmt.Sprintf("failed_build_aad: %v", err)
			s.logger.LogEvent(ctx, auditEvent)
		}
		return fmt.Errorf("failed to build AAD for encryption: %w", err)
	}

	// Get active DEK using scope/ID from context
	dek, dekErr := s.dekService.GetActiveDEK(ctx, scope, scopeID)
	if dekErr != nil {
		if s.logger != nil {
			auditEvent.Status = audit.StatusFailed
			auditEvent.Context["error"] = fmt.Sprintf("failed_get_active_dek: %v", dekErr)
			s.logger.LogEvent(ctx, auditEvent)
		}
		return fmt.Errorf("failed to get active DEK: %w", dekErr)
	}

	// If no key is returned, keep plaintext
	if dek == nil {
		// Clear any existing encryption fields
		field.Ciphertext = ""
		field.IV = ""
		field.Version = 0

		if s.logger != nil {
			auditEvent.Status = audit.StatusSuccess
			auditEvent.Context["reason"] = "no_active_dek"
			s.logger.LogEvent(ctx, auditEvent)
		}
		return nil
	}

	// Create AES cipher
	block, cipherErr := aes.NewCipher(dek)
	if cipherErr != nil {
		if s.logger != nil {
			auditEvent.Status = audit.StatusFailed
			auditEvent.Context["error"] = fmt.Sprintf("failed_create_cipher: %v", cipherErr)
			s.logger.LogEvent(ctx, auditEvent)
		}
		return fmt.Errorf("failed to create cipher: %w", cipherErr)
	}

	// Create GCM mode
	gcm, gcmErr := cipher.NewGCM(block)
	if gcmErr != nil {
		if s.logger != nil {
			auditEvent.Status = audit.StatusFailed
			auditEvent.Context["error"] = fmt.Sprintf("failed_create_gcm: %v", gcmErr)
			s.logger.LogEvent(ctx, auditEvent)
		}
		return fmt.Errorf("failed to create GCM: %w", gcmErr)
	}

	// Generate random nonce
	nonce := make([]byte, gcm.NonceSize())
	if _, nonceErr := rand.Read(nonce); nonceErr != nil {
		if s.logger != nil {
			auditEvent.Status = audit.StatusFailed
			auditEvent.Context["error"] = fmt.Sprintf("failed_generate_nonce: %v", nonceErr)
			s.logger.LogEvent(ctx, auditEvent)
		}
		return fmt.Errorf("failed to generate nonce: %w", nonceErr)
	}

	// Encrypt plaintext with AAD
	ciphertext := gcm.Seal(nil, nonce, []byte(field.Plaintext), aad)

	// Update field with encrypted values
	field.Ciphertext = base64.StdEncoding.EncodeToString(ciphertext)
	field.IV = base64.StdEncoding.EncodeToString(nonce)
	field.Plaintext = "" // Clear plaintext after successful encryption

	// Update stats
	atomic.AddUint64(&s.stats.TotalEncrypts, 1)
	now := time.Now().UTC()
	s.stats.LastEncryptTime = now
	s.stats.LastOpTime = now

	return nil
}

// Decrypt decrypts a field value if it is encrypted
func (s *fieldService) Decrypt(ctx context.Context, field *types.FieldEncrypted) error {
	if field == nil {
		return fmt.Errorf("field is nil")
	}

	// Create audit event
	auditEvent := CreateAuditEvent(ctx, field, audit.EventTypeFieldDecrypt, audit.OperationDecrypt)

	// If there's no ciphertext, nothing to decrypt
	if field.Ciphertext == "" {
		if s.logger != nil {
			auditEvent.Status = audit.StatusSuccess
			auditEvent.Context["reason"] = "no_ciphertext"
			s.logger.LogEvent(ctx, auditEvent)
		}
		return nil
	}

	// If DEK service is nil, encryption is disabled
	if s.dekService == nil {
		// If we have ciphertext but no DEK service, we can't decrypt
		// Return error only if we don't have plaintext
		if field.Plaintext == "" {
			if s.logger != nil {
				auditEvent.Status = audit.StatusFailed
				auditEvent.Context["error"] = "encryption_disabled_no_plaintext"
				s.logger.LogEvent(ctx, auditEvent)
			}
			return fmt.Errorf("cannot decrypt field: encryption is disabled and no plaintext available")
		}
		// If we have plaintext, just update timestamp and return
		field.UpdatedAt = time.Now().UTC()
		if s.logger != nil {
			auditEvent.Status = audit.StatusSuccess
			auditEvent.Context["reason"] = "has_plaintext"
			s.logger.LogEvent(ctx, auditEvent)
		}
		return nil
	}

	// Get DEK Info using scope/ID from context
	scope, scopeID := GetScopeAndIDFromContext(ctx)
	dekInfo, err := s.dekService.GetInfo(ctx, scope, scopeID)
	if err != nil {
		if s.logger != nil {
			auditEvent.Status = audit.StatusFailed
			auditEvent.Context["error"] = fmt.Sprintf("failed_get_dek_info: %v", err)
			s.logger.LogEvent(ctx, auditEvent)
		}
		return fmt.Errorf("failed to get DEK info for scope %s/%s: %w", scope, scopeID, err)
	}

	// Find the correct version
	var version *types.DEKVersion
	for _, v := range dekInfo.Versions {
		if v.Version == int(field.Version) {
			version = &v
			break
		}
	}

	if version == nil {
		if s.logger != nil {
			auditEvent.Status = audit.StatusFailed
			auditEvent.Context["error"] = fmt.Sprintf("dek_version_not_found: %d", field.Version)
			s.logger.LogEvent(ctx, auditEvent)
		}
		return fmt.Errorf("DEK version %d not found", field.Version)
	}

	// Build AAD using the version stored in the field and the context
	aad, err := s.buildAAD(ctx, field.Version)
	if err != nil {
		// Log error and update audit event status
		log.Error().Err(err).Str("scope", scope).Str("scopeID", scopeID).Uint32("version", field.Version).Msg("Failed to build AAD during decryption")
		if s.logger != nil {
			auditEvent.Status = audit.StatusFailed
			auditEvent.Context["error"] = fmt.Sprintf("failed_build_aad: %v", err)
			s.logger.LogEvent(ctx, auditEvent)
		}
		return fmt.Errorf("failed to build AAD for decryption: %w", err)
	}

	// Get DEK for version using stored scope/ID
	key, err := s.dekService.UnwrapDEK(ctx, version, s.scope, s.orgID)
	if err != nil {
		if s.logger != nil {
			if auditEvent != nil {
				auditEvent.Status = audit.StatusFailed
				auditEvent.Context["error"] = fmt.Sprintf("failed_unwrap_dek: %v", err)
				s.logger.LogEvent(ctx, auditEvent)
			} else {
				s.zLogger.Error().Err(err).Str("scope", s.scope).Str("orgID", s.orgID).Msg("Audit event (auditEvent) was nil during DEK unwrap failure in Decrypt method")
			}
		}
		return fmt.Errorf("failed to get DEK: %w", err)
	}

	ciphertext, err := base64.StdEncoding.DecodeString(field.Ciphertext)
	if err != nil {
		if s.logger != nil {
			auditEvent.Status = audit.StatusFailed
			auditEvent.Context["error"] = fmt.Sprintf("failed_decode_ciphertext: %v", err)
			s.logger.LogEvent(ctx, auditEvent)
		}
		return fmt.Errorf("failed to decode ciphertext: %w", err)
	}

	nonce, err := base64.StdEncoding.DecodeString(field.IV)
	if err != nil {
		if s.logger != nil {
			auditEvent.Status = audit.StatusFailed
			auditEvent.Context["error"] = fmt.Sprintf("failed_decode_iv: %v", err)
			s.logger.LogEvent(ctx, auditEvent)
		}
		return fmt.Errorf("failed to decode IV: %w", err)
	}

	// Create AES cipher
	block, cipherErr := aes.NewCipher(key)
	if cipherErr != nil {
		if s.logger != nil {
			auditEvent.Status = audit.StatusFailed
			auditEvent.Context["error"] = fmt.Sprintf("failed_create_cipher: %v", cipherErr)
			s.logger.LogEvent(ctx, auditEvent)
		}
		return fmt.Errorf("failed to create cipher: %w", cipherErr)
	}

	// Create GCM mode
	gcm, gcmErr := cipher.NewGCM(block)
	if gcmErr != nil {
		if s.logger != nil {
			auditEvent.Status = audit.StatusFailed
			auditEvent.Context["error"] = fmt.Sprintf("failed_create_gcm: %v", gcmErr)
			s.logger.LogEvent(ctx, auditEvent)
		}
		return fmt.Errorf("failed to create GCM: %w", gcmErr)
	}

	plaintextBytes, openErr := gcm.Open(nil, nonce, ciphertext, aad)
	if openErr != nil {
		if s.logger != nil {
			auditEvent.Status = audit.StatusFailed
			auditEvent.Context["error"] = fmt.Sprintf("failed_decrypt: %v", openErr)
			s.logger.LogEvent(ctx, auditEvent)
		}
		return fmt.Errorf("failed to decrypt data: %w", openErr)
	}

	// Update field with decrypted value
	field.Plaintext = string(plaintextBytes)
	field.UpdatedAt = time.Now().UTC()

	// Update stats
	atomic.AddUint64(&s.stats.TotalDecrypts, 1)
	now := time.Now().UTC()
	s.stats.LastDecryptTime = now
	s.stats.LastOpTime = now

	return nil
}

// EncryptSearchable encrypts a field value and generates a search hash
func (s *fieldService) EncryptSearchable(ctx context.Context, field *types.FieldEncrypted, searchKey string) error {
	if field == nil {
		return fmt.Errorf("field is nil")
	}

	if searchKey == "" {
		return ErrMissingSearchKey
	}

	// Decode the hex search key
	decodedSearchKey, err := hex.DecodeString(searchKey)
	if err != nil {
		log.Error().Err(err).Msg("Failed to decode search key for EncryptSearchable")
		return fmt.Errorf("invalid search key format: %w", err)
	}
	// Basic validation after decoding (optional, but good practice)
	if len(decodedSearchKey) == 0 {
		log.Error().Msg("Decoded search key is empty for EncryptSearchable")
		return fmt.Errorf("decoded search key cannot be empty")
	}

	// Create audit event
	auditEvent := CreateAuditEvent(ctx, field, audit.EventTypeFieldEncrypt, audit.OperationEncrypt)

	// Always update timestamp
	field.UpdatedAt = time.Now().UTC()

	// Generate HMAC-SHA256 search hash first using the decoded key
	if field.Plaintext != "" {
		field.SearchHash = generateSearchHash(field.Plaintext, decodedSearchKey) // Use decoded key
	}

	// If DEK service is nil or encryption is disabled, just update timestamp and return
	if s.dekService == nil {
		// Clear any existing encryption fields to ensure consistency
		field.Ciphertext = ""
		field.IV = ""
		field.Version = 0

		// Log audit event
		if s.logger != nil {
			auditEvent.Status = audit.StatusSuccess
			auditEvent.Context["mode"] = "plaintext"
			s.logger.LogEvent(ctx, auditEvent)
		}
		return nil
	}

	// Get DEK status using scope/ID from context
	scope, scopeID := GetScopeAndIDFromContext(ctx)
	systemStatus, err := s.dekService.GetDEKStatus(ctx, scope, scopeID)
	if err != nil {
		if s.logger != nil {
			auditEvent.Status = audit.StatusFailed
			auditEvent.Context["error"] = err.Error()
			s.logger.LogEvent(ctx, auditEvent)
		}
		return fmt.Errorf("failed to get DEK status for scope %s/%s: %w", scope, scopeID, err)
	}

	// If no active DEK, operate in plaintext mode
	if !systemStatus.Active {
		// Clear any existing encryption fields
		field.Ciphertext = ""
		field.IV = ""
		field.Version = 0

		// Log audit event
		if s.logger != nil {
			auditEvent.Status = audit.StatusSuccess
			auditEvent.Context["mode"] = "plaintext_no_dek"
			s.logger.LogEvent(ctx, auditEvent)
		}

		return nil
	}

	// Set the field version to the current DEK version
	field.Version = uint32(systemStatus.Version)
	auditEvent.DEKVersion = systemStatus.Version

	// Additional authenticated data (AAD) includes version for integrity
	aad, err := s.buildAAD(ctx, field.Version)
	if err != nil {
		// Log error and update audit event status
		log.Error().Err(err).Str("scope", scope).Str("scopeID", scopeID).Uint32("version", field.Version).Msg("Failed to build AAD during searchable encryption")
		if s.logger != nil {
			auditEvent.Status = audit.StatusFailed
			auditEvent.Context["error"] = fmt.Sprintf("failed_build_aad: %v", err)
			s.logger.LogEvent(ctx, auditEvent)
		}
		return fmt.Errorf("failed to build AAD for searchable encryption: %w", err)
	}

	// Get DEK for encryption using scope/ID from context
	dek, dekErr := s.dekService.GetActiveDEK(ctx, scope, scopeID)
	if dekErr != nil {
		if s.logger != nil {
			auditEvent.Status = audit.StatusFailed
			auditEvent.Context["error"] = fmt.Sprintf("failed_get_active_dek: %v", dekErr)
			s.logger.LogEvent(ctx, auditEvent)
		}
		return fmt.Errorf("failed to get active DEK: %w", dekErr)
	}

	// Create AES cipher
	block, cipherErr := aes.NewCipher(dek)
	if cipherErr != nil {
		if s.logger != nil {
			auditEvent.Status = audit.StatusFailed
			auditEvent.Context["error"] = fmt.Sprintf("failed_create_cipher: %v", cipherErr)
			s.logger.LogEvent(ctx, auditEvent)
		}
		return fmt.Errorf("failed to create cipher: %w", cipherErr)
	}

	// Create GCM mode
	gcm, gcmErr := cipher.NewGCM(block)
	if gcmErr != nil {
		if s.logger != nil {
			auditEvent.Status = audit.StatusFailed
			auditEvent.Context["error"] = fmt.Sprintf("failed_create_gcm: %v", gcmErr)
			s.logger.LogEvent(ctx, auditEvent)
		}
		return fmt.Errorf("failed to create GCM: %w", gcmErr)
	}

	// Generate random nonce
	nonce := make([]byte, gcm.NonceSize())
	if _, nonceErr := rand.Read(nonce); nonceErr != nil {
		if s.logger != nil {
			auditEvent.Status = audit.StatusFailed
			auditEvent.Context["error"] = fmt.Sprintf("failed_generate_nonce: %v", nonceErr)
			s.logger.LogEvent(ctx, auditEvent)
		}
		return fmt.Errorf("failed to generate nonce: %w", nonceErr)
	}

	// Encrypt plaintext with AAD
	ciphertext := gcm.Seal(nil, nonce, []byte(field.Plaintext), aad)

	// Update field with encrypted values
	field.Ciphertext = base64.StdEncoding.EncodeToString(ciphertext)
	field.IV = base64.StdEncoding.EncodeToString(nonce)
	field.Plaintext = "" // Clear plaintext after successful encryption

	// Update stats
	atomic.AddUint64(&s.stats.TotalEncrypts, 1)
	now := time.Now().UTC()
	s.stats.LastEncryptTime = now
	s.stats.LastOpTime = now

	// Log successful encryption
	if s.logger != nil {
		auditEvent.Status = audit.StatusSuccess
		s.logger.LogEvent(ctx, auditEvent)
	}

	return nil
}

// Match checks if a plaintext value matches an encrypted searchable field
func (s *fieldService) Match(ctx context.Context, field *types.FieldEncrypted, value string, searchKey string) (bool, error) {
	if field == nil {
		return false, fmt.Errorf("field is nil")
	}

	if searchKey == "" {
		return false, ErrMissingSearchKey
	}

	// Decode the hex search key
	decodedSearchKey, err := hex.DecodeString(searchKey)
	if err != nil {
		log.Error().Err(err).Msg("Failed to decode search key for Match")
		// Return false and error as we cannot perform the match
		return false, fmt.Errorf("invalid search key format: %w", err)
	}
	if len(decodedSearchKey) == 0 {
		log.Error().Msg("Decoded search key is empty for Match")
		return false, fmt.Errorf("decoded search key cannot be empty")
	}

	// If field has no search hash, return false
	if field.SearchHash == "" {
		return false, nil
	}

	// Generate HMAC-SHA256 hash of search value using the decoded key
	searchHash := generateSearchHash(value, decodedSearchKey) // Use decoded key

	// Compare hashes
	return searchHash == field.SearchHash, nil
}

// Verify verifies the integrity of an encrypted field
func (s *fieldService) Verify(ctx context.Context, field *types.FieldEncrypted) error {
	if field == nil {
		return fmt.Errorf("field is nil")
	}

	// Create audit event
	event := CreateAuditEvent(ctx, field, "verify", "field_verify")

	// Log start event
	if err := s.logger.LogEvent(ctx, event); err != nil {
		fmt.Printf("Failed to log audit event: %v\n", err)
	}

	defer func() {
		// Always update event status at the end
		event.Status = "completed"
		event.Timestamp = time.Now().UTC()
		if err := s.logger.LogEvent(ctx, event); err != nil {
			fmt.Printf("Failed to log audit event: %v\n", err)
		}
	}()

	// Check required fields
	if field.Version == 0 {
		return fmt.Errorf("version is required")
	}
	if field.Ciphertext == "" {
		return fmt.Errorf("ciphertext is required")
	}
	if field.IV == "" {
		return fmt.Errorf("IV is required")
	}

	// Get DEK Info using scope/ID from context
	scope, scopeID := GetScopeAndIDFromContext(ctx)
	dekInfo, err := s.dekService.GetInfo(ctx, scope, scopeID)
	if err != nil {
		return fmt.Errorf("failed to get DEK info for scope %s/%s: %w", scope, scopeID, err)
	}

	// Find the correct version
	var version *types.DEKVersion
	for _, v := range dekInfo.Versions {
		if v.Version == int(field.Version) {
			version = &v
			break
		}
	}

	if version == nil {
		return fmt.Errorf("DEK version %d not found", field.Version)
	}

	// Get DEK for version using stored scope/ID
	key, err := s.dekService.UnwrapDEK(ctx, version, s.scope, s.orgID)
	if err != nil {
		if s.logger != nil {
			if event != nil {
				event.Status = audit.StatusFailed
				event.Context["error"] = fmt.Sprintf("failed_unwrap_dek: %v", err)
				s.logger.LogEvent(ctx, event)
			} else {
				s.zLogger.Error().Err(err).Str("scope", s.scope).Str("orgID", s.orgID).Msg("Audit event (event) was nil during DEK unwrap failure in Verify method")
			}
		}
		return fmt.Errorf("failed to get DEK: %w", err)
	}

	// Decode base64 values
	ciphertext, err := base64.StdEncoding.DecodeString(field.Ciphertext)
	if err != nil {
		return fmt.Errorf("failed to decode ciphertext: %w", err)
	}

	nonce, err := base64.StdEncoding.DecodeString(field.IV)
	if err != nil {
		return fmt.Errorf("failed to decode IV: %w", err)
	}

	// Create AES cipher
	block, err := aes.NewCipher(key)
	if err != nil {
		return fmt.Errorf("failed to create cipher: %w", err)
	}

	// Create GCM mode with default tag size (16 bytes)
	gcm, gcmErr := cipher.NewGCM(block)
	if gcmErr != nil {
		return fmt.Errorf("failed to create GCM: %w", gcmErr)
	}

	// Additional authenticated data (AAD) includes version for integrity
	aad, err := s.buildAAD(ctx, field.Version)
	if err != nil {
		// Log error - might not have audit event here, log directly
		log.Error().Err(err).Str("scope", scope).Str("scopeID", scopeID).Uint32("version", field.Version).Msg("Failed to build AAD during verification")
		return fmt.Errorf("failed to build AAD for verification: %w", err)
	}

	// Attempt to decrypt to verify integrity
	_, openErr := gcm.Open(nil, nonce, ciphertext, aad)
	if openErr != nil {
		if s.logger != nil {
			if event != nil {
				event.Status = audit.StatusFailed
				event.Context["error"] = fmt.Sprintf("gcm_open_failed: %v", openErr)
				s.logger.LogEvent(ctx, event)
			} else {
				s.zLogger.Error().Err(openErr).Str("scope", s.scope).Str("orgID", s.orgID).Msg("Audit event (event) was nil during GCM open failure in Verify method")
			}
		}
		return fmt.Errorf("failed to verify field: %w", openErr)
	}

	return nil
}

// GetStats returns statistics about field encryption operations
func (s *fieldService) GetStats(ctx context.Context) (*types.FieldStats, error) {
	// Convert internal stats to the return type
	return &types.FieldStats{
		TotalEncrypts:   s.stats.TotalEncrypts,
		TotalDecrypts:   s.stats.TotalDecrypts,
		LastEncryptTime: s.stats.LastEncryptTime,
		LastDecryptTime: s.stats.LastDecryptTime,
		LastOpTime:      s.stats.LastOpTime,
	}, nil
}

// ValidateAndCleanupEncryptedField validates that the ciphertext decrypts to the plaintext
// and removes the plaintext if validation is successful
func (s *fieldService) ValidateAndCleanupEncryptedField(ctx context.Context, field *types.FieldEncrypted) error {
	if field == nil {
		return fmt.Errorf("field is nil")
	}

	// If there's no ciphertext, nothing to validate
	if field.Ciphertext == "" {
		return fmt.Errorf("no ciphertext to validate")
	}

	// Create a validation decorator
	validateFunc := func(ctx context.Context, e *types.FieldEncrypted) error {
		// Try to decrypt using our decrypt method
		return s.Decrypt(ctx, e)
	}

	// Use the validate function
	if err := ValidateEncryptedField(ctx, field, validateFunc); err != nil {
		return err
	}

	// Validation successful
	return nil
}

// ValidateAndCleanupEncryptedFields validates and cleans up multiple encrypted fields
func (s *fieldService) ValidateAndCleanupEncryptedFields(ctx context.Context, fields ...*types.FieldEncrypted) error {
	for _, field := range fields {
		if err := s.ValidateAndCleanupEncryptedField(ctx, field); err != nil {
			return fmt.Errorf("failed to validate and cleanup field: %w", err)
		}
	}
	return nil
}
