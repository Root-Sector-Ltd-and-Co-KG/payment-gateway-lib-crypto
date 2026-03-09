package dek

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	wrapping "github.com/hashicorp/go-kms-wrapping/v2"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"go.mongodb.org/mongo-driver/v2/mongo"

	"github.com/root-sector-ltd-and-co-kg/payment-gateway-lib-crypto/audit"
	"github.com/root-sector-ltd-and-co-kg/payment-gateway-lib-crypto/field"
	"github.com/root-sector-ltd-and-co-kg/payment-gateway-lib-crypto/interfaces"
	"github.com/root-sector-ltd-and-co-kg/payment-gateway-lib-crypto/kms"
	"github.com/root-sector-ltd-and-co-kg/payment-gateway-lib-crypto/types"
)

// Define custom type for context keys
type contextKey string

const (
	// Event type
	eventType = "dek"

	// Operations
	operationCreate  = "create"
	operationRotate  = "rotate"
	operationUnwrap  = "unwrap"
	operationWrap    = "wrap"
	operationVerify  = "verify"
	operationStatus  = "status"
	operationRestore = "restore"

	// Status values
	statusSuccess = "success"
	statusFailed  = "failed"

	// Context keys
	contextKeyVersion            = "version"
	contextKeyError              = "error"
	contextKeyScope   contextKey = "scope"
	contextKeyOrgID   contextKey = "org_id"

	// Scope values - standardized constants
	scopeSystem = "system"
	scopeOrg    = "organization"

	// Cache key prefixes
	cacheKeyPrefixDEKInfo = "dek_info"
	cacheKeyPrefixDEK     = "dek"
)

// KMSServiceGetter defines the interface for retrieving a KMS provider.
// This allows dekService to fetch the *current* provider dynamically.
type KMSServiceGetter interface {
	GetKMSProvider(ctx context.Context, scope string, orgID string) (kms.Provider, error)
}

// dekService implements the Service interface for DEK management
type dekService struct {
	kmsGetter     KMSServiceGetter        // Added KMS getter interface
	configGetter  interfaces.ConfigGetter // Added Config getter interface
	logger        interfaces.AuditLogger  // For structured audit events
	zLogger       zerolog.Logger          // Added for operational logging
	cache         types.Cache             // Changed from cacheStore: Now holds the actual cache instance
	store         interfaces.DEKStore
	encryptionKey []byte
	mu            sync.RWMutex
	status        *types.DEKStatus
	initialized   bool
}

// NewService creates a new DEK service instance.
// It no longer handles singleton logic; use InitializeGlobalService for that.
// NewService creates a new, independent DEK service instance.
// It requires all dependencies to be passed in.
// Accepts an optional, pre-configured dekCache instance.
func NewService(kmsGetter KMSServiceGetter, configGetter interfaces.ConfigGetter, auditLogger interfaces.AuditLogger, store interfaces.DEKStore, dekCache types.Cache, encryptionKey []byte, opLogger zerolog.Logger) (interfaces.DEKService, error) {
	// Validate required dependencies
	// config parameter removed
	if kmsGetter == nil {
		return nil, fmt.Errorf("kmsGetter is required for NewService")
	}
	if configGetter == nil {
		return nil, fmt.Errorf("configGetter is required for NewService")
	}
	if store == nil {
		return nil, fmt.Errorf("store (DEKStore) is required for NewService")
	}

	if opLogger.GetLevel() == zerolog.Disabled {
		opLogger = log.Logger // Use global logger if none provided
	}

	// Create service instance
	svc := &dekService{
		kmsGetter:     kmsGetter,
		configGetter:  configGetter,
		logger:        auditLogger,
		zLogger:       opLogger,
		store:         store,
		cache:         dekCache,
		encryptionKey: encryptionKey,
		status: &types.DEKStatus{
			Exists:      false,
			Active:      false,
			Version:     0,
			CreatedAt:   time.Time{},
			UpdatedAt:   time.Time{},
			NeedsRotate: false,
		},
	}

	return svc, nil
}

// loadDEKInfo loads DEK info from store with caching
func (s *dekService) loadDEKInfo(ctx context.Context) (*types.DEKInfo, error) {
	// Determine scope and orgID from context
	scope, orgID := s.getScopeFromContext(ctx)
	cacheKey, err := s.getCacheKey(scope, orgID)
	if err != nil {
		s.zLogger.Warn().Err(err).Msg("Failed to generate cache key for DEK info")
		// Fallback to fetching directly from store without caching
		return s.store.GetActiveDEK(ctx, scope, orgID)
	}

	// Try to get from cache first if enabled and initialized
	if s.cache != nil && s.cache.IsEnabled() {
		if cached, _, found := s.cache.Get(ctx, cacheKey); found && cached != nil {
			var info types.DEKInfo
			if err := json.Unmarshal(cached.Get(), &info); err == nil {
				s.zLogger.Trace().Msg("Using cached DEK info")
				return &info, nil
			} else {
				// If unmarshal fails, log and continue to fetch from store
				s.zLogger.Warn().Err(err).Msg("Failed to unmarshal cached DEK info")
			}
		}
	}

	// Load from store
	info, err := s.store.GetActiveDEK(ctx, scope, orgID)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			return nil, fmt.Errorf("not found")
		}
		return nil, fmt.Errorf("failed to get DEK info from store: %w", err)
	}

	// Handle nil info case
	if info == nil {
		return nil, fmt.Errorf("not found")
	}

	// Cache the result if cache is enabled
	if s.cache != nil && s.cache.IsEnabled() {
		// Marshal DEK info for caching
		dekBytes, marshalErr := json.Marshal(info)
		if marshalErr == nil {
			// Use a background context for caching to avoid deadlocks
			cacheCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()

			s.cache.Set(cacheCtx, cacheKey, dekBytes, 1) // Assuming version 1 for now, might need adjustment
			s.zLogger.Trace().Msg("Cached DEK info")
		} else {
			s.zLogger.Warn().Err(marshalErr).Msg("Failed to marshal DEK info for caching")
		}
	}

	return info, nil
}

// Initialize initializes the DEK service
func (s *dekService) Initialize(ctx context.Context) error {
	// Check initialization status first with a read lock to avoid unnecessary write lock contention
	s.mu.RLock()
	initialized := s.initialized
	s.mu.RUnlock()
	if initialized {
		return nil
	}

	// Acquire write lock only when potentially modifying state
	s.mu.Lock()
	// Double-check initialization status after acquiring write lock
	if s.initialized {
		s.mu.Unlock() // Release lock if already initialized by another goroutine
		return nil
	}
	// Keep lock initially, release before potentially blocking calls

	s.zLogger.Info().Msg("Starting DEK service initialization")

	// Cache instance is now expected to be passed during NewService.
	// We just log its status here.
	logCacheStatus := s.zLogger.Info()
	if s.cache != nil && s.cache.IsEnabled() {
		logCacheStatus.Bool("cacheProvidedAndEnabled", true)
	} else if s.cache != nil {
		logCacheStatus.Bool("cacheProvidedButDisabled", true)
	} else {
		logCacheStatus.Bool("cacheNotProvided", true)
	}
	logCacheStatus.Msg("DEKService.Initialize: Cache status")

	s.mu.Unlock() // Release lock before potentially slow I/O in loadDEKInfo

	// Load DEK info without pre-caching first
	// Use a background context as this is initialization
	initCtx := context.Background()     // Use background for initial setup attempt
	info, err := s.loadDEKInfo(initCtx) // This function handles its own caching logic
	if err != nil {
		if strings.Contains(err.Error(), "not found") {
			s.zLogger.Info().Msg("No DEK found during initialization")
			// Mark as initialized even if no DEK found
			s.mu.Lock()
			s.initialized = true
			s.mu.Unlock()
			return nil // Okay if no DEK exists yet
		}
		// For other errors, log but continue - might be temporary
		s.zLogger.Warn().Err(err).Msg("Error loading DEK info during initialization")

		// If loadDEKInfo failed with an error other than "not found", return the error
		// Re-acquire lock before returning or modifying state
		s.mu.Lock()
		s.initialized = true // Mark as initialized even on error to prevent re-entry
		s.mu.Unlock()
		return fmt.Errorf("error loading DEK info during initialization: %w", err)
	}

	// If we found a DEK, verify it can be unwrapped (outside the main lock)
	var verificationError error
	var verificationDEK []byte // Variable to store the successfully unwrapped DEK
	if info != nil && len(info.Versions) > 0 {
		latestVersion := info.Versions[len(info.Versions)-1]
		// Use a background context for the unwrap check during initialization
		unwrapCtx := context.Background()                                         // Use a background context for initialization tasks
		dek, unwrapErr := s.UnwrapDEK(unwrapCtx, &latestVersion, scopeSystem, "") // UnwrapDEK handles its own locking
		if unwrapErr != nil || len(dek) == 0 {
			verificationError = fmt.Errorf("failed to verify DEK unwrapping during initialization: %w", unwrapErr)
			s.zLogger.Error().
				Err(verificationError).
				Msg("Found DEK but unable to unwrap it during initialization")
			// Do not return yet, update status below first
		} else {
			verificationDEK = dek // Store the successfully unwrapped DEK
			s.zLogger.Info().Msg("Successfully verified DEK unwrapping during initialization")
		}
	}

	// Re-acquire lock to update final state
	s.mu.Lock()
	defer s.mu.Unlock() // Ensure lock is released even if pre-caching goroutine panics

	// Check again if initialized by another goroutine while we were unlocked
	if s.initialized {
		return nil
	}

	// Update status
	s.status.Exists = info != nil
	s.status.Active = info != nil && info.Active
	if info != nil {
		s.status.Version = info.Version
		s.status.CreatedAt = info.CreatedAt
		s.status.UpdatedAt = info.UpdatedAt
		// Keep provider from config
	} else {
		s.status.Version = 0
		s.status.CreatedAt = time.Time{}
		s.status.UpdatedAt = time.Time{}
	}

	// Mark as initialized *after* successfully updating state
	s.initialized = true

	// Return verification error *after* marking as initialized
	if verificationError != nil {
		return verificationError
	}

	// Pre-cache in background only if verification succeeded and cache is enabled
	if verificationError == nil && info != nil && len(verificationDEK) > 0 && s.cache != nil && s.cache.IsEnabled() {
		// Pass necessary info to the goroutine to avoid data races on s.info
		dekToCache := verificationDEK
		infoVersion := info.Version

		go func(dek []byte, version int, scope string, orgID string) { // Removed id parameter
			cacheCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()

			// Use the already unwrapped DEK from the verification step
			// Pass background context as scope isn't strictly necessary here (assuming system for init)
			cacheKey, keyErr := s.getUnwrappedCacheKey(cacheCtx, version, scope, orgID) // Pass only ctx, version, and explicit scope/orgID
			if keyErr == nil {
				// Use the Set method from types.Cache interface
				// Set does not return an error, so just call it.
				s.cache.Set(cacheCtx, cacheKey, dek, version)
				s.zLogger.Trace().Str("cacheKey", cacheKey).Msg("Pre-cached DEK successfully")
			} else {
				s.zLogger.Warn().Err(keyErr).Msg("Failed to generate cache key for pre-caching")
			}
		}(dekToCache, infoVersion, scopeSystem, "") // Pass only copies/values needed to the goroutine
	}

	s.zLogger.Info().
		Bool("hasKmsGetter", s.kmsGetter != nil).
		Bool("initialized", s.initialized).
		Msg("DEK service initialization completed")

	return nil
}

// GetAuditLogger implements Service
func (s *dekService) GetAuditLogger() interface{} {
	return s.logger
}

// GetDEKService implements Service
func (s *dekService) GetDEKService() interface{} {
	return s
}

// GetTaskProcessor implements Service
func (s *dekService) GetTaskProcessor() interface{} {
	return nil
}

// GetStats implements Service
func (s *dekService) GetStats(ctx context.Context) (interface{}, error) {
	stats, err := s.GetDEKStats(ctx, "system", "")
	if err != nil {
		return nil, err
	}
	return stats, nil
}

// generateDEK generates a new random DEK
func (s *dekService) generateDEK() ([]byte, error) {
	const keySize = 32 // 256-bit key
	key := make([]byte, keySize)

	n, err := rand.Read(key)
	if err != nil {
		return nil, fmt.Errorf("failed to generate random key: %w", err)
	}

	if n != keySize {
		return nil, fmt.Errorf("failed to generate complete key: got %d bytes, want %d", n, keySize)
	}

	// Verify key is not all zeros (extremely unlikely but critical check)
	isZero := true
	for _, b := range key {
		if b != 0 {
			isZero = false
			break
		}
	}
	if isZero {
		return nil, fmt.Errorf("generated key is all zeros")
	}

	return key, nil
}

// getScopeFromContext extracts scope and orgID from context with improved validation
func (s *dekService) getScopeFromContext(ctx context.Context) (scope string, orgID string) {
	// Try to get scope from context using the audit package key type
	if scopeVal := ctx.Value(audit.KeyScope); scopeVal != nil {
		if scopeStr, ok := scopeVal.(string); ok {
			scope = scopeStr
		}
	}

	// Try to get orgID from context using the audit package key type
	if orgIDVal := ctx.Value(audit.KeyOrgID); orgIDVal != nil {
		if orgIDStr, ok := orgIDVal.(string); ok {
			orgID = orgIDStr
		}
	}

	// Validate and normalize scope
	switch scope {
	case scopeSystem:
		if orgID != "" {
			s.zLogger.Warn().
				Str("scope", scope).
				Str("orgID", orgID).
				Msg("System scope should not have an orgID, ignoring orgID")
			orgID = ""
		}
	case scopeOrg:
		if orgID == "" {
			s.zLogger.Warn().
				Str("scope", scope).
				Msg("Organization scope set but no orgID provided")
		}
	default:
		if scope != "" {
			s.zLogger.Warn().
				Str("invalidScope", scope).
				Msg("Invalid scope provided, defaulting to system scope")
		}
		scope = scopeSystem
		orgID = ""
	}

	s.zLogger.Trace().
		Str("scope", scope).
		Str("orgID", orgID).
		Msg("Extracted scope and orgID from context")

	return scope, orgID
}

// getWrapContext builds the wrap context based on scope and orgID
func (s *dekService) getWrapContext(scope, orgID string) []byte {
	if scope == scopeSystem {
		return []byte(scopeSystem)
	} else if scope == scopeOrg || scope == "organization" {
		if orgID != "" {
			// Always use the constant scopeOrg for consistency
			return []byte(fmt.Sprintf("%s:%s", scopeOrg, orgID))
		}
	}
	return []byte(scopeSystem)
}

// wrapDEK wraps a DEK using the configured KMS provider
func (s *dekService) wrapDEK(ctx context.Context, key []byte, scope string, orgID string) (*types.DEKVersion, error) {
	// Fetch the current provider dynamically
	provider, err := s.kmsGetter.GetKMSProvider(ctx, scope, orgID)
	if err != nil {
		log.Error().Err(err).Str("scope", scope).Str("orgID", orgID).Msg("Failed to get KMS provider for wrapping")
		return nil, fmt.Errorf("failed to get KMS provider for scope '%s': %w", scope, err)
	}
	if provider == nil {
		log.Error().Str("scope", scope).Str("orgID", orgID).Msg("Attempted to wrap DEK but KMS provider is nil (dynamically fetched)")
		return nil, fmt.Errorf("cannot wrap DEK: KMS provider is not configured for scope '%s'", scope)
	}

	if key == nil {
		return nil, fmt.Errorf("key is required")
	}

	// Get wrapper from the dynamically fetched provider
	wrapper := provider.GetWrapper()
	if wrapper == nil {
		return nil, fmt.Errorf("KMS wrapper not available from provider")
	}

	// Create wrap context with timeout
	wrapCtx, wrapCancel := context.WithTimeout(ctx, 5*time.Second)
	defer wrapCancel()

	// If scope is empty, get from context
	if scope == "" {
		scope, _ = s.getScopeFromContext(ctx)
	}

	// Build wrap context using orgID if provided
	wrapContext := s.getWrapContext(scope, orgID)

	s.zLogger.Trace().
		Str("scope", scope).
		Hex("wrapContext", wrapContext).
		Msg("Using wrap context for encryption")

	// Set up wrap options
	var opts []wrapping.Option
	if len(wrapContext) > 0 {
		opts = append(opts, wrapping.WithAad(wrapContext))
	}

	// Encrypt key using KMS
	blobInfo, err := wrapper.Encrypt(wrapCtx, key, opts...)
	if err != nil {
		return nil, fmt.Errorf("failed to wrap key: %w", err)
	}

	if blobInfo == nil {
		return nil, fmt.Errorf("wrapped key info is nil")
	}

	s.zLogger.Trace().
		Bool("hasIv", len(blobInfo.Iv) > 0).
		Bool("hasCiphertext", len(blobInfo.Ciphertext) > 0).
		Msg("Received blob info from KMS")

	// Create version with wrapped data
	version := &types.DEKVersion{
		Version:     1,
		BlobInfo:    blobInfo,
		CreatedAt:   time.Now().UTC(),
		WrapContext: wrapContext,
	}

	// Verify unwrap
	verifyCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	var verifyOpts []wrapping.Option
	if len(wrapContext) > 0 {
		verifyOpts = append(verifyOpts, wrapping.WithAad(wrapContext))
	}

	unwrapped, err := wrapper.Decrypt(verifyCtx, version.BlobInfo, verifyOpts...)
	if err != nil {
		return nil, fmt.Errorf("failed to verify wrapped key: %w", err)
	}

	if !bytes.Equal(unwrapped, key) {
		return nil, fmt.Errorf("unwrapped key does not match original")
	}

	s.zLogger.Trace().
		Msg("Successfully created and verified DEK version")

	version.WrapContext = wrapContext
	return version, nil
}

// CreateDEK creates a new DEK and wraps it with KMS
func (s *dekService) CreateDEK(ctx context.Context, scope string, orgID string) (*types.DEKInfo, error) {
	// Removed incorrect check against internal s.info state.
	// The check below against the persistent store is the correct way to verify existence.

	// Now check the persistent store definitively WITHOUT holding the main service lock
	s.zLogger.Trace().Str("scope", scope).Str("orgID", orgID).Msg("Checking store for existing active DEK before creation")
	existingInfo, err := s.store.GetActiveDEK(ctx, scope, orgID)
	if err != nil && !strings.Contains(err.Error(), "not found") { // Check specifically for "not found" variant
		s.zLogger.Error().Err(err).Str("scope", scope).Str("orgID", orgID).Msg("Error checking store for existing DEK")
		// Don't return internal store errors directly, wrap them
		return nil, fmt.Errorf("failed to verify existing DEK status: %w", err)
	} else if existingInfo != nil {
		s.zLogger.Warn().Str("scope", scope).Str("orgID", orgID).Str("existingDEKId", existingInfo.Id).Msg("DEK already exists in store")
		return nil, fmt.Errorf("DEK already exists in store for scope %s/%s", scope, orgID)
	}
	s.zLogger.Trace().Str("scope", scope).Str("orgID", orgID).Msg("No existing active DEK found in store, proceeding with creation")

	// Check if KMS provider is configured before proceeding to wrap
	provider, err := s.kmsGetter.GetKMSProvider(ctx, scope, orgID)
	if err != nil {
		log.Error().Err(err).Str("scope", scope).Str("orgID", orgID).Msg("Failed to get KMS provider before DEK creation")
		if s.logger != nil {
			s.logAuditEvent(ctx, eventType, operationCreate, statusFailed, 0, fmt.Errorf("kms_provider_fetch_failed: %w", err))
		}
		return nil, fmt.Errorf("failed to get KMS provider for scope '%s': %w", scope, err)
	}
	if provider == nil {
		log.Error().Str("scope", scope).Str("orgID", orgID).Msg("KMS provider is nil (dynamically fetched), cannot create/wrap DEK")
		if s.logger != nil {
			s.logAuditEvent(ctx, eventType, operationCreate, statusFailed, 0, fmt.Errorf("kms_provider_not_configured"))
		}
		return nil, fmt.Errorf("KMS provider is not configured for scope '%s'", scope)
	}

	// Generate new DEK (no lock needed)
	newDEK, err := s.generateDEK()
	if err != nil {
		return nil, fmt.Errorf("failed to generate DEK: %w", err)
	}

	// Wrap (encrypt) the DEK using KMS
	// Pass the dynamically fetched provider to wrapDEK or let wrapDEK fetch it again?
	// Let wrapDEK fetch it again for consistency.
	wrappedVersion, err := s.wrapDEK(ctx, newDEK, scope, orgID)

	if err != nil {
		// Log failure if wrapDEK failed
		s.logAuditEvent(ctx, "dek", "create", "failure", 0, fmt.Errorf("failed to wrap DEK: %w", err))
		return nil, fmt.Errorf("failed to wrap DEK: %w", err)
	}

	// --- Release lock AFTER wrapping ---

	// Create DEK info with wrapped version (no lock needed here)
	dekInfo := &types.DEKInfo{
		Id:        uuid.New().String(),
		Version:   1,
		Active:    true,
		Versions:  []types.DEKVersion{*wrappedVersion},
		CreatedAt: time.Now().UTC(),
		UpdatedAt: time.Now().UTC(),
	}

	// Store DEK info (no lock needed for store operation itself)
	if err := s.store.StoreDEK(ctx, dekInfo, scope, orgID); err != nil {
		// Log failure before returning
		s.logAuditEvent(ctx, "dek", "create", "failure", 0, fmt.Errorf("failed to store DEK: %w", err))
		return nil, fmt.Errorf("failed to store DEK: %w", err)
	}

	// --- Critical section: Update internal state ---
	s.mu.Lock() // Acquire write lock *only* for updating internal state
	// s.info = dekInfo // Removed assignment to s.info
	// Determine provider type from config for status display
	providerType := ""
	// Fetch config to get provider type - use the context passed to CreateDEK
	config, _ := s.configGetter.GetEncryptionConfig(ctx, scope, orgID) // Ignore error for status update
	if config != nil {
		providerType = string(config.Provider)
	}
	s.status = &types.DEKStatus{
		Exists:      true,
		Active:      true,
		Version:     dekInfo.Version,
		CreatedAt:   dekInfo.CreatedAt,
		UpdatedAt:   dekInfo.UpdatedAt,
		Provider:    types.ProviderType(providerType), // Use config for initial status
		NeedsRotate: false,
	}
	s.mu.Unlock() // Release lock after updating internal state
	// --- End Critical section ---

	// Log success
	s.logAuditEvent(ctx, "dek", "create", "success", dekInfo.Version, nil)

	return dekInfo, nil
}

// DeleteDEK deletes the current DEK
func (s *dekService) DeleteDEK(ctx context.Context, scope string, orgID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Clear from cache if enabled
	if s.cache != nil {
		cacheKey, err := s.getCacheKey(scope, orgID)
		if err == nil {
			s.cache.Delete(cacheKey)
		} else {
			s.zLogger.Warn().Err(err).Msg("Failed to generate cache key for deletion")
		}
	}

	// Delete from store
	if err := s.store.DeleteDEK(ctx, orgID, scope); err != nil {
		s.logAuditEvent(ctx, eventType, operationRestore, statusFailed, 0, err)
		return fmt.Errorf("failed to delete DEK: %w", err)
	}

	// Log success
	s.logAuditEvent(ctx, eventType, operationRestore, statusSuccess, 0, nil)
	return nil
}

// GetDEK retrieves a DEK by ID
func (s *dekService) GetDEK(ctx context.Context, id string) ([]byte, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	// Try cache first if enabled
	if s.cache != nil && s.cache.IsEnabled() {
		if dek, _, found := s.cache.Get(ctx, id); found {
			return dek.Get(), nil
		}
	}

	// Get DEK info from store - use system scope as default
	info, err := s.store.GetDEK(ctx, id, "system")
	if err != nil {
		return nil, fmt.Errorf("failed to get DEK: %w", err)
	}

	// Get latest version
	latestVersion := info.Versions[len(info.Versions)-1]

	// Unwrap the key
	dek, err := s.UnwrapDEK(ctx, &latestVersion, scopeSystem, "")
	if err != nil {
		return nil, fmt.Errorf("failed to unwrap key: %w", err)
	}

	// Cache the unwrapped key
	if s.cache != nil && s.cache.IsEnabled() {
		s.cache.Set(ctx, id, dek, latestVersion.Version)
	}

	return dek, nil
}

func (s *dekService) GetDEKVersion(ctx context.Context, id string) (int, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	// Try cache first if enabled
	if s.cache != nil && s.cache.IsEnabled() {
		if _, version, found := s.cache.Get(ctx, id); found {
			return version, nil
		}
	}

	return 1, nil // Default version for new DEKs
}

func (s *dekService) GetDEKInfo(ctx context.Context, id string) (*types.DEKInfo, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	version, err := s.GetDEKVersion(ctx, id)
	if err != nil {
		return nil, err
	}

	return &types.DEKInfo{
		Id:        id, // Use Id
		Version:   version,
		Active:    true,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}, nil
}

func (s *dekService) GetDEKStats(ctx context.Context, scope string, id string) (*types.DEKStats, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	stats := types.DEKStats{
		LastOperation: time.Now(),
	}

	if s.cache != nil {
		cacheStats := s.cache.GetStats(ctx)
		stats.TotalDEKs = cacheStats.Size
		stats.ActiveDEKs = cacheStats.Size
	}

	return &stats, nil
}

// logAuditEvent logs an audit event with the given parameters
func (s *dekService) logAuditEvent(ctx context.Context, eventType, operation, status string, version int, err error) {
	// Create context map with string keys
	contextMap := map[string]string{
		string(contextKeyVersion): fmt.Sprintf("%d", version),
		string(contextKeyScope):   scopeSystem,
	}

	// Add error to context if present
	if err != nil {
		contextMap[string(contextKeyError)] = err.Error()
	}

	// Create audit event
	event := &types.AuditEvent{
		ID:         uuid.New().String(),
		Timestamp:  time.Now(),
		EventType:  eventType,
		Operation:  operation,
		Status:     status,
		DEKVersion: version,
		Context:    contextMap,
	}

	// Log event, print to stdout if logger fails
	if s.logger != nil {
		if logErr := s.logger.LogEvent(ctx, event); logErr != nil {
			fmt.Printf("Failed to log audit event: %v\n", logErr)
		}
	} else {
		fmt.Printf("Audit logger not initialized. Event: %+v\n", event)
	}
}

// getCacheKey returns a properly formatted cache key based on scope and orgID
func (s *dekService) getCacheKey(scope, orgID string) (string, error) {
	if scope == scopeSystem {
		return fmt.Sprintf("%s:%s", cacheKeyPrefixDEKInfo, scopeSystem), nil
	}

	// If scope is org and orgID is not empty, use org:orgID format
	if scope == scopeOrg && orgID != "" {
		return fmt.Sprintf("%s:%s:%s", cacheKeyPrefixDEKInfo, scopeOrg, orgID), nil
	}

	// Return error for invalid scope
	return "", fmt.Errorf("invalid scope or missing organization ID: scope=%s, orgID=%s", scope, orgID)
}

// getUnwrappedCacheKey generates a cache key for unwrapped DEKs
// It no longer uses dekId to avoid inconsistencies between callers.
// The key is now based solely on scope, orgID (if applicable), and version.
func (s *dekService) getUnwrappedCacheKey(ctx context.Context, version int, scope string, orgID string) (string, error) {
	// If scope/orgID are not passed, try to get from context as a fallback (should be rare)
	if scope == "" {
		scope, orgID = s.getScopeFromContext(ctx) // Fallback, but prefer explicit params
		s.zLogger.Warn().Msg("getUnwrappedCacheKey called without explicit scope, falling back to context-derived scope.")
	}

	if scope == scopeSystem {
		// Format: dek:system:v<version>
		return fmt.Sprintf("%s:%s:v%d", cacheKeyPrefixDEK, scopeSystem, version), nil
	}

	// Only use org scope if both scope is org and orgID is provided
	if scope == scopeOrg && orgID != "" {
		// Format: dek:organization:<orgID>:v<version>
		return fmt.Sprintf("%s:%s:%s:v%d", cacheKeyPrefixDEK, scopeOrg, orgID, version), nil
	}

	// Return error for invalid scope or missing orgID
	return "", fmt.Errorf("invalid scope or missing organization ID for unwrapped cache key: scope=%s, orgID=%s", scope, orgID)
}

// UnwrapDEK unwraps a DEK version using the configured KMS provider
func (s *dekService) UnwrapDEK(ctx context.Context, version *types.DEKVersion, scope string, orgID string) ([]byte, error) {
	cacheStatusLog := s.zLogger.Trace()
	cacheIsNil := s.cache == nil
	cacheIsEnabled := false
	if !cacheIsNil {
		cacheIsEnabled = s.cache.IsEnabled()
	}
	cacheStatusLog.Bool("sCacheIsNil", cacheIsNil).
		Bool("sCacheIsEnabled", cacheIsEnabled).
		Msg("UnwrapDEK: Cache status at entry")

	if version == nil {
		return nil, fmt.Errorf("version is required")
	}
	if version.BlobInfo == nil {
		return nil, fmt.Errorf("version.BlobInfo is required")
	}

	// Determine scope/orgID early for dynamic lookups
	// Use passed-in scope and orgID directly for logging and consistency check with cache context derivation
	s.zLogger.Trace().
		Int("version", int(version.Version)).
		Str("keyId", version.BlobInfo.KeyInfo.KeyId).
		Bool("hasWrappedKey", version.BlobInfo.KeyInfo != nil && len(version.BlobInfo.KeyInfo.WrappedKey) > 0).
		Bool("hasCiphertext", len(version.BlobInfo.Ciphertext) > 0).
		Bool("hasIv", len(version.BlobInfo.Iv) > 0).
		Bool("hasHmac", len(version.BlobInfo.Hmac) > 0).
		Msg("Starting DEK unwrap")

	// Try cache first if enabled
	if s.cache != nil && s.cache.IsEnabled() {
		cacheKey, err := s.getUnwrappedCacheKey(ctx, version.Version, scope, orgID)
		if err == nil {
			s.zLogger.Trace().
				Str("cacheKeyAttempt", cacheKey).
				Str("scope", scope).
				Str("orgID", orgID).
				Int("version", version.Version).
				Msg("UnwrapDEK: Attempting to GET unwrapped DEK from cache")
			if dek, _, found := s.cache.Get(ctx, cacheKey); found && dek != nil && len(dek.Get()) > 0 {
				s.zLogger.Trace().
					Str("cacheKey", cacheKey).
					Int("version", version.Version).
					Int("dekLength", len(dek.Get())).
					Msg("Using cached unwrapped DEK")
				return dek.Get(), nil
			}
			s.zLogger.Trace().
				Str("cacheKey", cacheKey).
				Int("version", version.Version).
				Msg("Cache miss for unwrapped DEK")
		} else {
			s.zLogger.Warn().Err(err).Msg("Failed to generate unwrapped cache key in UnwrapDEK")
		}
	}

	// Get provider dynamically (scope/orgID already determined by parameters)
	provider, err := s.kmsGetter.GetKMSProvider(ctx, scope, orgID)
	if err != nil {
		s.zLogger.Error().Err(err).Str("scope", scope).Str("orgID", orgID).Msg("Failed to get KMS provider for unwrapping")
		return nil, fmt.Errorf("failed to get KMS provider for scope '%s': %w", scope, err)
	}
	if provider == nil {
		s.zLogger.Error().Str("scope", scope).Str("orgID", orgID).Msg("KMS provider is nil (dynamically fetched), cannot unwrap DEK")
		return nil, fmt.Errorf("KMS provider not configured for scope '%s'", scope)
	}

	// Get wrapper from the dynamically fetched provider
	wrapper := provider.GetWrapper()
	if wrapper == nil {
		s.zLogger.Error().Msg("KMS wrapper not available from provider")
		return nil, fmt.Errorf("KMS wrapper not available")
	}

	// Set up wrap context
	var opts []wrapping.Option
	var finalAAD []byte

	// AAD MUST come from the stored WrapContext in the version.
	// If it's missing, decryption cannot proceed safely.
	if len(version.WrapContext) == 0 {
		err := fmt.Errorf("missing wrap context in DEK version %d, cannot determine AAD for decryption", version.Version)
		s.zLogger.Error().Err(err).Msg("UnwrapDEK failed")
		return nil, err
	}

	finalAAD = version.WrapContext
	s.zLogger.Trace().
		Hex("version.WrapContext", version.WrapContext).
		Hex("finalAAD", finalAAD).
		Msg("AAD Source: Using wrap context stored in version")
	opts = append(opts, wrapping.WithAad(finalAAD))

	// Decrypt using KMS with the stored blob info
	logEntry := s.zLogger.Trace()
	if version.BlobInfo.KeyInfo != nil {
		logEntry = logEntry.Str("keyId", version.BlobInfo.KeyInfo.KeyId)
	} else {
		logEntry = logEntry.Str("keyId", "<nil KeyInfo>")
	}
	logEntry.
		Hex("finalAADPassedToKMS", finalAAD).
		Bool("hasWrappedKey", len(version.BlobInfo.KeyInfo.WrappedKey) > 0).
		Bool("hasCiphertext", len(version.BlobInfo.Ciphertext) > 0).
		Bool("hasIv", len(version.BlobInfo.Iv) > 0).
		Bool("hasHmac", len(version.BlobInfo.Hmac) > 0).
		Uint64("mechanism", version.BlobInfo.KeyInfo.Mechanism).
		Hex("iv", version.BlobInfo.Iv).
		Hex("ciphertext", version.BlobInfo.Ciphertext).
		Msg("Attempting to unwrap DEK with KMS")

	dek, err := wrapper.Decrypt(ctx, version.BlobInfo, opts...)
	if err != nil {
		logEntry := s.zLogger.Error().Err(err)
		if version.BlobInfo.KeyInfo != nil {
			logEntry = logEntry.Str("keyId", version.BlobInfo.KeyInfo.KeyId)
		} else {
			logEntry = logEntry.Str("keyId", "<nil KeyInfo>")
		}
		logEntry.
			Hex("aadUsed", finalAAD).
			Hex("iv", version.BlobInfo.Iv).
			Hex("ciphertext", version.BlobInfo.Ciphertext).
			Msg("Failed to unwrap DEK with KMS")
		return nil, fmt.Errorf("failed to unwrap key: %w", err)
	}

	if len(dek) == 0 {
		s.zLogger.Error().Msg("Unwrapped DEK is empty")
		return nil, fmt.Errorf("unwrapped key is empty")
	}

	s.zLogger.Trace().
		Int("dekLength", len(dek)).
		Msg("Successfully unwrapped DEK")

	// Cache the unwrapped DEK if enabled
	if s.cache != nil && s.cache.IsEnabled() {
		cacheKey, keyErr := s.getUnwrappedCacheKey(ctx, version.Version, scope, orgID)
		if keyErr == nil {
			s.zLogger.Trace().
				Str("cacheKey", cacheKey).
				Int("version", version.Version).
				Int("dekLength", len(dek)).
				Msg("UnwrapDEK: Attempting to SET unwrapped DEK in cache")

			// Call Set - Note: The Cache interface's Set method doesn't return an error.
			s.cache.Set(ctx, cacheKey, dek, version.Version)
			s.zLogger.Trace().Str("cacheKey", cacheKey).Int("version", version.Version).Msg("Cached unwrapped DEK")
		} else {
			s.zLogger.Warn().Err(keyErr).Msg("Failed to generate cache key for caching DEK in UnwrapDEK")
		}
	}

	return dek, nil
}

// RotateDEK rotates the current DEK
func (s *dekService) RotateDEK(ctx context.Context, scope string, orgID string, force bool) (*types.DEKInfo, error) {
	// Get current DEK info from store (no lock needed for store access)
	currentInfo, err := s.store.GetActiveDEK(ctx, scope, orgID)
	if err != nil {
		return nil, fmt.Errorf("failed to get current DEK for rotation: %w", err)
	}

	if currentInfo == nil {
		return nil, fmt.Errorf("no active DEK found for rotation")
	}

	// Log current info for debugging
	s.zLogger.Trace().
		Str("dekID", currentInfo.Id).
		Int("currentVersion", currentInfo.Version).
		Int("numVersions", len(currentInfo.Versions)).
		Bool("forceFullReencryption", force).
		Msg("Current DEK info before rotation")

	if len(currentInfo.Versions) == 0 {
		return nil, fmt.Errorf("current DEK has no versions")
	}

	// Get current version of DEK
	currentVersion := currentInfo.Version

	var newVersion *types.DEKVersion
	var plaintextDEK []byte
	var isSameKey bool

	// Check if this is a full re-encryption (force=true) or envelope encryption (force=false)
	if force {
		// FULL RE-ENCRYPTION: Generate a completely new DEK key
		s.zLogger.Info().Msg("Performing FULL RE-ENCRYPTION with new DEK key")

		// Generate new DEK key
		plaintextDEK, err = s.generateDEK()
		if err != nil {
			return nil, fmt.Errorf("failed to generate new DEK key for full re-encryption: %w", err)
		}

		// Wrap the new DEK (wrapDEK will fetch provider)
		newVersion, err = s.wrapDEK(ctx, plaintextDEK, scope, orgID)
		if err != nil {
			return nil, fmt.Errorf("failed to wrap new DEK for full re-encryption: %w", err)
		}

		isSameKey = false
	} else {
		// ENVELOPE ENCRYPTION: Just re-wrap the same plaintext DEK
		s.zLogger.Info().Msg("Performing ENVELOPE ENCRYPTION (re-wrapping same DEK key)")

		// First, find the current version in the versions array
		var currentVersionData *types.DEKVersion
		for i, v := range currentInfo.Versions {
			if v.Version == currentVersion {
				currentVersionData = &currentInfo.Versions[i]
				break
			}
		}

		if currentVersionData == nil {
			return nil, fmt.Errorf("could not find current DEK version in versions array")
		}

		// Get plaintext DEK by unwrapping the current version (UnwrapDEK will fetch provider)
		// Create a new context with the correct scope and orgID for UnwrapDEK
		unwrapCtx := context.WithValue(ctx, audit.KeyScope, scope)
		if orgID != "" {
			unwrapCtx = context.WithValue(unwrapCtx, audit.KeyOrgID, orgID)
		}
		plaintextDEK, err = s.UnwrapDEK(unwrapCtx, currentVersionData, scope, orgID) // Pass the enriched context
		if err != nil {
			return nil, fmt.Errorf("failed to unwrap current DEK version: %w", err)
		}

		// Add detailed logging for the original DEK
		s.zLogger.Trace().
			Int("currentVersion", currentVersion).
			Int("dekLength", len(plaintextDEK)).
			Hex("dekKeyHash", createKeyHash(plaintextDEK)). // Log a hash of the key for comparison
			Msg("Successfully unwrapped current DEK version")

		// DO NOT generate a new plaintext DEK, re-use the existing one
		// This is the key difference between envelope encryption and full re-encryption

		// Just re-wrap the EXACT SAME plaintext DEK with a new KMS key wrapping (wrapDEK fetches provider)
		newVersion, err = s.wrapDEK(ctx, plaintextDEK, scope, orgID)
		if err != nil {
			return nil, fmt.Errorf("failed to wrap DEK for new version: %w", err)
		}

		// Add detailed logging for the new wrapped DEK
		s.zLogger.Trace().
			Int("newVersion", currentVersion+1).
			Hex("dekKeyHash", createKeyHash(plaintextDEK)). // Should be the same hash
			Msg("Successfully re-wrapped same DEK key for new version")

		isSameKey = true
	}

	// Increment version number
	newVersion.Version = currentVersion + 1

	// Create updated DEK info (maintaining same ID)
	updatedInfo := &types.DEKInfo{
		Id:        currentInfo.Id,                            // Use Id, Keep same ID
		Version:   currentVersion + 1,                        // Increment version
		Active:    true,                                      // New version is active
		Versions:  append(currentInfo.Versions, *newVersion), // Add new version to existing versions
		CreatedAt: currentInfo.CreatedAt,                     // Keep creation time
		UpdatedAt: time.Now(),                                // Update time
	}

	// Log update for debugging
	s.zLogger.Trace().
		Str("dekID", updatedInfo.Id).
		Int("oldVersion", currentVersion).
		Int("newVersion", updatedInfo.Version).
		Int("numVersions", len(updatedInfo.Versions)).
		Bool("isSameKey", isSameKey).
		Bool("isFullReencryption", force).
		Msg("Updated DEK info for rotation")

	// Store the updated DEK
	if err := s.store.StoreDEK(ctx, updatedInfo, scope, orgID); err != nil {
		return nil, fmt.Errorf("failed to store updated DEK: %w", err)
	}

	// --- Critical section: Update internal state (only status, no s.info) ---
	s.mu.Lock() // Acquire write lock *only* for updating internal status
	providerType := ""
	// Fetch config dynamically to get provider type - use the context passed to RotateDEK
	config, configErr := s.configGetter.GetEncryptionConfig(ctx, scope, orgID)
	if configErr == nil && config != nil {
		providerType = string(config.Provider)
	} else {
		s.zLogger.Warn().Err(configErr).Str("scope", scope).Str("orgID", orgID).Msg("Failed to get config for status update during rotation, provider type may be empty")
	}
	// Update the existing status object if it's not nil, otherwise create a new one
	if s.status == nil {
		s.status = &types.DEKStatus{}
	}
	s.status.Exists = true
	s.status.Active = true
	s.status.Version = updatedInfo.Version
	s.status.CreatedAt = updatedInfo.CreatedAt
	s.status.UpdatedAt = updatedInfo.UpdatedAt
	s.status.Provider = types.ProviderType(providerType)
	s.status.NeedsRotate = false

	s.mu.Unlock() // Release lock after updating internal state
	// --- End Critical section ---

	// Clear cache — delete both the DEK info key and the previous version's
	// unwrapped DEK key so the stale plaintext key is not served after rotation.
	if s.cache != nil {
		infoCacheKey, err := s.getCacheKey(scope, orgID)
		if err == nil {
			s.cache.Delete(infoCacheKey)
			s.zLogger.Trace().Str("cacheKey", infoCacheKey).Msg("Cleared DEK info cache after rotation")
		} else {
			s.zLogger.Warn().Err(err).Msg("Failed to generate DEK info cache key for clearing after rotation")
		}

		// Also clear the previous active version's unwrapped DEK cache entry.
		oldUnwrappedKey, keyErr := s.getUnwrappedCacheKey(ctx, currentVersion, scope, orgID)
		if keyErr == nil {
			s.cache.Delete(oldUnwrappedKey)
			s.zLogger.Trace().Str("cacheKey", oldUnwrappedKey).Int("version", currentVersion).Msg("Cleared old unwrapped DEK cache after rotation")
		} else {
			s.zLogger.Warn().Err(keyErr).Int("version", currentVersion).Msg("Failed to generate old unwrapped DEK cache key for clearing after rotation")
		}
	}

	return updatedInfo, nil
}

// createKeyHash creates a hash of a key for logging purposes
// This only logs a hash of the key, not the key itself
func createKeyHash(key []byte) []byte {
	if len(key) == 0 {
		return []byte{}
	}

	// Create a simple hash for comparison in logs
	// This is not for security, just for debugging
	hash := make([]byte, 8)
	for i := 0; i < len(key) && i < 32; i++ {
		hash[i%8] ^= key[i]
	}
	return hash
}

// GetActiveDEK returns the current active DEK for field encryption
func (s *dekService) GetActiveDEK(ctx context.Context, scope string, orgID string) ([]byte, error) {
	// No internal lock needed here as we are fetching dynamically

	// Fetch current DEK info from store first
	currentInfo, err := s.store.GetActiveDEK(ctx, scope, orgID)
	if err != nil {
		return nil, fmt.Errorf("failed to get active DEK info: %w", err)
	}
	if currentInfo == nil || !currentInfo.Active || len(currentInfo.Versions) == 0 {
		return nil, fmt.Errorf("no active DEK found for scope %s/%s", scope, orgID)
	}
	currentVersionNumber := currentInfo.Version
	dekInfoId := currentInfo.Id

	// Try cache first if enabled
	if s.cache != nil && s.cache.IsEnabled() {
		// Use the current version number for the cache key
		cacheKey, keyErr := s.getUnwrappedCacheKey(ctx, currentVersionNumber, scope, orgID)
		if keyErr == nil {
			s.zLogger.Trace().
				Str("cacheKeyAttempt", cacheKey).
				Str("scope", scope).
				Str("orgID", orgID).
				Int("version", currentVersionNumber).
				Msg("GetActiveDEK: Attempting to GET unwrapped DEK from cache")
			if dek, cachedVersion, found := s.cache.Get(ctx, cacheKey); found && dek != nil && len(dek.Get()) > 0 {
				// Verify the cached version matches the current version from the store
				if cachedVersion == currentVersionNumber {
					s.zLogger.Trace().
						Str("scope", scope).
						Str("orgID", orgID).
						Int("version", cachedVersion).
						Str("cacheKey", cacheKey).
						Int("dekLength", len(dek.Get())).
						Msg("Using cached active DEK")
					return dek.Get(), nil
				}
				// Fix: Use currentVersionNumber fetched from store, not undefined currentInfo.Version
				s.zLogger.Trace().
					Str("scope", scope).
					Str("orgID", orgID).
					Int("cachedVersion", cachedVersion).
					Int("currentVersion", currentVersionNumber).
					Msg("Cached DEK version mismatch, will fetch fresh")
			}
		} else {
			s.zLogger.Warn().Err(keyErr).Msg("Failed to generate unwrapped cache key in GetActiveDEK") // Log specific location
		}
	}

	// If cache miss or version mismatch, unwrap the latest version from the fetched info
	s.zLogger.Trace().
		Str("scope", scope).
		Str("orgID", orgID).
		Str("dekId", dekInfoId). // Keep logging the actual DB DEK ID for info
		Int("version", currentVersionNumber).
		Msg("Cache miss or mismatch, unwrapping active DEK from store info")

	// Get latest version details from the info we already fetched
	latestVersion := currentInfo.Versions[len(currentInfo.Versions)-1]

	// Unwrap and cache the DEK (UnwrapDEK handles caching internally)
	return s.UnwrapDEK(ctx, &latestVersion, scope, orgID)
}

// GetDEKStatus gets the status of a DEK for a specific scope and organization
func (s *dekService) GetDEKStatus(ctx context.Context, scope string, orgID string) (*types.DEKStatus, error) {
	// No lock needed here as we fetch everything dynamically

	// Fetch config first to get provider type (even if DEK doesn't exist)
	config, configErr := s.configGetter.GetEncryptionConfig(ctx, scope, orgID)
	providerType := ""
	if configErr == nil && config != nil {
		providerType = string(config.Provider)
	} else if configErr != nil && configErr != mongo.ErrNoDocuments {
		// Log error if config fetch failed for reasons other than not found
		s.zLogger.Warn().Err(configErr).Str("scope", scope).Str("orgID", orgID).Msg("Failed to get config for DEK status check")
		// Continue, but provider type will be empty
	}

	// Now check for the DEK in the store
	info, err := s.store.GetActiveDEK(ctx, scope, orgID)
	if err != nil {
		// If not found, return default status with the provider type from config
		if strings.Contains(err.Error(), "not found") || err == mongo.ErrNoDocuments {
			return &types.DEKStatus{
				Exists:        false,
				Active:        false,
				Provider:      types.ProviderType(providerType),
				ProviderKeyID: "", // Ensure ProviderKeyID is initialized
				NeedsRotate:   false,
			}, nil
		}
		// For other store errors, return the error
		return nil, fmt.Errorf("failed to get DEK info for status check: %w", err)
	}

	// Add defensive nil check for info, even if err is nil
	if info == nil {
		s.zLogger.Warn().Str("scope", scope).Str("orgID", orgID).Msg("GetActiveDEK returned nil info without error, treating as non-existent")
		return &types.DEKStatus{
			Exists:        false,
			Active:        false,
			Provider:      types.ProviderType(providerType),
			ProviderKeyID: "", // Ensure ProviderKeyID is initialized
			NeedsRotate:   false,
		}, nil
	}

	needsRotate := false
	var providerKeyID string
	if info.Active && len(info.Versions) > 0 {
		// Get the latest (active) version
		latestVersion := info.Versions[len(info.Versions)-1]
		if latestVersion.BlobInfo != nil && latestVersion.BlobInfo.KeyInfo != nil {
			providerKeyID = latestVersion.BlobInfo.KeyInfo.KeyId
		}
	}

	status := &types.DEKStatus{
		Exists:        true,
		Active:        info.Active,
		Version:       info.Version,
		CreatedAt:     info.CreatedAt,
		UpdatedAt:     info.UpdatedAt,
		Provider:      types.ProviderType(providerType),
		ProviderKeyID: providerKeyID, // Populate ProviderKeyID
		NeedsRotate:   needsRotate,
	}

	return status, nil
}

// GetInfo implements Service
func (s *dekService) GetInfo(ctx context.Context, scope string, id string) (*types.DEKInfo, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	// Get DEK info from store
	info, err := s.store.GetActiveDEK(ctx, scope, id)
	if err != nil {
		s.zLogger.Error().
			Err(err).
			Str("scope", scope).
			Str("id", id).
			Msg("Failed to get DEK info from store")
		return nil, fmt.Errorf("failed to get DEK info: %w", err)
	}

	// If no DEK exists, return nil
	if info == nil {
		s.zLogger.Trace().
			Str("scope", scope).
			Str("id", id).
			Msg("No DEK info found")
		return nil, nil
	}

	s.zLogger.Trace().
		Str("scope", scope).
		Str("id", id).
		Str("dekId", info.Id).
		Int("version", info.Version).
		Int("numVersions", len(info.Versions)).
		Bool("active", info.Active).
		Time("createdAt", info.CreatedAt).
		Time("updatedAt", info.UpdatedAt).
		Msg("Found DEK info")

	return info, nil
}

// Create implements Service
func (s *dekService) Create(ctx context.Context, scope string, id string) error {
	_, err := s.CreateDEK(ctx, scope, id)
	return err
}

// Rotate implements Service
func (s *dekService) Rotate(ctx context.Context, scope string, id string) error {
	_, err := s.RotateDEK(ctx, scope, id, false)
	return err
}

// Restore implements Service
func (s *dekService) Restore(ctx context.Context, scope string, id string) error {
	return s.DeleteDEK(ctx, scope, id)
}

// InvalidateCache clears cache entries related to a specific scope.
// Required for the DEKService interface and used by CoreEncryptionService.
func (s *dekService) InvalidateCache(ctx context.Context, scope string, scopeID string) error {
	s.zLogger.Trace().Str("scope", scope).Str("scopeID", scopeID).Msg("Invalidating DEK cache")

	if s.cache == nil || !s.cache.IsEnabled() {
		s.zLogger.Trace().Str("scope", scope).Str("scopeID", scopeID).Msg("Cache not enabled or nil, skipping invalidation")
		return nil
	}

	// Invalidate DEK Info cache
	infoCacheKey, err := s.getCacheKey(scope, scopeID)
	if err == nil {
		s.cache.Delete(infoCacheKey)
		s.zLogger.Trace().Str("key", infoCacheKey).Msg("Deleted DEK info cache key")
	} else {
		s.zLogger.Warn().Err(err).Str("scope", scope).Str("scopeID", scopeID).Msg("Failed to generate DEK info cache key for invalidation")
		// Continue to try and invalidate unwrapped keys if possible
	}

	// Invalidate all unwrapped DEK cache entries for this scope by fetching the
	// DEK info from the store to enumerate all known versions, then deleting each
	// versioned cache key. This ensures that a rotated or revoked DEK is not served
	// from cache after invalidation.
	dekInfo, storeErr := s.store.GetActiveDEK(ctx, scope, scopeID)
	if storeErr == nil && dekInfo != nil {
		clearedCount := 0
		for _, v := range dekInfo.Versions {
			unwrappedKey, keyErr := s.getUnwrappedCacheKey(ctx, v.Version, scope, scopeID)
			if keyErr == nil {
				s.cache.Delete(unwrappedKey)
				clearedCount++
				s.zLogger.Trace().Str("key", unwrappedKey).Msg("Deleted unwrapped DEK cache key")
			} else {
				s.zLogger.Warn().Err(keyErr).Int("version", v.Version).Str("scope", scope).Str("scopeID", scopeID).Msg("Failed to generate unwrapped cache key for version during invalidation")
			}
		}
		s.zLogger.Debug().Int("versionsCleared", clearedCount).Str("scope", scope).Str("scopeID", scopeID).Msg("Cleared unwrapped DEK cache entries")
	} else if storeErr != nil {
		s.zLogger.Warn().Err(storeErr).Str("scope", scope).Str("scopeID", scopeID).Msg("Could not fetch DEK info to enumerate versions for cache invalidation; unwrapped DEK cache entries will expire via TTL")
	}

	return nil
}

// GetScopedFieldService returns a FieldService instance appropriate for the scope
// defined in the context. It checks configuration and initializes necessary components
// (like KMS provider, DEK info) on-demand.
func (s *dekService) GetScopedFieldService(ctx context.Context) (interfaces.FieldService, error) {
	s.zLogger.Trace().Msg("GetScopedFieldService called in DEK service")

	// 1. Extract scope and scopeID from context first.
	scope, scopeID := s.getScopeFromContext(ctx)
	s.zLogger.Trace().Str("scope", scope).Str("scopeID", scopeID).Msg("Extracted scope and ID for FieldService")

	// 2. Check if encryption is configured and enabled for the extracted scope.
	config, err := s.configGetter.GetEncryptionConfig(ctx, scope, scopeID)
	if err != nil {
		if err == mongo.ErrNoDocuments || strings.Contains(err.Error(), "not found") {
			s.zLogger.Info().Str("scope", scope).Str("scopeID", scopeID).Msg("Encryption config not found for scope, returning no-op FieldService.")
			return field.NewFieldService(nil, s.logger, s.zLogger, scope, scopeID), nil
		}
		s.zLogger.Error().Err(err).Str("scope", scope).Str("scopeID", scopeID).Msg("Failed to get encryption config for scope")
		return nil, fmt.Errorf("failed to get encryption config for scope %s/%s: %w", scope, scopeID, err)
	}

	// 3. If config exists, check if encryption is enabled.
	if config == nil || !config.Enabled { // config == nil check is defensive
		s.zLogger.Trace().Str("scope", scope).Str("scopeID", scopeID).Msg("Encryption explicitly disabled for scope, returning no-op FieldService.")
		return field.NewFieldService(nil, s.logger, s.zLogger, scope, scopeID), nil
	}

	s.zLogger.Trace().Str("scope", scope).Str("scopeID", scopeID).Msg("Encryption enabled for scope. Ensuring KMS and DEK are ready.")

	// 4a. Get KMS Provider (will be cached by the getter implementation)
	kmsProvider, err := s.kmsGetter.GetKMSProvider(ctx, scope, scopeID)
	if err != nil {
		s.zLogger.Error().Err(err).Str("scope", scope).Str("scopeID", scopeID).Msg("Failed to get KMS provider for enabled scope")
		return nil, fmt.Errorf("failed to get KMS provider for scope %s/%s: %w", scope, scopeID, err)
	}
	if kmsProvider == nil {
		s.zLogger.Error().Str("scope", scope).Str("scopeID", scopeID).Msg("Encryption enabled but KMS provider is nil")
		return nil, fmt.Errorf("encryption enabled but KMS provider is not available for scope %s/%s", scope, scopeID)
	}

	// 4b. Load DEK Info (using the store, which handles its own caching via loadDEKInfo)
	// Note: s.loadDEKInfo() uses the scope/orgID from the context it *receives* (ctx),
	// which should have been properly set up by the caller of GetScopedFieldService.
	// If s.loadDEKInfo() needs explicit scope/orgID, this part might need adjustment.
	// For now, assuming context propagation handles it.
	dekInfo, err := s.loadDEKInfo(ctx) // This uses the original ctx, assuming it has the correct scope for loadDEKInfo
	if err != nil {
		if strings.Contains(err.Error(), "not found") || err == mongo.ErrNoDocuments {
			s.zLogger.Error().Str("scope", scope).Str("scopeID", scopeID).Msg("Encryption enabled but no active DEK found for scope")
			return nil, fmt.Errorf("encryption enabled but no active DEK found for scope %s/%s", scope, scopeID)
		}
		s.zLogger.Error().Err(err).Str("scope", scope).Str("scopeID", scopeID).Msg("Failed to load DEK info for enabled scope")
		return nil, fmt.Errorf("failed to load DEK info for scope %s/%s: %w", scope, scopeID, err)
	}
	if dekInfo == nil || !dekInfo.Active || len(dekInfo.Versions) == 0 {
		s.zLogger.Error().Str("scope", scope).Str("scopeID", scopeID).Msg("Encryption enabled but loaded DEK is inactive or has no versions")
		return nil, fmt.Errorf("encryption enabled but DEK is not active for scope %s/%s", scope, scopeID)
	}

	// 4c. Perform necessary internal checks (e.g., try unwrapping the latest DEK version)
	latestVersion := dekInfo.Versions[len(dekInfo.Versions)-1]
	// Pass the correct scope and scopeID to UnwrapDEK
	_, unwrapErr := s.UnwrapDEK(ctx, &latestVersion, scope, scopeID)
	if unwrapErr != nil {
		s.zLogger.Error().Err(unwrapErr).Str("scope", scope).Str("scopeID", scopeID).Int("dekVersion", latestVersion.Version).Msg("DEK verification failed: Unable to unwrap latest DEK version")
		return nil, fmt.Errorf("DEK verification failed for scope %s/%s: %w", scope, scopeID, unwrapErr)
	}
	s.zLogger.Trace().Str("scope", scope).Str("scopeID", scopeID).Int("dekVersion", latestVersion.Version).Msg("DEK verification successful.")

	// 5. Return a properly configured FieldService instance
	s.zLogger.Trace().Str("scope", scope).Str("scopeID", scopeID).Msg("Returning configured FieldService for scope.")
	return field.NewFieldService(s, s.logger, s.zLogger, scope, scopeID), nil
}
