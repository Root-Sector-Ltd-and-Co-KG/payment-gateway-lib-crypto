// Package cache provides caching functionality for encryption operations.
package cache

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/root-sector-ltd-and-co-kg/payment-gateway-lib-crypto/interfaces"
	"github.com/root-sector-ltd-and-co-kg/payment-gateway-lib-crypto/types"
	"github.com/rs/zerolog/log"
)

// CacheAdapter adapts the internal cache interface to the encryption cache interface.
// It provides a bridge between the general-purpose internal cache and the specialized
// encryption cache requirements, ensuring type safety and proper data handling.
type CacheAdapter struct {
	cache interfaces.Cache // The underlying internal cache implementation
}

// NewCacheAdapter creates a new adapter for the internal cache.
// It wraps the provided internal cache implementation with the encryption cache interface.
// Parameters:
//   - cache: The internal cache implementation to adapt
//
// Returns:
//   - types.Cache: The adapted cache implementing the encryption cache interface
func NewCacheAdapter(cache interfaces.Cache) types.Cache {
	return &CacheAdapter{cache: cache}
}

// Enable implements types.Cache.
// This is a no-op as the internal cache is always enabled.
func (a *CacheAdapter) Enable() {
	// No-op as internal cache is always enabled
}

// Disable implements types.Cache.
// This is a no-op as the internal cache cannot be disabled.
func (a *CacheAdapter) Disable() {
	// No-op as internal cache cannot be disabled
}

// IsEnabled implements types.Cache.
// Returns true if the underlying cache is initialized.
func (a *CacheAdapter) IsEnabled() bool {
	return a.cache != nil
}

// Clear implements types.Cache.
// Attempts to clear all entries from the cache using pattern matching.
// This is a best-effort operation that may not clear all entries if
// pattern matching fails or if some deletions fail.
func (a *CacheAdapter) Clear() {
	ctx := context.Background()
	keys, err := a.cache.Keys(ctx, "*")
	if err != nil {
		log.Warn().Err(err).Str("op", "cache.Keys").Msg("encryption cache clear: list keys failed")
		return
	}
	for _, key := range keys {
		if delErr := a.cache.Delete(ctx, key); delErr != nil {
			log.Warn().Err(delErr).Str("op", "cache.Delete").Msg("encryption cache clear: delete failed")
		}
	}
}

// Get implements types.Cache.
// Retrieves a value from the cache and converts it to the encryption cache format.
// Parameters:
//   - ctx: Context for the operation
//   - key: The cache key to retrieve
//
// Returns:
//   - *types.SecureBytes: The retrieved value as secure bytes
//   - int: The version of the cached value
//   - bool: Whether the value was found in the cache
func (a *CacheAdapter) Get(ctx context.Context, key string) (*types.SecureBytes, int, bool) {
	var entry types.CacheEntry
	err := a.cache.Get(ctx, key, &entry)
	if err != nil {
		return nil, 0, false
	}
	return entry.Value, entry.Version, true
}

// Set implements types.Cache.
// Stores a value in the cache with the encryption cache format.
// Parameters:
//   - ctx: Context for the operation
//   - key: The cache key to store
//   - value: The value to store as bytes
//   - version: The version of the value being stored
func (a *CacheAdapter) Set(ctx context.Context, key string, value []byte, version int) {
	entry := types.CacheEntry{
		Value:   types.NewSecureBytes(value),
		Version: version,
	}
	_ = a.cache.Set(ctx, key, entry, 15*time.Minute) // Using default TTL
}

// Delete implements types.Cache.
// Removes a value from the cache.
// Parameters:
//   - key: The cache key to delete
func (a *CacheAdapter) Delete(key string) {
	if err := a.cache.Delete(context.Background(), key); err != nil {
		log.Warn().Err(err).Str("op", "cache.Delete").Msg("encryption cache delete failed")
	}
}

// GetStats implements types.Cache.
// Returns basic cache statistics.
// Note: The internal cache doesn't expose detailed stats, so this returns
// minimal information with current timestamps.
func (a *CacheAdapter) GetStats(ctx context.Context) types.CacheStats {
	// Basic stats since internal cache doesn't expose detailed stats
	return types.CacheStats{
		LastAccess:  time.Now(),
		LastUpdated: time.Now(),
	}
}

// ReverseAdapter adapts the encryption cache interface to the internal cache interface.
// This provides bidirectional compatibility between the two cache interfaces,
// allowing the encryption cache to be used where an internal cache is expected.
type ReverseAdapter struct {
	cache types.Cache // The underlying encryption cache implementation
}

// NewReverseAdapter creates a new adapter for the encryption cache.
// It wraps the provided encryption cache with the internal cache interface.
// Parameters:
//   - cache: The encryption cache implementation to adapt
//
// Returns:
//   - internalCache.CacheInterface: The adapted cache implementing the internal cache interface
func NewReverseAdapter(cache types.Cache) interfaces.Cache {
	return &ReverseAdapter{cache: cache}
}

// Set implements CacheInterface.
// Stores a value in the encryption cache after JSON marshaling.
// Parameters:
//   - ctx: Context for the operation
//   - key: The cache key to store
//   - value: The value to store (will be JSON marshaled)
//   - expiration: The TTL for the cached value (not used in encryption cache)
//
// Returns:
//   - error: Any error that occurred during the operation
func (r *ReverseAdapter) Set(ctx context.Context, key string, value interface{}, expiration time.Duration) error {
	data, err := json.Marshal(value)
	if err != nil {
		return err
	}
	r.cache.Set(ctx, key, data, 1) // Version 1 as default
	return nil
}

// Get implements CacheInterface.
// Retrieves a value from the encryption cache and JSON unmarshals it.
// Parameters:
//   - ctx: Context for the operation
//   - key: The cache key to retrieve
//   - dest: Destination interface to unmarshal the value into
//
// Returns:
//   - error: Any error that occurred during the operation
func (r *ReverseAdapter) Get(ctx context.Context, key string, dest interface{}) error {
	value, _, found := r.cache.Get(ctx, key)
	if !found {
		return errors.New("cache: key not found")
	}
	return json.Unmarshal(value.Get(), dest)
}

// Delete implements CacheInterface.
// Removes a value from the encryption cache.
// Parameters:
//   - ctx: Context for the operation (not used)
//   - key: The cache key to delete
//
// Returns:
//   - error: Any error that occurred during the operation
func (r *ReverseAdapter) Delete(ctx context.Context, key string) error {
	r.cache.Delete(key)
	return nil
}

// Keys implements CacheInterface.
// This operation is not supported in the encryption cache interface.
// Parameters:
//   - ctx: Context for the operation (not used)
//   - pattern: The pattern to match keys against (not used)
//
// Returns:
//   - []string: Always returns nil
//   - error: Always returns nil
func (r *ReverseAdapter) Keys(ctx context.Context, pattern string) ([]string, error) {
	// Not supported in the encryption cache interface
	return nil, nil
}
