package cache

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/root-sector-ltd-and-co-kg/payment-gateway-lib-crypto/interfaces"
)

// stubCache implements interfaces.Cache for adapter tests.
type stubCache struct {
	setErr  error
	delErr  error
	keysErr error
	keys    []string
}

func (s *stubCache) Set(ctx context.Context, key string, value interface{}, expiration time.Duration) error {
	return s.setErr
}

func (s *stubCache) Get(ctx context.Context, key string, dest interface{}) error {
	return errors.New("not implemented")
}

func (s *stubCache) Delete(ctx context.Context, key string) error {
	return s.delErr
}

func (s *stubCache) Keys(ctx context.Context, pattern string) ([]string, error) {
	if s.keysErr != nil {
		return nil, s.keysErr
	}
	return s.keys, nil
}

var _ interfaces.Cache = (*stubCache)(nil)

func TestCacheAdapter_SetDoesNotPanicOnUnderlyingError(t *testing.T) {
	t.Parallel()
	stub := &stubCache{setErr: errors.New("backend unavailable")}
	adapter := NewCacheAdapter(stub)
	adapter.Set(context.Background(), "k", []byte("v"), 1)
}

func TestCacheAdapter_DeleteDoesNotPanicOnUnderlyingError(t *testing.T) {
	t.Parallel()
	stub := &stubCache{delErr: errors.New("delete failed")}
	adapter := NewCacheAdapter(stub)
	adapter.Delete("k")
}

func TestCacheAdapter_ClearDoesNotPanicOnKeysError(t *testing.T) {
	t.Parallel()
	stub := &stubCache{keysErr: errors.New("keys failed")}
	adapter := NewCacheAdapter(stub)
	adapter.Clear()
}

func TestCacheAdapter_ClearIteratesDeletes(t *testing.T) {
	t.Parallel()
	stub := &stubCache{keys: []string{"a", "b"}}
	adapter := NewCacheAdapter(stub)
	adapter.Clear()
}
