package store

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"

	"github.com/root-sector-ltd-and-co-kg/payment-gateway-lib-crypto/types"
)

func TestMongoDBStoreRotationUsesExpectedVersionAtomicUpdate(t *testing.T) {
	var capturedCollection string
	var capturedFilter any
	var capturedUpdate any
	var capturedOptions []options.Lister[options.UpdateOneOptions]
	store := &MongoDBStore{
		cacheTTL: time.Minute,
		updateOne: func(_ context.Context, collection string, filter, update any, opts ...options.Lister[options.UpdateOneOptions]) (*mongo.UpdateResult, error) {
			capturedCollection = collection
			capturedFilter = filter
			capturedUpdate = update
			capturedOptions = opts
			return &mongo.UpdateResult{MatchedCount: 1, ModifiedCount: 1}, nil
		},
	}
	info := rotationStoreTestInfo()

	if err := store.StoreDEK(context.Background(), info, "system", ""); err != nil {
		t.Fatalf("StoreDEK() error = %v", err)
	}

	if capturedCollection != "system" {
		t.Fatalf("collection = %q, want system", capturedCollection)
	}
	wantFilter := bson.M{
		"_id":         "1",
		"dek._id":     info.Id,
		"dek.active":  true,
		"dek.version": 1,
	}
	if !reflect.DeepEqual(capturedFilter, wantFilter) {
		t.Fatalf("rotation filter = %#v, want %#v", capturedFilter, wantFilter)
	}
	wantUpdate := bson.M{
		"$set": bson.M{
			"dek.active":    true,
			"dek.version":   2,
			"dek.updatedAt": info.UpdatedAt,
			"updatedAt":     info.UpdatedAt,
		},
		"$push": bson.M{"dek.versions": info.Versions[1]},
	}
	if !reflect.DeepEqual(capturedUpdate, wantUpdate) {
		t.Fatalf("rotation update = %#v, want atomic update %#v", capturedUpdate, wantUpdate)
	}
	if len(capturedOptions) != 0 {
		t.Fatalf("rotation used %d update options, want no upsert option", len(capturedOptions))
	}
}

func TestMongoDBStoreRotationConflictEvictsCache(t *testing.T) {
	store := &MongoDBStore{
		cacheTTL: time.Minute,
		updateOne: func(context.Context, string, any, any, ...options.Lister[options.UpdateOneOptions]) (*mongo.UpdateResult, error) {
			return &mongo.UpdateResult{MatchedCount: 0}, nil
		},
	}
	cacheKey := store.getCacheKey("system", "")
	store.cache.Store(cacheKey, &cacheEntry{value: rotationStoreTestInfo(), expiresAt: time.Now().Add(time.Minute)})

	err := store.StoreDEK(context.Background(), rotationStoreTestInfo(), "system", "")
	if err == nil || !errors.Is(err, errDEKVersionConflict) {
		t.Fatalf("StoreDEK() error = %v, want DEK version conflict", err)
	}
	if !strings.Contains(err.Error(), "expected version 1") {
		t.Fatalf("StoreDEK() error = %q, want expected-version context", err)
	}
	if _, ok := store.cache.Load(cacheKey); ok {
		t.Fatal("rotation conflict left stale DEK info in the process cache")
	}
}

func rotationStoreTestInfo() *types.DEKInfo {
	return &types.DEKInfo{
		Id:        "rotation-test-dek",
		Version:   2,
		Active:    true,
		Versions:  []types.DEKVersion{{Version: 1}, {Version: 2}},
		CreatedAt: time.Unix(1, 0).UTC(),
		UpdatedAt: time.Unix(2, 0).UTC(),
	}
}
