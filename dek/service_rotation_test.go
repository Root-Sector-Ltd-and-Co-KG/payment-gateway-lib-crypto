package dek

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"testing"
	"time"

	wrapping "github.com/hashicorp/go-kms-wrapping/v2"
	"github.com/rs/zerolog"

	"github.com/root-sector-ltd-and-co-kg/payment-gateway-lib-crypto/interfaces"
	"github.com/root-sector-ltd-and-co-kg/payment-gateway-lib-crypto/kms"
	"github.com/root-sector-ltd-and-co-kg/payment-gateway-lib-crypto/types"
)

func TestRotateDEKMaterialSemantics(t *testing.T) {
	t.Run("ordinary rotation preserves plaintext material", func(t *testing.T) {
		service, store, provider := newRotationTestService(t)
		before := activeMaterialFingerprint(t, provider, store.active)

		_, err := service.RotateDEK(context.Background(), scopeSystem, "", false)
		if err != nil {
			t.Fatalf("ordinary rotation failed: %v", err)
		}

		after := activeMaterialFingerprint(t, provider, store.active)
		if before != after {
			t.Fatal("ordinary rotation changed plaintext DEK material")
		}
	})

	t.Run("forced rotation replaces plaintext material", func(t *testing.T) {
		service, store, provider := newRotationTestService(t)
		before := activeMaterialFingerprint(t, provider, store.active)
		replacement := sha256.Sum256([]byte("replacement DEK material"))
		service.entropy = bytes.NewReader(replacement[:])

		_, err := service.RotateDEK(context.Background(), scopeSystem, "", true)
		if err != nil {
			t.Fatalf("forced rotation failed: %v", err)
		}

		after := activeMaterialFingerprint(t, provider, store.active)
		if before == after {
			t.Fatal("forced rotation reused plaintext DEK material")
		}
	})
}

func TestRotateDEKFailuresLeaveActiveVersionUnchanged(t *testing.T) {
	tests := []struct {
		name      string
		configure func(t *testing.T, store *rotationTestStore, getter *rotationTestKMSGetter)
	}{
		{
			name: "generation failure",
			configure: func(_ *testing.T, _ *rotationTestStore, getter *rotationTestKMSGetter) {
				getter.service.entropy = errorReader{err: errors.New("entropy unavailable")}
			},
		},
		{
			name: "wrapping failure",
			configure: func(_ *testing.T, _ *rotationTestStore, getter *rotationTestKMSGetter) {
				replacement := sha256.Sum256([]byte("replacement after wrapping failure"))
				getter.service.entropy = bytes.NewReader(replacement[:])
				getter.provider = &rotationTestProvider{
					Provider: getter.provider,
					wrapper: &rotationTestWrapper{
						Wrapper:    getter.provider.GetWrapper(),
						encryptErr: errors.New("wrapping unavailable"),
					},
				}
			},
		},
		{
			name: "store failure",
			configure: func(_ *testing.T, store *rotationTestStore, getter *rotationTestKMSGetter) {
				replacement := sha256.Sum256([]byte("replacement after store failure"))
				getter.service.entropy = bytes.NewReader(replacement[:])
				store.storeErr = errors.New("persistence unavailable")
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			service, store, provider, getter := newRotationTestServiceWithGetter(t)
			before := activeMaterialFingerprint(t, provider, store.active)
			tt.configure(t, store, getter)

			_, err := service.RotateDEK(context.Background(), scopeSystem, "", true)
			if err == nil {
				t.Fatal("rotation failure was not returned")
			}

			after := activeMaterialFingerprint(t, provider, store.active)
			if before != after || store.active.Version != 1 || len(store.active.Versions) != 1 {
				t.Fatal("failed rotation changed the active DEK version")
			}
		})
	}
}

func newRotationTestService(t *testing.T) (*dekService, *rotationTestStore, kms.Provider) {
	service, store, provider, _ := newRotationTestServiceWithGetter(t)
	return service, store, provider
}

func newRotationTestServiceWithGetter(t *testing.T) (*dekService, *rotationTestStore, kms.Provider, *rotationTestKMSGetter) {
	t.Helper()
	wrappingKey := sha256.Sum256([]byte("rotation test wrapping key"))
	provider, err := kms.NewProvider(kms.Config{
		Type:          types.ProviderAead,
		AeadKeyID:     "rotation-test",
		AeadKeyBase64: base64.StdEncoding.EncodeToString(wrappingKey[:]),
	})
	if err != nil {
		t.Fatalf("create test KMS provider: %v", err)
	}

	getter := &rotationTestKMSGetter{provider: provider}
	store := &rotationTestStore{}
	serviceInterface, err := NewService(
		getter,
		rotationTestConfigGetter{},
		rotationTestAuditLogger{},
		store,
		nil,
		nil,
		zerolog.Nop(),
	)
	if err != nil {
		t.Fatalf("create DEK service: %v", err)
	}
	service := serviceInterface.(*dekService)
	getter.service = service

	initial := sha256.Sum256([]byte("initial DEK material"))
	version, err := service.wrapDEK(context.Background(), initial[:], scopeSystem, "")
	if err != nil {
		t.Fatalf("wrap initial DEK: %v", err)
	}
	store.active = &types.DEKInfo{
		Id:        "rotation-test-dek",
		Version:   1,
		Active:    true,
		Versions:  []types.DEKVersion{*version},
		CreatedAt: time.Unix(1, 0).UTC(),
		UpdatedAt: time.Unix(1, 0).UTC(),
	}

	return service, store, provider, getter
}

func activeMaterialFingerprint(t *testing.T, provider kms.Provider, info *types.DEKInfo) [sha256.Size]byte {
	t.Helper()
	if info == nil || len(info.Versions) == 0 {
		t.Fatal("active DEK version is missing")
	}
	version := info.Versions[len(info.Versions)-1]
	plaintext, err := provider.GetWrapper().Decrypt(
		context.Background(),
		version.BlobInfo,
		wrapping.WithAad(version.WrapContext),
	)
	if err != nil {
		t.Fatalf("unwrap active DEK for fingerprint: %v", err)
	}
	return sha256.Sum256(plaintext)
}

type errorReader struct {
	err error
}

func (r errorReader) Read(_ []byte) (int, error) {
	return 0, r.err
}

type rotationTestKMSGetter struct {
	provider kms.Provider
	service  *dekService
}

func (g *rotationTestKMSGetter) GetKMSProvider(context.Context, string, string) (kms.Provider, error) {
	return g.provider, nil
}

type rotationTestProvider struct {
	kms.Provider
	wrapper wrapping.Wrapper
}

func (p *rotationTestProvider) GetWrapper() wrapping.Wrapper {
	return p.wrapper
}

type rotationTestWrapper struct {
	wrapping.Wrapper
	encryptErr error
}

func (w *rotationTestWrapper) Encrypt(context.Context, []byte, ...wrapping.Option) (*wrapping.BlobInfo, error) {
	return nil, w.encryptErr
}

type rotationTestConfigGetter struct{}

func (rotationTestConfigGetter) GetEncryptionConfig(context.Context, string, string) (*types.EncryptionConfig, error) {
	return &types.EncryptionConfig{Enabled: true, Provider: types.ProviderAead}, nil
}

type rotationTestStore struct {
	active   *types.DEKInfo
	storeErr error
}

func (s *rotationTestStore) GetDEK(context.Context, string, string) (*types.DEKInfo, error) {
	return cloneRotationDEKInfo(s.active), nil
}

func (s *rotationTestStore) GetActiveDEK(context.Context, string, string) (*types.DEKInfo, error) {
	return cloneRotationDEKInfo(s.active), nil
}

func (s *rotationTestStore) StoreDEK(_ context.Context, info *types.DEKInfo, _, _ string) error {
	if s.storeErr != nil {
		return s.storeErr
	}
	s.active = cloneRotationDEKInfo(info)
	return nil
}

func (s *rotationTestStore) DeleteDEK(context.Context, string, string) error {
	return nil
}

func (s *rotationTestStore) ListDEKs(context.Context, string) ([]*types.DEKInfo, error) {
	if s.active == nil {
		return nil, nil
	}
	return []*types.DEKInfo{cloneRotationDEKInfo(s.active)}, nil
}

func cloneRotationDEKInfo(info *types.DEKInfo) *types.DEKInfo {
	if info == nil {
		return nil
	}
	clone := *info
	clone.Versions = append([]types.DEKVersion(nil), info.Versions...)
	return &clone
}

type rotationTestAuditLogger struct{}

func (rotationTestAuditLogger) Printf(string, ...interface{}) {}

func (rotationTestAuditLogger) LogEvent(context.Context, *types.AuditEvent) error {
	return nil
}

func (rotationTestAuditLogger) GetEvents(context.Context, map[string]interface{}) ([]*types.AuditEvent, error) {
	return nil, nil
}

var _ interfaces.DEKStore = (*rotationTestStore)(nil)
var _ interfaces.AuditLogger = rotationTestAuditLogger{}
