package field

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"math"
	"strings"
	"testing"

	"github.com/rs/zerolog"

	"github.com/root-sector-ltd-and-co-kg/payment-gateway-lib-crypto/audit"
	"github.com/root-sector-ltd-and-co-kg/payment-gateway-lib-crypto/interfaces"
	"github.com/root-sector-ltd-and-co-kg/payment-gateway-lib-crypto/types"
)

type securityTestDEKService struct {
	statusVersion int
}

func (s *securityTestDEKService) Initialize(ctx context.Context) error { return nil }
func (s *securityTestDEKService) GetAuditLogger() interface{}          { return nil }
func (s *securityTestDEKService) GetTaskProcessor() interface{}        { return nil }
func (s *securityTestDEKService) GetInfo(ctx context.Context, scope string, id string) (*types.DEKInfo, error) {
	return &types.DEKInfo{
		Version:  s.statusVersion,
		Active:   true,
		Versions: []types.DEKVersion{{Version: s.statusVersion}},
	}, nil
}
func (s *securityTestDEKService) GetDEKStatus(ctx context.Context, scope string, id string) (*types.DEKStatus, error) {
	return &types.DEKStatus{Exists: true, Active: true, Version: s.statusVersion}, nil
}
func (s *securityTestDEKService) GetDEKStats(ctx context.Context, scope string, id string) (*types.DEKStats, error) {
	return nil, nil
}
func (s *securityTestDEKService) Create(ctx context.Context, scope string, id string) error {
	return nil
}
func (s *securityTestDEKService) Rotate(ctx context.Context, scope string, id string) error {
	return nil
}
func (s *securityTestDEKService) Restore(ctx context.Context, scope string, id string) error {
	return nil
}
func (s *securityTestDEKService) CreateDEK(ctx context.Context, scope string, orgID string) (*types.DEKInfo, error) {
	return nil, nil
}
func (s *securityTestDEKService) DeleteDEK(ctx context.Context, scope string, orgID string) error {
	return nil
}
func (s *securityTestDEKService) UnwrapDEK(ctx context.Context, version *types.DEKVersion, scope string, orgID string) ([]byte, error) {
	return nil, nil
}
func (s *securityTestDEKService) RotateDEK(ctx context.Context, scope string, orgID string, force bool) (*types.DEKInfo, error) {
	return nil, nil
}
func (s *securityTestDEKService) GetActiveDEK(ctx context.Context, scope string, orgID string) ([]byte, error) {
	return []byte("0123456789abcdef0123456789abcdef"), nil
}
func (s *securityTestDEKService) InvalidateCache(ctx context.Context, scope string, scopeID string) error {
	return nil
}
func (s *securityTestDEKService) GetScopedFieldService(ctx context.Context) (interfaces.FieldService, error) {
	return nil, nil
}

type securityTestAuditLogger struct {
	err error
}

func (l *securityTestAuditLogger) Printf(format string, v ...interface{}) {}
func (l *securityTestAuditLogger) LogEvent(ctx context.Context, event *types.AuditEvent) error {
	return l.err
}
func (l *securityTestAuditLogger) GetEvents(ctx context.Context, filters map[string]interface{}) ([]*types.AuditEvent, error) {
	return nil, nil
}

func securityTestContext() context.Context {
	ctx := context.Background()
	ctx = context.WithValue(ctx, audit.KeyScope, "system")
	ctx = context.WithValue(ctx, audit.KeyCollection, "customers")
	ctx = context.WithValue(ctx, audit.KeyRecordID, "cus_123")
	ctx = context.WithValue(ctx, audit.KeyFieldName, "email")
	ctx = context.WithValue(ctx, audit.KeyFieldType, "string")
	return ctx
}

type rotationRaceDEKService struct {
	securityTestDEKService
	activeVersion int
	rotated       bool
	keys          map[int][]byte
}

func newRotationRaceDEKService() *rotationRaceDEKService {
	versionOneKey := sha256.Sum256([]byte("field encryption race version one"))
	versionTwoKey := sha256.Sum256([]byte("field encryption race version two"))
	return &rotationRaceDEKService{
		activeVersion: 1,
		keys: map[int][]byte{
			1: versionOneKey[:],
			2: versionTwoKey[:],
		},
	}
}

func (s *rotationRaceDEKService) rotateAfterSnapshot() {
	if !s.rotated {
		s.activeVersion = 2
		s.rotated = true
	}
}

func (s *rotationRaceDEKService) GetInfo(context.Context, string, string) (*types.DEKInfo, error) {
	version := s.activeVersion
	s.rotateAfterSnapshot()
	return &types.DEKInfo{
		Version: version,
		Active:  true,
		Versions: []types.DEKVersion{
			{Version: 1},
			{Version: 2},
		},
	}, nil
}

func (s *rotationRaceDEKService) GetDEKStatus(context.Context, string, string) (*types.DEKStatus, error) {
	version := s.activeVersion
	s.rotateAfterSnapshot()
	return &types.DEKStatus{Exists: true, Active: true, Version: version}, nil
}

func (s *rotationRaceDEKService) GetActiveDEK(context.Context, string, string) ([]byte, error) {
	return s.keys[s.activeVersion], nil
}

func (s *rotationRaceDEKService) UnwrapDEK(_ context.Context, version *types.DEKVersion, _, _ string) ([]byte, error) {
	return s.keys[version.Version], nil
}

func TestFieldServiceEncryptBindsDEKVersionAndMaterialToSameSnapshot(t *testing.T) {
	dekService := newRotationRaceDEKService()
	svc := NewFieldService(dekService, nil, zerolog.Nop(), "system", "")
	const plaintext = "alice@example.test"
	field := &types.FieldEncrypted{Plaintext: plaintext}

	if err := svc.Encrypt(securityTestContext(), field); err != nil {
		t.Fatalf("Encrypt() error = %v", err)
	}
	if field.Version != 1 {
		t.Fatalf("encrypted field version = %d, want snapshot version 1", field.Version)
	}
	if err := svc.Decrypt(securityTestContext(), field); err != nil {
		t.Fatalf("Decrypt() ciphertext produced across forced rotation: %v", err)
	}
	if field.Plaintext != plaintext {
		t.Fatalf("decrypted plaintext = %q, want %q", field.Plaintext, plaintext)
	}
}

func TestFieldServiceRejectsUnsafeDEKVersionsBeforeEncrypting(t *testing.T) {
	tests := []struct {
		name    string
		version int
		run     func(context.Context, interfaces.FieldService, *types.FieldEncrypted) error
	}{
		{
			name:    "encrypt rejects negative active DEK version",
			version: -1,
			run: func(ctx context.Context, svc interfaces.FieldService, field *types.FieldEncrypted) error {
				return svc.Encrypt(ctx, field)
			},
		},
		{
			name:    "encrypt rejects active DEK version above uint32",
			version: int(math.MaxUint32) + 1,
			run: func(ctx context.Context, svc interfaces.FieldService, field *types.FieldEncrypted) error {
				return svc.Encrypt(ctx, field)
			},
		},
		{
			name:    "searchable encrypt rejects negative active DEK version",
			version: -1,
			run: func(ctx context.Context, svc interfaces.FieldService, field *types.FieldEncrypted) error {
				return svc.EncryptSearchable(ctx, field, strings.Repeat("01", 32))
			},
		},
		{
			name:    "searchable encrypt rejects active DEK version above uint32",
			version: int(math.MaxUint32) + 1,
			run: func(ctx context.Context, svc interfaces.FieldService, field *types.FieldEncrypted) error {
				return svc.EncryptSearchable(ctx, field, strings.Repeat("01", 32))
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			svc := NewFieldService(
				&securityTestDEKService{statusVersion: tt.version},
				&securityTestAuditLogger{},
				zerolog.Nop(),
				"system",
				"",
			)
			field := &types.FieldEncrypted{Plaintext: "alice@example.test"}

			err := tt.run(securityTestContext(), svc, field)

			if err == nil {
				t.Fatal("expected unsafe DEK version to be rejected")
			}
			if !strings.Contains(err.Error(), "invalid active DEK version") {
				t.Fatalf("expected invalid active DEK version error, got %v", err)
			}
			if field.Ciphertext != "" {
				t.Fatalf("field was encrypted despite invalid version: %q", field.Ciphertext)
			}
		})
	}
}

func TestFieldServiceLogAuditEventHandlesLoggerErrors(t *testing.T) {
	svc := &fieldService{
		logger:  &securityTestAuditLogger{err: errors.New("audit sink unavailable")},
		zLogger: zerolog.Nop(),
	}
	event := &types.AuditEvent{
		EventType: "field.encrypt",
		Operation: "encrypt",
		Context:   map[string]string{},
	}

	if logged := svc.logAuditEvent(context.Background(), event); logged {
		t.Fatal("expected logAuditEvent to report false when audit logger fails")
	}
}

func TestDEKVersionToFieldVersionAcceptsValidVersions(t *testing.T) {
	got, err := dekVersionToFieldVersion(42)
	if err != nil {
		t.Fatalf("expected valid DEK version, got %v", err)
	}
	if got != 42 {
		t.Fatalf("expected field version 42, got %d", got)
	}
}

func TestDEKVersionToFieldVersionRejectsInvalidVersions(t *testing.T) {
	for _, version := range []int{0, -1, int(math.MaxUint32) + 1} {
		t.Run(fmt.Sprintf("version_%d", version), func(t *testing.T) {
			if _, err := dekVersionToFieldVersion(version); err == nil {
				t.Fatal("expected invalid DEK version to be rejected")
			}
		})
	}
}
