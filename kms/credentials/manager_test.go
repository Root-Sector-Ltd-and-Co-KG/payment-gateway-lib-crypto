package credentials

import (
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/root-sector-ltd-and-co-kg/payment-gateway-lib-crypto/kms"
	encTypes "github.com/root-sector-ltd-and-co-kg/payment-gateway-lib-crypto/types"
)

var credentialTestKey = []byte("0123456789abcdefghijklmnopqrstuv")

type fakeEncryptor struct {
	encrypt func(string) (string, error)
	decrypt func(string) (string, error)
}

func (f fakeEncryptor) Encrypt(data string) (string, error) {
	return f.encrypt(data)
}

func (f fakeEncryptor) Decrypt(data string) (string, error) {
	return f.decrypt(data)
}

func TestNewManagerRejectsInvalidKeys(t *testing.T) {
	tests := []struct {
		name string
		key  []byte
	}{
		{
			name: "too short",
			key:  []byte("short"),
		},
		{
			name: "insufficient entropy",
			key:  []byte("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			manager, err := NewManager(tt.key)
			if err == nil {
				t.Fatal("NewManager() error = nil, want an invalid-key error")
			}
			if manager != nil {
				t.Fatalf("NewManager() manager = %T, want nil", manager)
			}
		})
	}
}

func TestCredentialManagerRoundTrip(t *testing.T) {
	tests := []struct {
		name     string
		provider encTypes.ProviderType
		want     encTypes.KMSCredentials
	}{
		{
			name:     "AWS",
			provider: encTypes.ProviderAWS,
			want: encTypes.KMSCredentials{
				AccessKeyID:     "aws-access-key-id",
				SecretAccessKey: "aws-secret-access-key",
				SessionToken:    "aws-session-token",
			},
		},
		{
			name:     "Azure",
			provider: encTypes.ProviderAzure,
			want: encTypes.KMSCredentials{
				TenantID:     "azure-tenant-id",
				ClientID:     "azure-client-id",
				ClientSecret: "azure-client-secret",
			},
		},
		{
			name:     "GCP",
			provider: encTypes.ProviderGCP,
			want: encTypes.KMSCredentials{
				CredentialsJSON: `{"project_id":"gcp-project","private_key":"gcp-private-key"}`,
			},
		},
		{
			name:     "Vault",
			provider: encTypes.ProviderVault,
			want: encTypes.KMSCredentials{
				Token: "vault-token",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			manager, err := NewManager(credentialTestKey)
			if err != nil {
				t.Fatalf("NewManager() error = %v", err)
			}

			want := tt.want
			config := &encTypes.EncryptionConfig{
				Provider:    tt.provider,
				Credentials: &want,
			}
			if err := manager.EncryptCredentials(config); err != nil {
				t.Fatalf("EncryptCredentials() error = %v", err)
			}

			plaintext := reflect.ValueOf(tt.want)
			encrypted := reflect.ValueOf(*config.Credentials)
			credentialsType := plaintext.Type()
			for i := 0; i < plaintext.NumField(); i++ {
				plaintextValue := plaintext.Field(i).String()
				if plaintextValue == "" {
					continue
				}

				encryptedValue := encrypted.Field(i).String()
				if !strings.HasPrefix(encryptedValue, "ENC[") {
					t.Errorf("%s encrypted value = %q, want ENC[ prefix", credentialsType.Field(i).Name, encryptedValue)
				}
				if encryptedValue == plaintextValue {
					t.Errorf("%s encrypted value matches plaintext %q", credentialsType.Field(i).Name, plaintextValue)
				}
			}

			if err := manager.DecryptCredentials(config); err != nil {
				t.Fatalf("DecryptCredentials() error = %v", err)
			}
			if !reflect.DeepEqual(*config.Credentials, tt.want) {
				t.Errorf("round-trip credentials = %+v, want %+v", *config.Credentials, tt.want)
			}
		})
	}
}

func TestCredentialManagerMaskedValuesAreOmittedWithoutTransformation(t *testing.T) {
	maskedCredentials := []struct {
		name     string
		provider encTypes.ProviderType
		value    encTypes.KMSCredentials
	}{
		{
			name:     "AWS",
			provider: encTypes.ProviderAWS,
			value: encTypes.KMSCredentials{
				AccessKeyID:     maskedValue,
				SecretAccessKey: maskedValue,
				SessionToken:    maskedValue,
			},
		},
		{
			name:     "Azure",
			provider: encTypes.ProviderAzure,
			value: encTypes.KMSCredentials{
				TenantID:     maskedValue,
				ClientID:     maskedValue,
				ClientSecret: maskedValue,
			},
		},
		{
			name:     "GCP",
			provider: encTypes.ProviderGCP,
			value: encTypes.KMSCredentials{
				CredentialsJSON: maskedValue,
			},
		},
		{
			name:     "Vault",
			provider: encTypes.ProviderVault,
			value: encTypes.KMSCredentials{
				Token: maskedValue,
			},
		},
	}
	operations := []struct {
		name string
		run  func(*credentialManager, *encTypes.EncryptionConfig) error
	}{
		{
			name: "encrypt",
			run: func(manager *credentialManager, config *encTypes.EncryptionConfig) error {
				return manager.EncryptCredentials(config)
			},
		},
		{
			name: "decrypt",
			run: func(manager *credentialManager, config *encTypes.EncryptionConfig) error {
				return manager.DecryptCredentials(config)
			},
		},
	}

	for _, operation := range operations {
		for _, credentials := range maskedCredentials {
			t.Run(operation.name+"/"+credentials.name, func(t *testing.T) {
				manager := &credentialManager{
					encryptor: fakeEncryptor{
						encrypt: func(string) (string, error) {
							t.Fatal("Encrypt() called for a masked value")
							return "", nil
						},
						decrypt: func(string) (string, error) {
							t.Fatal("Decrypt() called for a masked value")
							return "", nil
						},
					},
				}
				value := credentials.value
				config := &encTypes.EncryptionConfig{
					Provider:    credentials.provider,
					Credentials: &value,
				}

				if err := operation.run(manager, config); err != nil {
					t.Fatalf("%s credentials error = %v", operation.name, err)
				}
				if config.Credentials == nil {
					t.Fatal("credentials = nil, want an empty credentials value")
				}
				if !reflect.DeepEqual(*config.Credentials, encTypes.KMSCredentials{}) {
					t.Errorf("credentials = %+v, want empty credentials", *config.Credentials)
				}
			})
		}
	}
}

func TestCredentialManagerRejectsUnsupportedProviderWithoutMutation(t *testing.T) {
	operations := []struct {
		name string
		run  func(*credentialManager, *encTypes.EncryptionConfig) error
	}{
		{
			name: "encrypt",
			run: func(manager *credentialManager, config *encTypes.EncryptionConfig) error {
				return manager.EncryptCredentials(config)
			},
		},
		{
			name: "decrypt",
			run: func(manager *credentialManager, config *encTypes.EncryptionConfig) error {
				return manager.DecryptCredentials(config)
			},
		},
	}

	for _, operation := range operations {
		t.Run(operation.name, func(t *testing.T) {
			manager := &credentialManager{
				encryptor: fakeEncryptor{
					encrypt: func(string) (string, error) {
						t.Fatal("Encrypt() called for an unsupported provider")
						return "", nil
					},
					decrypt: func(string) (string, error) {
						t.Fatal("Decrypt() called for an unsupported provider")
						return "", nil
					},
				},
			}
			credentials := &encTypes.KMSCredentials{
				AccessKeyID:     "original-access-key",
				SecretAccessKey: "original-secret-key",
			}
			originalPointer := credentials
			originalValue := *credentials
			config := &encTypes.EncryptionConfig{
				Provider:    encTypes.ProviderType("unsupported"),
				Credentials: credentials,
			}

			err := operation.run(manager, config)
			if err == nil {
				t.Fatalf("%s credentials error = nil, want unsupported-provider error", operation.name)
			}
			if !strings.Contains(err.Error(), "unsupported provider") {
				t.Errorf("%s credentials error = %q, want unsupported-provider error", operation.name, err)
			}
			if config.Credentials != originalPointer {
				t.Fatalf("credentials pointer changed from %p to %p", originalPointer, config.Credentials)
			}
			if !reflect.DeepEqual(*config.Credentials, originalValue) {
				t.Errorf("credentials = %+v, want unchanged %+v", *config.Credentials, originalValue)
			}
		})
	}
}

func TestCredentialManagerTransformationFailureDoesNotMutateConfig(t *testing.T) {
	injectedErr := errors.New("injected transform failure")
	operations := []struct {
		name string
		run  func(*credentialManager, *encTypes.EncryptionConfig) error
	}{
		{
			name: "encrypt",
			run: func(manager *credentialManager, config *encTypes.EncryptionConfig) error {
				return manager.EncryptCredentials(config)
			},
		},
		{
			name: "decrypt",
			run: func(manager *credentialManager, config *encTypes.EncryptionConfig) error {
				return manager.DecryptCredentials(config)
			},
		},
	}
	providers := []struct {
		name     string
		provider encTypes.ProviderType
		value    encTypes.KMSCredentials
		failAt   int
	}{
		{
			name:     "AWS",
			provider: encTypes.ProviderAWS,
			value: encTypes.KMSCredentials{
				AccessKeyID:     "original-access-key",
				SecretAccessKey: "original-secret-key",
				SessionToken:    "original-session-token",
			},
			failAt: 2,
		},
		{
			name:     "Azure",
			provider: encTypes.ProviderAzure,
			value: encTypes.KMSCredentials{
				TenantID:     "original-tenant-id",
				ClientID:     "original-client-id",
				ClientSecret: "original-client-secret",
			},
			failAt: 2,
		},
		{
			name:     "GCP",
			provider: encTypes.ProviderGCP,
			value: encTypes.KMSCredentials{
				CredentialsJSON: `{"project_id":"original-project"}`,
			},
			failAt: 1,
		},
		{
			name:     "Vault",
			provider: encTypes.ProviderVault,
			value: encTypes.KMSCredentials{
				Token: "original-vault-token",
			},
			failAt: 1,
		},
	}

	for _, operation := range operations {
		for _, provider := range providers {
			t.Run(operation.name+"/"+provider.name, func(t *testing.T) {
				transformations := 0
				transform := func(data string) (string, error) {
					transformations++
					if transformations == provider.failAt {
						return "", injectedErr
					}
					return "transformed-" + data, nil
				}
				manager := &credentialManager{
					encryptor: fakeEncryptor{
						encrypt: transform,
						decrypt: transform,
					},
				}
				credentials := provider.value
				originalPointer := &credentials
				originalValue := credentials
				config := &encTypes.EncryptionConfig{
					Provider:    provider.provider,
					Credentials: originalPointer,
				}

				err := operation.run(manager, config)
				if !errors.Is(err, injectedErr) {
					t.Fatalf("%s credentials error = %v, want %v", operation.name, err, injectedErr)
				}
				if transformations != provider.failAt {
					t.Errorf("transformations = %d, want %d", transformations, provider.failAt)
				}
				if config.Credentials != originalPointer {
					t.Fatalf("credentials pointer changed from %p to %p", originalPointer, config.Credentials)
				}
				if !reflect.DeepEqual(*config.Credentials, originalValue) {
					t.Errorf("credentials = %+v, want unchanged %+v", *config.Credentials, originalValue)
				}
			})
		}
	}
}

func TestToKMSConfig(t *testing.T) {
	// Sample input EncryptionConfig data
	awsInput := &encTypes.EncryptionConfig{
		Provider: encTypes.ProviderAWS,
		KeyID:    "aws-arn",
		Region:   "us-west-2",
		Credentials: &encTypes.KMSCredentials{
			AccessKeyID:     "AKIA...",
			SecretAccessKey: "SECRET...",
		},
	}
	azureInput := &encTypes.EncryptionConfig{
		Provider:     encTypes.ProviderAzure,
		KeyID:        "https://a.vault.azure.net/k/b/c",
		VaultAddress: "https://a.vault.azure.net",
		Credentials: &encTypes.KMSCredentials{
			TenantID:     "TENANT",
			ClientID:     "CLIENT",
			ClientSecret: "SECRET",
		},
	}
	gcpInput := &encTypes.EncryptionConfig{
		Provider: encTypes.ProviderGCP,
		KeyID:    "projects/p/locations/l/keyRings/r/cryptoKeys/k", // ResourceName stored in KeyID
		// Region and KeyRing are deprecated/removed from EncryptionConfig
		Credentials: &encTypes.KMSCredentials{
			CredentialsJSON: `{"project_id":"p"}`,
		},
	}
	vaultInput := &encTypes.EncryptionConfig{
		Provider:     encTypes.ProviderVault,
		KeyID:        "vault-key-name",
		VaultAddress: "https://v.example.com",
		VaultMount:   "transit",
		Credentials: &encTypes.KMSCredentials{
			Token: "VAULT_TOKEN",
		},
	}

	// Expected output kms.Config data
	expectedAWS := kms.Config{
		Type: encTypes.ProviderAWS,
		AWS: &kms.AWSConfig{
			KeyID:  "aws-arn",
			Region: "us-west-2",
			Credentials: map[string]interface{}{
				"accessKeyId":     "AKIA...",
				"secretAccessKey": "SECRET...",
			},
		},
	}
	expectedAzure := kms.Config{
		Type: encTypes.ProviderAzure,
		Azure: &kms.AzureConfig{
			KeyID:        "https://a.vault.azure.net/k/b/c",
			VaultAddress: "https://a.vault.azure.net",
			Credentials: map[string]interface{}{
				"tenantId":     "TENANT",
				"clientId":     "CLIENT",
				"clientSecret": "SECRET",
			},
		},
	}
	expectedGCP := kms.Config{
		Type: encTypes.ProviderGCP,
		GCP: &kms.GCPConfig{
			ResourceName: "projects/p/locations/l/keyRings/r/cryptoKeys/k",
			Credentials: map[string]interface{}{
				"credentialsJson": `{"project_id":"p"}`,
			},
		},
	}
	expectedVault := kms.Config{
		Type: encTypes.ProviderVault,
		Vault: &kms.VaultConfig{
			KeyID:        "vault-key-name",
			VaultAddress: "https://v.example.com",
			VaultMount:   "transit",
			Credentials: map[string]interface{}{
				"token": "VAULT_TOKEN",
			},
		},
	}

	tests := []struct {
		name     string
		input    *encTypes.EncryptionConfig
		expected kms.Config
	}{
		{
			name:     "AWS Conversion",
			input:    awsInput,
			expected: expectedAWS,
		},
		{
			name:     "Azure Conversion",
			input:    azureInput,
			expected: expectedAzure,
		},
		{
			name:     "GCP Conversion",
			input:    gcpInput,
			expected: expectedGCP,
		},
		{
			name:     "Vault Conversion",
			input:    vaultInput,
			expected: expectedVault,
		},
		{
			name:     "Nil Input",
			input:    nil,
			expected: kms.Config{}, // Expect empty config
		},
		{
			name: "Unsupported Provider",
			input: &encTypes.EncryptionConfig{
				Provider: "unknown",
				KeyID:    "some-key",
			},
			expected: kms.Config{Type: "unknown"}, // Only type should be set
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := toKMSConfig(tt.input)
			// Use reflect.DeepEqual for comparing nested structs and maps
			if !reflect.DeepEqual(result, tt.expected) {
				t.Errorf("toKMSConfig() = %+v, want %+v", result, tt.expected)
				// Log specific differences for easier debugging
				if result.Type != tt.expected.Type {
					t.Errorf("Type mismatch: got %v, want %v", result.Type, tt.expected.Type)
				}
				if !reflect.DeepEqual(result.AWS, tt.expected.AWS) {
					t.Errorf("AWS config mismatch: got %+v, want %+v", result.AWS, tt.expected.AWS)
				}
				if !reflect.DeepEqual(result.Azure, tt.expected.Azure) {
					t.Errorf("Azure config mismatch: got %+v, want %+v", result.Azure, tt.expected.Azure)
				}
				if !reflect.DeepEqual(result.GCP, tt.expected.GCP) {
					t.Errorf("GCP config mismatch: got %+v, want %+v", result.GCP, tt.expected.GCP)
				}
				if !reflect.DeepEqual(result.Vault, tt.expected.Vault) {
					t.Errorf("Vault config mismatch: got %+v, want %+v", result.Vault, tt.expected.Vault)
				}
			}
		})
	}
}
