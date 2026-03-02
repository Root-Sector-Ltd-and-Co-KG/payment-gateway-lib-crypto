package kms

import (
	"strings"
	"testing"

	encTypes "github.com/root-sector-ltd-and-co-kg/payment-gateway-lib-crypto/types"
)

// --- Test Cases for Validation Functions ---

func TestValidateAWSConfig(t *testing.T) {
	tests := []struct {
		name      string
		config    AWSConfig
		expectErr bool
		errSubstr string // Substring expected in the error message
	}{
		{
			name: "Valid AWS Config",
			config: AWSConfig{
				KeyID:  "arn:aws:kms:us-east-1:123456789012:key/valid-key-id",
				Region: "us-east-1",
				Credentials: map[string]interface{}{
					"accessKeyId":     "ACCESSKEY",
					"secretAccessKey": "SECRETKEY",
				},
			},
			expectErr: false,
		},
		{
			name: "Valid AWS Config (No Credentials)",
			config: AWSConfig{
				KeyID:  "arn:aws:kms:us-east-1:123456789012:key/valid-key-id",
				Region: "us-east-1",
			},
			expectErr: false, // Credentials are optional
		},
		{
			name: "Missing KeyID",
			config: AWSConfig{
				Region: "us-east-1",
			},
			expectErr: true,
			errSubstr: "key ID (ARN) is required",
		},
		{
			name: "Missing Region",
			config: AWSConfig{
				KeyID: "arn:aws:kms:us-east-1:123456789012:key/valid-key-id",
			},
			expectErr: true,
			errSubstr: "region is required",
		},
		{
			name: "Missing Secret Key",
			config: AWSConfig{
				KeyID:  "arn:aws:kms:us-east-1:123456789012:key/valid-key-id",
				Region: "us-east-1",
				Credentials: map[string]interface{}{
					"accessKeyId": "ACCESSKEY",
				},
			},
			expectErr: true,
			errSubstr: "both accessKeyId and secretAccessKey must be provided",
		},
		{
			name: "Missing Access Key",
			config: AWSConfig{
				KeyID:  "arn:aws:kms:us-east-1:123456789012:key/valid-key-id",
				Region: "us-east-1",
				Credentials: map[string]interface{}{
					"secretAccessKey": "SECRETKEY",
				},
			},
			expectErr: true,
			errSubstr: "both accessKeyId and secretAccessKey must be provided",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateAWSConfig(tt.config)
			if tt.expectErr {
				if err == nil {
					t.Errorf("expected an error but got nil")
				} else if tt.errSubstr != "" && !strings.Contains(err.Error(), tt.errSubstr) {
					t.Errorf("expected error containing %q, got %q", tt.errSubstr, err.Error())
				}
			} else if err != nil {
				t.Errorf("expected no error but got: %v", err)
			}
		})
	}
}

func TestValidateAzureConfig(t *testing.T) {
	tests := []struct {
		name      string
		config    AzureConfig
		expectErr bool
		errSubstr string
	}{
		{
			name: "Valid Azure Config",
			config: AzureConfig{
				KeyID:        "https://myvault.vault.azure.net/keys/mykey/version",
				VaultAddress: "https://myvault.vault.azure.net",
				Credentials: map[string]interface{}{
					"tenantId":     "TENANT",
					"clientId":     "CLIENT",
					"clientSecret": "SECRET",
				},
			},
			expectErr: false,
		},
		{
			name: "Valid Azure Config (No Credentials - MSI)",
			config: AzureConfig{
				KeyID:        "https://myvault.vault.azure.net/keys/mykey/version",
				VaultAddress: "https://myvault.vault.azure.net",
			},
			expectErr: false, // Credentials optional
		},
		{
			name: "Missing KeyID",
			config: AzureConfig{
				VaultAddress: "https://myvault.vault.azure.net",
			},
			expectErr: true,
			errSubstr: "key ID (URL) is required",
		},
		{
			name: "Missing Vault Address",
			config: AzureConfig{
				KeyID: "https://myvault.vault.azure.net/keys/mykey/version",
			},
			expectErr: true,
			errSubstr: "vault address must be a valid Azure Key Vault URL",
		},
		{
			name: "Invalid Vault Address Format",
			config: AzureConfig{
				KeyID:        "https://myvault.vault.azure.net/keys/mykey/version",
				VaultAddress: "myvault", // Invalid format
			},
			expectErr: true,
			errSubstr: "vault address must be a valid Azure Key Vault URL",
		},
		{
			name: "Missing Tenant ID",
			config: AzureConfig{
				KeyID:        "https://myvault.vault.azure.net/keys/mykey/version",
				VaultAddress: "https://myvault.vault.azure.net",
				Credentials: map[string]interface{}{
					"clientId":     "CLIENT",
					"clientSecret": "SECRET",
				},
			},
			expectErr: true,
			errSubstr: "tenantId is required in credentials",
		},
		{
			name: "Empty Client Secret",
			config: AzureConfig{
				KeyID:        "https://myvault.vault.azure.net/keys/mykey/version",
				VaultAddress: "https://myvault.vault.azure.net",
				Credentials: map[string]interface{}{
					"tenantId":     "TENANT",
					"clientId":     "CLIENT",
					"clientSecret": "", // Empty
				},
			},
			expectErr: true,
			errSubstr: "clientSecret is required in credentials and cannot be empty",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateAzureConfig(tt.config)
			if tt.expectErr {
				if err == nil {
					t.Errorf("expected an error but got nil")
				} else if tt.errSubstr != "" && !strings.Contains(err.Error(), tt.errSubstr) {
					t.Errorf("expected error containing %q, got %q", tt.errSubstr, err.Error())
				}
			} else if err != nil {
				t.Errorf("expected no error but got: %v", err)
			}
		})
	}
}

func TestValidateGCPConfig(t *testing.T) {
	validCredsJSON := `{"type": "service_account", "project_id": "test-project"}`
	invalidCredsJSON := `{"type": "service_account"}` // Missing project_id

	tests := []struct {
		name      string
		config    GCPConfig
		expectErr bool
		errSubstr string
	}{
		{
			name: "Valid GCP Config",
			config: GCPConfig{
				ResourceName: "projects/test-project/locations/global/keyRings/test-ring/cryptoKeys/test-key",
				Credentials: map[string]interface{}{
					"credentialsJson": validCredsJSON,
				},
			},
			expectErr: false,
		},
		{
			name: "Missing ResourceName",
			config: GCPConfig{
				Credentials: map[string]interface{}{
					"credentialsJson": validCredsJSON,
				},
			},
			expectErr: true,
			errSubstr: "resource name is required",
		},
		{
			name: "Invalid ResourceName Format (Short)",
			config: GCPConfig{
				ResourceName: "projects/test-project/locations/global",
				Credentials: map[string]interface{}{
					"credentialsJson": validCredsJSON,
				},
			},
			expectErr: true,
			errSubstr: "invalid resource name format",
		},
		{
			name: "Invalid ResourceName Format (Wrong Parts)",
			config: GCPConfig{
				ResourceName: "projects/test-project/regions/global/keyrings/test-ring/keys/test-key",
				Credentials: map[string]interface{}{
					"credentialsJson": validCredsJSON,
				},
			},
			expectErr: true,
			errSubstr: "invalid resource name format",
		},
		{
			name: "Empty Component in ResourceName",
			config: GCPConfig{
				ResourceName: "projects//locations/global/keyRings/test-ring/cryptoKeys/test-key", // Empty project
				Credentials: map[string]interface{}{
					"credentialsJson": validCredsJSON,
				},
			},
			expectErr: true,
			errSubstr: "components in resource name cannot be empty",
		},
		{
			name: "Missing Credentials (ADC mode)",
			config: GCPConfig{
				ResourceName: "projects/test-project/locations/global/keyRings/test-ring/cryptoKeys/test-key",
			},
			expectErr: false, // nil Credentials map means ADC is expected
		},
		{
			name: "Missing credentialsJson Key",
			config: GCPConfig{
				ResourceName: "projects/test-project/locations/global/keyRings/test-ring/cryptoKeys/test-key",
				Credentials:  map[string]interface{}{}, // Empty map
			},
			expectErr: true,
			errSubstr: "credentialsJson is required in credentials map",
		},
		{
			name: "Empty credentialsJson Value",
			config: GCPConfig{
				ResourceName: "projects/test-project/locations/global/keyRings/test-ring/cryptoKeys/test-key",
				Credentials: map[string]interface{}{
					"credentialsJson": "", // Empty string
				},
			},
			expectErr: true,
			errSubstr: "credentialsJson is required in credentials map and cannot be empty",
		},
		{
			name: "Valid Config (Credentials JSON missing project_id - Warning expected)",
			config: GCPConfig{
				ResourceName: "projects/test-project/locations/global/keyRings/test-ring/cryptoKeys/test-key",
				Credentials: map[string]interface{}{
					"credentialsJson": invalidCredsJSON,
				},
			},
			expectErr: false, // Validation should pass, warning logged
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Note: We can't easily test the log warning here, just the error return
			err := validateGCPConfig(tt.config)
			if tt.expectErr {
				if err == nil {
					t.Errorf("expected an error but got nil")
				} else if tt.errSubstr != "" && !strings.Contains(err.Error(), tt.errSubstr) {
					t.Errorf("expected error containing %q, got %q", tt.errSubstr, err.Error())
				}
			} else if err != nil {
				t.Errorf("expected no error but got: %v", err)
			}
		})
	}
}

func TestValidateVaultConfig(t *testing.T) {
	tests := []struct {
		name      string
		config    VaultConfig
		expectErr bool
		errSubstr string
	}{
		{
			name: "Valid Vault Config",
			config: VaultConfig{
				KeyID:        "my-vault-key",
				VaultAddress: "https://vault.example.com:8200",
				VaultMount:   "transit",
				Credentials: map[string]interface{}{
					"token": "VAULT_TOKEN",
				},
			},
			expectErr: false,
		},
		{
			name: "Valid Vault Config (No Credentials - Env Auth)",
			config: VaultConfig{
				KeyID:        "my-vault-key",
				VaultAddress: "https://vault.example.com:8200",
				VaultMount:   "transit",
			},
			expectErr: false, // Credentials optional
		},
		{
			name: "Valid Vault Config (No Mount Path - Default)",
			config: VaultConfig{
				KeyID:        "my-vault-key",
				VaultAddress: "https://vault.example.com:8200",
				Credentials: map[string]interface{}{
					"token": "VAULT_TOKEN",
				},
			},
			expectErr: false, // Mount path optional
		},
		{
			name: "Missing KeyID",
			config: VaultConfig{
				VaultAddress: "https://vault.example.com:8200",
			},
			expectErr: true,
			errSubstr: "key ID (key name) is required",
		},
		{
			name: "Missing Vault Address",
			config: VaultConfig{
				KeyID: "my-vault-key",
			},
			expectErr: true,
			errSubstr: "vault address is required",
		},
		{
			name: "Missing Token Key",
			config: VaultConfig{
				KeyID:        "my-vault-key",
				VaultAddress: "https://vault.example.com:8200",
				Credentials:  map[string]interface{}{}, // Empty map
			},
			expectErr: true,
			errSubstr: "token is required in credentials map",
		},
		{
			name: "Empty Token Value",
			config: VaultConfig{
				KeyID:        "my-vault-key",
				VaultAddress: "https://vault.example.com:8200",
				Credentials: map[string]interface{}{
					"token": "", // Empty string
				},
			},
			expectErr: true,
			errSubstr: "token is required in credentials map and cannot be empty",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateVaultConfig(tt.config)
			if tt.expectErr {
				if err == nil {
					t.Errorf("expected an error but got nil")
				} else if tt.errSubstr != "" && !strings.Contains(err.Error(), tt.errSubstr) {
					t.Errorf("expected error containing %q, got %q", tt.errSubstr, err.Error())
				}
			} else if err != nil {
				t.Errorf("expected no error but got: %v", err)
			}
		})
	}
}

// --- TODO: Add Tests for create*Wrapper functions ---
// These tests would ideally mock the SetConfig call or inspect the configMap.
// --- Test Cases for NewProvider ---

// Mock Wrapper for testing NewProvider error propagation (optional, complex)
// type mockWrapper struct {
// 	wrapping.Wrapper // Embed to satisfy interface easily
// 	setConfigError error
// 	encryptError   error
// 	decryptError   error
// }
//
// func (m *mockWrapper) SetConfig(ctx context.Context, opt ...wrapping.Option) (*wrapping.WrapperConfig, error) {
// 	if m.setConfigError != nil {
// 		return nil, m.setConfigError
// 	}
// 	return &wrapping.WrapperConfig{}, nil
// }
// func (m *mockWrapper) Encrypt(ctx context.Context, plaintext []byte, opt ...wrapping.Option) (*wrapping.BlobInfo, error) {
// 	return nil, m.encryptError
// }
// func (m *mockWrapper) Decrypt(ctx context.Context, in *wrapping.BlobInfo, opt ...wrapping.Option) ([]byte, error) {
// 	return nil, m.decryptError
// }
// func (m *mockWrapper) Type(ctx context.Context) (wrapping.WrapperType, error) {
// 	return wrapping.WrapperTypeGcpCkms, nil // Example type
// }
// func (m *mockWrapper) KeyId(ctx context.Context) (string, error) {
// 	return "mock-key-id", nil
// }

func TestNewProvider(t *testing.T) {
	// Basic valid configs for each type (details don't matter much here, just non-nil)
	validAWSConfig := &AWSConfig{KeyID: "aws-key", Region: "us-east-1"}
	validAzureConfig := &AzureConfig{KeyID: "https://a.vault.azure.net/k/b/c", VaultAddress: "https://a.vault.azure.net"}
	validGCPConfig := &GCPConfig{ResourceName: "projects/p/locations/l/keyRings/r/cryptoKeys/k", Credentials: map[string]interface{}{"credentialsJson": `{"project_id":"p"}`}}
	validVaultConfig := &VaultConfig{KeyID: "vault-key", VaultAddress: "https://v.example.com"}

	tests := []struct {
		name      string
		config    Config
		expectErr bool
		errSubstr string
	}{
		{
			name: "Valid AWS Provider",
			config: Config{
				Type: encTypes.ProviderAWS,
				AWS:  validAWSConfig,
			},
			expectErr: false, // Expect no error *from NewProvider's initial checks*
		},
		{
			name: "Valid Azure Provider",
			config: Config{
				Type:  encTypes.ProviderAzure,
				Azure: validAzureConfig,
			},
			expectErr: false, // Expect no error *from NewProvider's initial checks*
		},
		{
			name: "Valid GCP Provider",
			config: Config{
				Type: encTypes.ProviderGCP,
				GCP:  validGCPConfig,
			},
			expectErr: false, // Expect no error *from NewProvider's initial checks*
		},
		{
			name: "Valid GCP Provider (No Credentials - ADC)",
			config: Config{
				Type: encTypes.ProviderGCP,
				GCP: &GCPConfig{
					ResourceName: "projects/p/locations/l/keyRings/r/cryptoKeys/k",
				},
			},
			expectErr: false, // Validation should pass; wrapper setup may still fail if ADC is unavailable
		},
		{
			name: "Valid Vault Provider",
			config: Config{
				Type:  encTypes.ProviderVault,
				Vault: validVaultConfig,
			},
			expectErr: false, // Expect no error *from NewProvider's initial checks*
		},
		{
			name: "Unsupported Provider Type",
			config: Config{
				Type: "unknown",
			},
			expectErr: true,
			errSubstr: "unsupported KMS provider type",
		},
		{
			name: "Missing AWS Config Struct",
			config: Config{
				Type: encTypes.ProviderAWS,
				AWS:  nil, // Missing struct
			},
			expectErr: true,
			errSubstr: "AWS configuration is missing",
		},
		{
			name: "Missing Azure Config Struct",
			config: Config{
				Type:  encTypes.ProviderAzure,
				Azure: nil,
			},
			expectErr: true,
			errSubstr: "azure configuration is missing", // Match actual error message case
		},
		{
			name: "Missing GCP Config Struct",
			config: Config{
				Type: encTypes.ProviderGCP,
				GCP:  nil,
			},
			expectErr: true,
			errSubstr: "GCP configuration is missing",
		},
		{
			name: "Missing Vault Config Struct",
			config: Config{
				Type:  encTypes.ProviderVault,
				Vault: nil,
			},
			expectErr: true,
			errSubstr: "vault configuration is missing", // Match actual error message case
		},
		{
			name: "Invalid AWS Config (Validation Error)",
			config: Config{
				Type: encTypes.ProviderAWS,
				AWS:  &AWSConfig{Region: "us-east-1"}, // Missing KeyID
			},
			expectErr: true,
			errSubstr: "invalid AWS KMS configuration", // Error from NewProvider wrapping validation error
		},
		{
			name: "Invalid GCP Config (Validation Error)",
			config: Config{
				Type: encTypes.ProviderGCP,
				GCP:  &GCPConfig{ResourceName: "invalid-format"}, // Invalid ResourceName
			},
			expectErr: true,
			errSubstr: "invalid GCP KMS configuration",
		},
		// Note: Testing error propagation from create*Wrapper requires mocking,
		// which is complex here. These tests focus on NewProvider's own logic.
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// We don't need the provider instance itself, just the error
			_, err := NewProvider(tt.config)

			if tt.expectErr {
				// If we expect an error (e.g., missing config struct, validation fail)
				if err == nil {
					t.Errorf("expected an error but got nil")
				} else if tt.errSubstr != "" && !strings.Contains(err.Error(), tt.errSubstr) {
					t.Errorf("expected error containing %q, got %q", tt.errSubstr, err.Error())
				}
				// If err is not nil and matches substring (or no substring check), it passes.
			} else {
				// If we don't expect an error *from NewProvider's initial checks*
				// Allow errors that originate from the downstream create*Wrapper calls
				if err != nil && !(strings.Contains(err.Error(), "failed to configure") || strings.Contains(err.Error(), "failed to create wrapper")) {
					// Fail only if the error is *not* from the downstream calls
					t.Errorf("expected no initial config error, but got: %v", err)
				}
				// If err is nil or relates to wrapper configuration/creation, the initial part passed.
			}
		})
	}
}

// For now, we focus on validation and NewProvider logic.

// --- TODO: Add Tests for NewProvider function ---
// These tests would check error handling for missing sub-configs and error propagation.
