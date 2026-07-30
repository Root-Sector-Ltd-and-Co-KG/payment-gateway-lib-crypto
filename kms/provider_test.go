package kms

import (
	"context"
	"encoding/base64"
	"errors"
	"os"
	"reflect"
	"strings"
	"testing"

	wrapping "github.com/hashicorp/go-kms-wrapping/v2"
	encTypes "github.com/root-sector-ltd-and-co-kg/payment-gateway-lib-crypto/types"
)

type captureWrapper struct {
	*wrapping.TestWrapper
	configMap      map[string]string
	setConfigError error
	onSetConfig    func(map[string]string)
}

func (w *captureWrapper) SetConfig(_ context.Context, options ...wrapping.Option) (*wrapping.WrapperConfig, error) {
	opts, err := wrapping.GetOpts(options...)
	if err != nil {
		return nil, err
	}
	w.configMap = opts.WithConfigMap
	if w.onSetConfig != nil {
		w.onSetConfig(w.configMap)
	}
	if w.setConfigError != nil {
		return nil, w.setConfigError
	}
	return &wrapping.WrapperConfig{}, nil
}

func replaceWrapperFactory(t *testing.T, target *func() wrapping.Wrapper, replacement func() wrapping.Wrapper) {
	t.Helper()
	original := *target
	*target = replacement
	t.Cleanup(func() {
		*target = original
	})
}

func assertConfigMap(t *testing.T, got, want map[string]string) {
	t.Helper()
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("unexpected wrapper configuration: got %#v, want %#v", got, want)
	}
}

func TestCreateAWSWrapperConfiguresLocalWrapper(t *testing.T) {
	capture := &captureWrapper{TestWrapper: wrapping.NewTestWrapper([]byte("offline-test-secret"))}
	replaceWrapperFactory(t, &newAWSWrapper, func() wrapping.Wrapper { return capture })

	got, err := createAWSWrapper(AWSConfig{
		KeyID:  "arn:aws:kms:eu-central-1:123456789012:key/payment-key",
		Region: "eu-central-1",
		Credentials: map[string]interface{}{
			"accessKeyId":     "test-access-key",
			"secretAccessKey": "test-secret-key",
			"sessionToken":    "test-session-token",
		},
	})
	if err != nil {
		t.Fatalf("createAWSWrapper returned an error: %v", err)
	}
	if got != capture {
		t.Fatalf("createAWSWrapper returned %T, want capture wrapper", got)
	}
	assertConfigMap(t, capture.configMap, map[string]string{
		"kms_key_id":    "arn:aws:kms:eu-central-1:123456789012:key/payment-key",
		"region":        "eu-central-1",
		"access_key":    "test-access-key",
		"secret_key":    "test-secret-key",
		"session_token": "test-session-token",
	})
}

func TestCreateAzureWrapperConfiguresLocalWrapper(t *testing.T) {
	capture := &captureWrapper{TestWrapper: wrapping.NewTestWrapper([]byte("offline-test-secret"))}
	replaceWrapperFactory(t, &newAzureWrapper, func() wrapping.Wrapper { return capture })

	got, err := createAzureWrapper(AzureConfig{
		KeyID:        "https://payments.vault.azure.net/keys/payment-key/0123456789",
		VaultAddress: "https://payments.vault.azure.net",
		Credentials: map[string]interface{}{
			"tenantId":     "test-tenant",
			"clientId":     "test-client",
			"clientSecret": "test-client-secret",
		},
	})
	if err != nil {
		t.Fatalf("createAzureWrapper returned an error: %v", err)
	}
	if got != capture {
		t.Fatalf("createAzureWrapper returned %T, want capture wrapper", got)
	}
	assertConfigMap(t, capture.configMap, map[string]string{
		"key_name":      "payment-key",
		"key_version":   "0123456789",
		"vault_name":    "payments",
		"vault_url":     "https://payments.vault.azure.net",
		"tenant_id":     "test-tenant",
		"client_id":     "test-client",
		"client_secret": "test-client-secret",
	})
}

func TestCreateGCPWrapperConfiguresLocalWrapperAndRemovesCredentialsFile(t *testing.T) {
	const credentialsJSON = `{"type":"service_account","project_id":"payments-test"}`

	var (
		credentialsPath    string
		credentialsContent []byte
		credentialsMode    os.FileMode
		inspectionErr      error
	)
	capture := &captureWrapper{
		TestWrapper: wrapping.NewTestWrapper([]byte("offline-test-secret")),
		onSetConfig: func(configMap map[string]string) {
			credentialsPath = configMap["credentials"]
			credentialsContent, inspectionErr = os.ReadFile(credentialsPath)
			if inspectionErr != nil {
				return
			}
			info, err := os.Stat(credentialsPath)
			if err != nil {
				inspectionErr = err
				return
			}
			credentialsMode = info.Mode().Perm()
		},
	}
	replaceWrapperFactory(t, &newGCPWrapper, func() wrapping.Wrapper { return capture })

	got, err := createGCPWrapper(GCPConfig{
		ResourceName: "projects/payments-test/locations/europe-west3/keyRings/payment-ring/cryptoKeys/payment-key",
		Credentials: map[string]interface{}{
			"credentialsJson": credentialsJSON,
		},
	})
	if err != nil {
		t.Fatalf("createGCPWrapper returned an error: %v", err)
	}
	if got != capture {
		t.Fatalf("createGCPWrapper returned %T, want capture wrapper", got)
	}
	if inspectionErr != nil {
		t.Fatalf("could not inspect temporary credentials file during SetConfig: %v", inspectionErr)
	}
	if string(credentialsContent) != credentialsJSON {
		t.Fatalf("temporary credentials contents = %q, want %q", credentialsContent, credentialsJSON)
	}
	if credentialsMode != 0600 {
		t.Fatalf("temporary credentials permissions = %04o, want 0600", credentialsMode)
	}
	assertConfigMap(t, capture.configMap, map[string]string{
		"project":     "payments-test",
		"region":      "europe-west3",
		"key_ring":    "payment-ring",
		"crypto_key":  "payment-key",
		"credentials": credentialsPath,
	})
	if _, err := os.Stat(credentialsPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("temporary credentials file still exists after construction: %v", err)
	}
}

func TestCreateVaultWrapperConfiguresLocalWrapper(t *testing.T) {
	capture := &captureWrapper{TestWrapper: wrapping.NewTestWrapper([]byte("offline-test-secret"))}
	replaceWrapperFactory(t, &newVaultWrapper, func() wrapping.Wrapper { return capture })

	got, err := createVaultWrapper(VaultConfig{
		KeyID:        "payment-key",
		VaultAddress: "https://vault.example.test:8200",
		VaultMount:   "payments",
		Credentials: map[string]interface{}{
			"token": "test-vault-token",
		},
	})
	if err != nil {
		t.Fatalf("createVaultWrapper returned an error: %v", err)
	}
	if got != capture {
		t.Fatalf("createVaultWrapper returned %T, want capture wrapper", got)
	}
	assertConfigMap(t, capture.configMap, map[string]string{
		"address":    "https://vault.example.test:8200",
		"key_name":   "payment-key",
		"mount_path": "payments",
		"token":      "test-vault-token",
	})
}

func TestCreateProviderWrappersPropagateSetConfigErrors(t *testing.T) {
	setConfigError := errors.New("offline SetConfig failure")
	tests := []struct {
		name        string
		factory     *func() wrapping.Wrapper
		create      func() error
		errorPrefix string
	}{
		{
			name:    "AWS",
			factory: &newAWSWrapper,
			create: func() error {
				_, err := createAWSWrapper(AWSConfig{KeyID: "aws-key", Region: "eu-central-1"})
				return err
			},
			errorPrefix: "failed to configure AWS KMS wrapper",
		},
		{
			name:    "Azure",
			factory: &newAzureWrapper,
			create: func() error {
				_, err := createAzureWrapper(AzureConfig{
					KeyID:        "https://payments.vault.azure.net/keys/payment-key/version",
					VaultAddress: "https://payments.vault.azure.net",
				})
				return err
			},
			errorPrefix: "failed to configure Azure Key Vault wrapper",
		},
		{
			name:    "GCP",
			factory: &newGCPWrapper,
			create: func() error {
				_, err := createGCPWrapper(GCPConfig{
					ResourceName: "projects/payments-test/locations/europe-west3/keyRings/payment-ring/cryptoKeys/payment-key",
				})
				return err
			},
			errorPrefix: "failed to configure GCP KMS wrapper",
		},
		{
			name:    "Vault",
			factory: &newVaultWrapper,
			create: func() error {
				_, err := createVaultWrapper(VaultConfig{
					KeyID:        "payment-key",
					VaultAddress: "https://vault.example.test:8200",
				})
				return err
			},
			errorPrefix: "failed to configure Vault Transit wrapper",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			capture := &captureWrapper{
				TestWrapper:    wrapping.NewTestWrapper([]byte("offline-test-secret")),
				setConfigError: setConfigError,
			}
			replaceWrapperFactory(t, tt.factory, func() wrapping.Wrapper { return capture })

			err := tt.create()
			if !errors.Is(err, setConfigError) {
				t.Fatalf("create wrapper error = %v, want wrapped SetConfig error", err)
			}
			if !strings.Contains(err.Error(), tt.errorPrefix) {
				t.Fatalf("create wrapper error = %q, want prefix %q", err, tt.errorPrefix)
			}
		})
	}
}

func TestNewProviderConstructsConfiguredProviderWithoutExternalCalls(t *testing.T) {
	tests := []struct {
		name       string
		factory    *func() wrapping.Wrapper
		config     Config
		wantConfig map[string]string
	}{
		{
			name:    "AWS",
			factory: &newAWSWrapper,
			config: Config{
				Type: encTypes.ProviderAWS,
				AWS: &AWSConfig{
					KeyID:  "arn:aws:kms:eu-central-1:123456789012:key/payment-key",
					Region: "eu-central-1",
				},
			},
			wantConfig: map[string]string{
				"kms_key_id": "arn:aws:kms:eu-central-1:123456789012:key/payment-key",
				"region":     "eu-central-1",
			},
		},
		{
			name:    "Azure",
			factory: &newAzureWrapper,
			config: Config{
				Type: encTypes.ProviderAzure,
				Azure: &AzureConfig{
					KeyID:        "https://payments.vault.azure.net/keys/payment-key/0123456789",
					VaultAddress: "https://payments.vault.azure.net",
				},
			},
			wantConfig: map[string]string{
				"key_name":    "payment-key",
				"key_version": "0123456789",
				"vault_name":  "payments",
				"vault_url":   "https://payments.vault.azure.net",
			},
		},
		{
			name:    "GCP",
			factory: &newGCPWrapper,
			config: Config{
				Type: encTypes.ProviderGCP,
				GCP: &GCPConfig{
					ResourceName: "projects/payments-test/locations/europe-west3/keyRings/payment-ring/cryptoKeys/payment-key",
				},
			},
			wantConfig: map[string]string{
				"project":    "payments-test",
				"region":     "europe-west3",
				"key_ring":   "payment-ring",
				"crypto_key": "payment-key",
			},
		},
		{
			name:    "Vault",
			factory: &newVaultWrapper,
			config: Config{
				Type: encTypes.ProviderVault,
				Vault: &VaultConfig{
					KeyID:        "payment-key",
					VaultAddress: "https://vault.example.test:8200",
					VaultMount:   "payments",
				},
			},
			wantConfig: map[string]string{
				"address":    "https://vault.example.test:8200",
				"key_name":   "payment-key",
				"mount_path": "payments",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			capture := &captureWrapper{TestWrapper: wrapping.NewTestWrapper([]byte("offline-test-secret"))}
			replaceWrapperFactory(t, tt.factory, func() wrapping.Wrapper { return capture })

			got, err := NewProvider(tt.config)
			if err != nil {
				t.Fatalf("NewProvider returned an error: %v", err)
			}
			if got.GetWrapper() != capture {
				t.Fatalf("NewProvider wrapper = %T, want capture wrapper", got.GetWrapper())
			}
			assertConfigMap(t, capture.configMap, tt.wantConfig)
		})
	}
}

func TestNewProviderAEADRoundTrip(t *testing.T) {
	ctx := context.Background()
	key := []byte("0123456789abcdef0123456789abcdef")
	got, err := NewProvider(Config{
		Type:          encTypes.ProviderAead,
		AeadKeyID:     "local-payment-key",
		AeadKeyBase64: base64.StdEncoding.EncodeToString(key),
	})
	if err != nil {
		t.Fatalf("NewProvider returned an error: %v", err)
	}
	if err := got.Test(ctx); err != nil {
		t.Fatalf("AEAD provider round trip failed: %v", err)
	}
	keyID, err := got.GetWrapper().KeyId(ctx)
	if err != nil {
		t.Fatalf("AEAD wrapper KeyId returned an error: %v", err)
	}
	if keyID != "local-payment-key" {
		t.Fatalf("AEAD wrapper key ID = %q, want %q", keyID, "local-payment-key")
	}
}

func TestNewProviderRejectsInvalidAEADConfig(t *testing.T) {
	tests := []struct {
		name          string
		aeadKeyBase64 string
		errorContains string
	}{
		{
			name:          "empty",
			aeadKeyBase64: "",
			errorContains: "AEAD provider requires AeadKeyBase64",
		},
		{
			name:          "malformed base64",
			aeadKeyBase64: "not-base64%%",
			errorContains: "failed to decode AeadKeyBase64",
		},
		{
			name:          "31 byte key",
			aeadKeyBase64: base64.StdEncoding.EncodeToString([]byte("1234567890123456789012345678901")),
			errorContains: "decoded AEAD key must be 32 bytes",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := NewProvider(Config{
				Type:          encTypes.ProviderAead,
				AeadKeyID:     "local-payment-key",
				AeadKeyBase64: tt.aeadKeyBase64,
			})
			if err == nil {
				t.Fatal("NewProvider returned nil error for invalid AEAD config")
			}
			if !strings.Contains(err.Error(), tt.errorContains) {
				t.Fatalf("NewProvider error = %q, want substring %q", err, tt.errorContains)
			}
		})
	}
}

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

// --- Test Cases for NewProvider ---

func TestNewProviderRejectsMissingOrInvalidProviderConfig(t *testing.T) {
	tests := []struct {
		name        string
		config      Config
		errContains []string
	}{
		{
			name: "Unsupported Provider Type",
			config: Config{
				Type: "unknown",
			},
			errContains: []string{"unsupported KMS provider type"},
		},
		{
			name: "Missing AWS Config Struct",
			config: Config{
				Type: encTypes.ProviderAWS,
				AWS:  nil, // Missing struct
			},
			errContains: []string{"AWS configuration is missing"},
		},
		{
			name: "Missing Azure Config Struct",
			config: Config{
				Type:  encTypes.ProviderAzure,
				Azure: nil,
			},
			errContains: []string{"azure configuration is missing"},
		},
		{
			name: "Missing GCP Config Struct",
			config: Config{
				Type: encTypes.ProviderGCP,
				GCP:  nil,
			},
			errContains: []string{"GCP configuration is missing"},
		},
		{
			name: "Missing Vault Config Struct",
			config: Config{
				Type:  encTypes.ProviderVault,
				Vault: nil,
			},
			errContains: []string{"vault configuration is missing"},
		},
		{
			name: "Invalid AWS Config (Validation Error)",
			config: Config{
				Type: encTypes.ProviderAWS,
				AWS:  &AWSConfig{Region: "us-east-1"}, // Missing KeyID
			},
			errContains: []string{"invalid AWS KMS configuration"},
		},
		{
			name: "Invalid Azure Config (Validation Error)",
			config: Config{
				Type: encTypes.ProviderAzure,
				Azure: &AzureConfig{
					KeyID:        "https://payments.vault.azure.net/keys/payment-key/version",
					VaultAddress: "http://payments.vault.azure.net",
				},
			},
			errContains: []string{
				"invalid Azure Key Vault configuration",
				"vault address must be a valid Azure Key Vault URL",
			},
		},
		{
			name: "Invalid GCP Config (Validation Error)",
			config: Config{
				Type: encTypes.ProviderGCP,
				GCP:  &GCPConfig{ResourceName: "invalid-format"}, // Invalid ResourceName
			},
			errContains: []string{"invalid GCP KMS configuration"},
		},
		{
			name: "Invalid Vault Config (Validation Error)",
			config: Config{
				Type:  encTypes.ProviderVault,
				Vault: &VaultConfig{KeyID: "vault-key"},
			},
			errContains: []string{
				"invalid Vault configuration",
				"vault address is required",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			unexpectedFactory := func() wrapping.Wrapper {
				t.Fatal("NewProvider reached a provider wrapper factory for invalid configuration")
				return nil
			}
			replaceWrapperFactory(t, &newAWSWrapper, unexpectedFactory)
			replaceWrapperFactory(t, &newAzureWrapper, unexpectedFactory)
			replaceWrapperFactory(t, &newGCPWrapper, unexpectedFactory)
			replaceWrapperFactory(t, &newVaultWrapper, unexpectedFactory)

			_, err := NewProvider(tt.config)
			if err == nil {
				t.Fatal("NewProvider returned nil error")
			}
			for _, want := range tt.errContains {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("NewProvider error = %q, want substring %q", err, want)
				}
			}
		})
	}
}
