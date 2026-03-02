// Package kms provides KMS provider functionality
package kms

import (
	"context"
	"encoding/base64" // Added for AEAD
	"fmt"
	"os" // Import os package
	"strings"

	"github.com/root-sector-ltd-and-co-kg/payment-gateway-lib-crypto/types"

	wrapping "github.com/hashicorp/go-kms-wrapping/v2"     // Base v2 package
	kmsaead "github.com/hashicorp/go-kms-wrapping/v2/aead" // AEAD wrapper
	awskms "github.com/hashicorp/go-kms-wrapping/wrappers/awskms/v2"
	azurekeyvault "github.com/hashicorp/go-kms-wrapping/wrappers/azurekeyvault/v2"
	gcpckms "github.com/hashicorp/go-kms-wrapping/wrappers/gcpckms/v2"
	transit "github.com/hashicorp/go-kms-wrapping/wrappers/transit/v2"

	"github.com/rs/zerolog"
)

var log = zerolog.New(zerolog.ConsoleWriter{Out: os.Stderr}).With().Timestamp().Logger()

// provider implements the Provider interface
type provider struct {
	wrapper         wrapping.Wrapper
	lastHealthCheck error
}

// NewProvider creates a new KMS provider based on the configuration
func NewProvider(config Config) (Provider, error) {
	var wrapper wrapping.Wrapper
	var err error
	var keyID, location string  // Variables to hold common info for logging
	ctx := context.Background() // Added for AEAD SetConfig, already used by helpers

	log.Debug().
		Str("provider", string(config.Type)).
		Msg("Initializing KMS provider")

	switch config.Type {
	case types.ProviderAWS:
		if config.AWS == nil {
			return nil, fmt.Errorf("AWS configuration is missing for provider type %s", config.Type)
		}
		keyID = config.AWS.KeyID
		location = config.AWS.Region
		if err = validateAWSConfig(*config.AWS); err != nil {
			return nil, fmt.Errorf("invalid AWS KMS configuration: %w", err)
		}
		wrapper, err = createAWSWrapper(*config.AWS)
	case types.ProviderAzure:
		if config.Azure == nil {
			return nil, fmt.Errorf("azure configuration is missing for provider type %s", config.Type)
		}
		keyID = config.Azure.KeyID
		// Azure doesn't have a direct 'region' equivalent in the same way, log VaultAddress
		location = config.Azure.VaultAddress
		if err = validateAzureConfig(*config.Azure); err != nil {
			return nil, fmt.Errorf("invalid Azure Key Vault configuration: %w", err)
		}
		wrapper, err = createAzureWrapper(*config.Azure)
	case types.ProviderGCP:
		if config.GCP == nil {
			return nil, fmt.Errorf("GCP configuration is missing for provider type %s", config.Type)
		}
		keyID = config.GCP.ResourceName
		if err = validateGCPConfig(*config.GCP); err != nil {
			return nil, fmt.Errorf("invalid GCP KMS configuration: %w", err)
		}
		// If validation passes, parsing for logging context is safe
		parts := strings.Split(config.GCP.ResourceName, "/")
		// Validation ensures len(parts) == 8 and parts[2] == "locations"
		location = parts[3] // Extract actual location for logging

		wrapper, err = createGCPWrapper(*config.GCP)
	case types.ProviderVault:
		if config.Vault == nil {
			return nil, fmt.Errorf("vault configuration is missing for provider type %s", config.Type)
		}
		keyID = config.Vault.KeyID
		location = config.Vault.VaultAddress
		if err = validateVaultConfig(*config.Vault); err != nil {
			return nil, fmt.Errorf("invalid Vault configuration: %w", err)
		}
		wrapper, err = createVaultWrapper(*config.Vault)
	case types.ProviderAead: // This is types.ProviderAead from the root types package
		log.Debug().Str("provider", string(config.Type)).Msg("KMS.NewProvider: Initializing AEAD provider")
		if config.AeadKeyBase64 == "" {
			log.Error().Msg("KMS.NewProvider: config.AeadKeyBase64 is required for AEAD provider.")
			return nil, fmt.Errorf("AEAD provider requires AeadKeyBase64")
		}
		if config.AeadKeyID == "" {
			// Allow empty AeadKeyID if KeyID is to be used, but log it
			log.Warn().Msg("AeadKeyID is empty for AEAD provider, will use BlobInfo.KeyInfo.KeyId if set by wrapper")
		}

		decodedKey, keyErr := base64.StdEncoding.DecodeString(config.AeadKeyBase64)
		if keyErr != nil {
			return nil, fmt.Errorf("failed to decode AeadKeyBase64: %w", keyErr)
		}
		if len(decodedKey) != 32 { // AES-256-GCM typically requires a 32-byte key
			return nil, fmt.Errorf("decoded AEAD key must be 32 bytes for AES-256-GCM, got %d", len(decodedKey))
		}

		aeadWrapper := kmsaead.NewWrapper()

		opts := []wrapping.Option{kmsaead.WithKey(decodedKey)} // Use kmsaead.WithKey
		if config.AeadKeyID != "" {
			opts = append(opts, wrapping.WithKeyId(config.AeadKeyID)) // Use base wrapping.WithKeyId
		}

		// Pass context to SetConfig
		_, err = aeadWrapper.SetConfig(ctx, opts...)
		if err != nil {
			return nil, fmt.Errorf("failed to configure AEAD wrapper: %w", err)
		}
		wrapper = aeadWrapper
		keyID = config.AeadKeyID // For logging
		location = "local"       // For logging
	default:
		log.Error().Str("providerConfigType", string(config.Type)).Msg("KMS.NewProvider: Unsupported provider type in switch default")
		return nil, fmt.Errorf("unsupported KMS provider type: %s", config.Type)
	}

	if err != nil {
		log.Error().Err(err).Str("provider", string(config.Type)).Msg("Failed to create KMS provider wrapper")
		return nil, fmt.Errorf("failed to create wrapper: %w", err)
	}

	log.Info().
		Str("provider", string(config.Type)).
		Str("keyIdentifier", keyID).
		Str("locationContext", location).
		Msg("KMS provider initialized successfully")

	return &provider{
		wrapper:         wrapper,
		lastHealthCheck: nil,
	}, nil
}

// GetWrapper returns the underlying KMS wrapper
func (p *provider) GetWrapper() wrapping.Wrapper {
	return p.wrapper
}

// Test tests the KMS wrapper by performing a test encryption/decryption
func (p *provider) Test(ctx context.Context) error {
	if p.wrapper == nil {
		return fmt.Errorf("wrapper not initialized")
	}

	// Test data
	testData := []byte("test")

	// Try to encrypt
	encrypted, err := p.wrapper.Encrypt(ctx, testData)
	if err != nil {
		return fmt.Errorf("encryption test failed: %w", err)
	}

	// Try to decrypt
	decrypted, err := p.wrapper.Decrypt(ctx, encrypted)
	if err != nil {
		return fmt.Errorf("decryption test failed: %w", err)
	}

	// Verify decrypted data
	if string(decrypted) != string(testData) {
		return fmt.Errorf("decrypted data does not match original")
	}
	return nil
}

// HealthCheck performs a comprehensive health check of the KMS provider
func (p *provider) HealthCheck(ctx context.Context) error {
	// Check if wrapper is initialized
	if p.wrapper == nil {
		return fmt.Errorf("KMS provider not properly initialized: wrapper is nil")
	}

	// Perform encryption/decryption test
	err := p.Test(ctx)
	if err != nil {
		p.lastHealthCheck = fmt.Errorf("KMS provider health check failed: %w", err)
		return p.lastHealthCheck
	}

	p.lastHealthCheck = nil
	return nil
}

// GetLastHealthCheckError returns the last health check error if any
func (p *provider) GetLastHealthCheckError() error {
	return p.lastHealthCheck
}

// validateAWSConfig validates AWS KMS configuration
func validateAWSConfig(awsConfig AWSConfig) error {
	if awsConfig.KeyID == "" {
		return fmt.Errorf("key ID (ARN) is required")
	}

	if awsConfig.Region == "" {
		return fmt.Errorf("region is required")
	}

	if awsConfig.Credentials != nil {
		_, hasAccessKey := awsConfig.Credentials["accessKeyId"].(string)
		_, hasSecretKey := awsConfig.Credentials["secretAccessKey"].(string)
		if (hasAccessKey && !hasSecretKey) || (!hasAccessKey && hasSecretKey) {
			return fmt.Errorf("both accessKeyId and secretAccessKey must be provided if using credentials")
		}
	} else {
		log.Info().Msg("AWS credentials not provided in config, assuming environment variables or default credentials")
	}

	return nil
}

// validateAzureConfig validates Azure Key Vault configuration
func validateAzureConfig(azureConfig AzureConfig) error {
	if azureConfig.KeyID == "" {
		return fmt.Errorf("key ID (URL) is required")
	}
	// Validate VaultAddress format (basic check)
	if !strings.HasPrefix(azureConfig.VaultAddress, "https://") || !strings.Contains(azureConfig.VaultAddress, ".vault.azure.net") {
		return fmt.Errorf("vault address must be a valid Azure Key Vault URL (e.g., https://myvault.vault.azure.net)")
	}

	if azureConfig.Credentials != nil {
		requiredFields := []string{"tenantId", "clientId", "clientSecret"}
		for _, field := range requiredFields {
			if val, ok := azureConfig.Credentials[field].(string); !ok || val == "" {
				return fmt.Errorf("%s is required in credentials and cannot be empty", field)
			}
		}
	} else {
		// If credentials are not provided, the library might use other auth methods (e.g., MSI)
		log.Info().Msg("Azure credentials not provided, assuming alternative authentication method (e.g., Managed Identity)")
	}

	return nil
}

// validateGCPConfig validates GCP KMS configuration
func validateGCPConfig(gcpConfig GCPConfig) error {
	if gcpConfig.ResourceName == "" {
		return fmt.Errorf("resource name is required")
	}
	// Basic format validation for ResourceName
	// projects/{project}/locations/{location}/keyRings/{keyRing}/cryptoKeys/{cryptoKey}
	parts := strings.Split(gcpConfig.ResourceName, "/")
	if len(parts) != 8 || parts[0] != "projects" || parts[2] != "locations" || parts[4] != "keyRings" || parts[6] != "cryptoKeys" {
		return fmt.Errorf("invalid resource name format. Expected: projects/{project}/locations/{location}/keyRings/{keyRing}/cryptoKeys/{cryptoKey}")
	}
	if parts[1] == "" || parts[3] == "" || parts[5] == "" || parts[7] == "" {
		return fmt.Errorf("project, location, keyRing, and cryptoKey components in resource name cannot be empty")
	}

	// Credentials are optional: when omitted, ADC is used.
	// If a credentials map is provided, credentialsJson must be present and non-empty,
	// because we write it to a temporary file for the wrapper library.
	if gcpConfig.Credentials != nil {
		credsJSON, ok := gcpConfig.Credentials["credentialsJson"].(string)
		if !ok || credsJSON == "" {
			return fmt.Errorf("credentialsJson is required in credentials map and cannot be empty")
		}
	} else {
		// If credentials are not provided, rely on Application Default Credentials
		// (for example GOOGLE_APPLICATION_CREDENTIALS or workload identity).
		log.Info().Msg("GCP credentials map not provided in config, assuming Application Default Credentials (ADC).")
	}

	return nil
}

// validateVaultConfig validates HashiCorp Vault configuration
func validateVaultConfig(vaultConfig VaultConfig) error {
	if vaultConfig.KeyID == "" {
		return fmt.Errorf("key ID (key name) is required")
	}

	if vaultConfig.VaultAddress == "" {
		return fmt.Errorf("vault address is required")
	}

	// VaultMount is optional, defaults handled by library

	if vaultConfig.Credentials != nil {
		if token, ok := vaultConfig.Credentials["token"].(string); !ok || token == "" {
			return fmt.Errorf("token is required in credentials map and cannot be empty")
		}
	} else {
		// Token might come from env (VAULT_TOKEN) or other auth methods
		log.Info().Msg("Vault token not provided in config, assuming VAULT_TOKEN environment variable or other auth method")
	}

	return nil
}

// createAWSWrapper creates an AWS KMS wrapper
func createAWSWrapper(awsConfig AWSConfig) (wrapping.Wrapper, error) {
	wrapper := awskms.NewWrapper()

	// Create config map with AWS KMS specific options
	configMap := map[string]string{
		"kms_key_id": awsConfig.KeyID,
		"region":     awsConfig.Region,
	}

	// Add credentials if provided
	if awsConfig.Credentials != nil {
		// Log credential presence without exposing sensitive data
		hasCredentials := map[string]bool{
			"accessKey":    awsConfig.Credentials["accessKeyId"] != nil,
			"secretKey":    awsConfig.Credentials["secretAccessKey"] != nil,
			"sessionToken": awsConfig.Credentials["sessionToken"] != nil,
		}

		log.Debug().
			Interface("credentials", hasCredentials).
			Msg("Configuring AWS KMS credentials from config")

		if accessKey, ok := awsConfig.Credentials["accessKeyId"].(string); ok && accessKey != "" {
			configMap["access_key"] = accessKey
		}
		if secretKey, ok := awsConfig.Credentials["secretAccessKey"].(string); ok && secretKey != "" {
			configMap["secret_key"] = secretKey
		}
		if sessionToken, ok := awsConfig.Credentials["sessionToken"].(string); ok && sessionToken != "" {
			configMap["session_token"] = sessionToken
		}
	}
	// No else needed, validation already logged info message if creds are nil

	// Configure the wrapper
	_, err := wrapper.SetConfig(context.Background(), wrapping.WithConfigMap(configMap))
	if err != nil {
		return nil, fmt.Errorf("failed to configure AWS KMS wrapper: %w", err)
	}

	return wrapper, nil
}

// createAzureWrapper creates an Azure Key Vault wrapper
func createAzureWrapper(azureConfig AzureConfig) (wrapping.Wrapper, error) {
	wrapper := azurekeyvault.NewWrapper()

	// Create config map with Azure Key Vault specific options
	// Example KeyID URL: https://myvault.vault.azure.net/keys/mykey/version
	keyName := azureConfig.KeyID // Default to full ID if parsing fails
	keyVersion := ""
	vaultName := ""

	// Parse KeyID URL
	parts := strings.Split(azureConfig.KeyID, "/")
	if len(parts) >= 5 && parts[3] == "keys" { // Basic check for URL structure
		keyName = parts[4]
		if len(parts) >= 6 {
			keyVersion = parts[5]
		}
	} else {
		log.Warn().Str("keyId", azureConfig.KeyID).Msg("Azure KeyID does not look like a standard Key Identifier URL. Using the full value as key_name.")
	}

	// Parse VaultAddress URL (Validation ensures it's in the correct format)
	prefixRemoved := strings.TrimPrefix(azureConfig.VaultAddress, "https://")
	vaultNameParts := strings.Split(prefixRemoved, ".")
	if len(vaultNameParts) > 0 {
		vaultName = vaultNameParts[0]
	} else {
		// This case should be caught by validation
		return nil, fmt.Errorf("could not parse vault name from VaultAddress: %s", azureConfig.VaultAddress)
	}

	configMap := map[string]string{
		"key_name":   keyName,
		"vault_name": vaultName,
		// Pass vault_url explicitly as the library might need it
		"vault_url": azureConfig.VaultAddress,
	}
	if keyVersion != "" {
		configMap["key_version"] = keyVersion
	}

	// Add credentials if provided
	if azureConfig.Credentials != nil {
		// Log credential presence without exposing sensitive data
		hasCredentials := map[string]bool{
			"tenantId":     azureConfig.Credentials["tenantId"] != nil,
			"clientId":     azureConfig.Credentials["clientId"] != nil,
			"clientSecret": azureConfig.Credentials["clientSecret"] != nil,
		}

		log.Debug().
			Interface("credentials", hasCredentials).
			Msg("Configuring Azure Key Vault credentials from config")

		if tenantID, ok := azureConfig.Credentials["tenantId"].(string); ok {
			configMap["tenant_id"] = tenantID
		}
		if clientID, ok := azureConfig.Credentials["clientId"].(string); ok {
			configMap["client_id"] = clientID
		}
		if clientSecret, ok := azureConfig.Credentials["clientSecret"].(string); ok {
			configMap["client_secret"] = clientSecret
		}
	}
	// No else needed here, validation already logged info message if creds are nil

	// Configure the wrapper
	_, err := wrapper.SetConfig(context.Background(), wrapping.WithConfigMap(configMap))
	if err != nil {
		return nil, fmt.Errorf("failed to configure Azure Key Vault wrapper: %w", err)
	}

	return wrapper, nil
}

// createGCPWrapper creates a Google Cloud KMS wrapper
func createGCPWrapper(gcpConfig GCPConfig) (wrapping.Wrapper, error) {
	wrapper := gcpckms.NewWrapper()

	// --- Parse Resource Name ---
	parts := strings.Split(gcpConfig.ResourceName, "/")
	if len(parts) != 8 || parts[0] != "projects" || parts[2] != "locations" || parts[4] != "keyRings" || parts[6] != "cryptoKeys" {
		// Validation should prevent this, but check again
		return nil, fmt.Errorf("internal error: invalid resource name format passed validation: %s", gcpConfig.ResourceName)
	}
	parsedProject := parts[1]
	parsedLocation := parts[3]
	parsedKeyRing := parts[5]
	parsedCryptoKey := parts[7]
	// --- End Parse Resource Name ---

	// Project ID is taken directly from the parsed ResourceName
	projectID := parsedProject
	log.Debug().Str("projectID", projectID).Msg("Using project ID parsed from ResourceName")

	// Create config map with GCP KMS specific options using parsed values
	configMap := map[string]string{
		"project":    projectID,       // Use project ID from ResourceName
		"region":     parsedLocation,  // Use parsed location, maps to library's 'region'
		"key_ring":   parsedKeyRing,   // Use parsed key ring
		"crypto_key": parsedCryptoKey, // Use parsed crypto key name
	}

	// --- Temporary File for Credentials ---
	// If credentials are provided, write to temp file and pass path to library
	if gcpConfig.Credentials != nil {
		var ok bool
		credsJSON, ok := gcpConfig.Credentials["credentialsJson"].(string)
		if !ok || credsJSON == "" {
			// Validation should have caught this
			return nil, fmt.Errorf("internal error: invalid or missing credentialsJson in GCP config credentials")
		}

		tempFile, err := os.CreateTemp("", "gcp-creds-*.json")
		if err != nil {
			return nil, fmt.Errorf("failed to create temporary credentials file: %w", err)
		}
		// Ensure cleanup happens even if subsequent steps fail
		defer func() {
			errRemove := os.Remove(tempFile.Name())
			if errRemove != nil {
				log.Error().Err(errRemove).Str("filePath", tempFile.Name()).Msg("Failed to remove temporary credentials file")
			} else {
				log.Debug().Str("filePath", tempFile.Name()).Msg("Successfully removed temporary credentials file")
			}
		}()

		if _, err := tempFile.Write([]byte(credsJSON)); err != nil {
			// Attempt to close before returning error
			if closeErr := tempFile.Close(); closeErr != nil {
				log.Error().Err(closeErr).Str("filePath", tempFile.Name()).Msg("Failed to close temporary credentials file after write error")
			}
			return nil, fmt.Errorf("failed to write credentials to temporary file: %w", err)
		}
		if err := tempFile.Close(); err != nil {
			// Log error but proceed, file might still be usable by SDK
			log.Error().Err(err).Str("filePath", tempFile.Name()).Msg("Failed to close temporary credentials file after successful write")
		}

		configMap["credentials"] = tempFile.Name() // Pass the temp file path
		log.Debug().Str("tempFilePath", tempFile.Name()).Msg("Configuring GCP KMS credentials using temporary file path")
	} else {
		// If no credentials provided in config, rely on ADC (env var, metadata server, etc.)
		log.Info().Msg("GCP credentials not provided in config, relying on Application Default Credentials (ADC).")
		// Do NOT add "credentials" key to configMap in this case
	}
	// --- End Temporary File ---

	// Configure the wrapper
	_, err := wrapper.SetConfig(context.Background(), wrapping.WithConfigMap(configMap))
	if err != nil {
		// Wrap the underlying error for better context
		return nil, fmt.Errorf("failed to configure GCP KMS wrapper: %w", err)
	}

	return wrapper, nil
}

// createVaultWrapper creates a HashiCorp Vault Transit wrapper
func createVaultWrapper(vaultConfig VaultConfig) (wrapping.Wrapper, error) {
	wrapper := transit.NewWrapper()

	// Create config map with Vault Transit specific options
	configMap := map[string]string{
		"address":  vaultConfig.VaultAddress,
		"key_name": vaultConfig.KeyID, // This is the key name in Vault
	}
	// Add mount path only if it's non-empty
	if vaultConfig.VaultMount != "" {
		configMap["mount_path"] = vaultConfig.VaultMount
	}

	// Add token if provided
	if vaultConfig.Credentials != nil {
		if token, ok := vaultConfig.Credentials["token"].(string); ok && token != "" {
			configMap["token"] = token
			log.Debug().Msg("Configuring Vault Transit credentials from config (token)")
		} else if !ok {
			// If Credentials map exists but token is missing/invalid type
			return nil, fmt.Errorf("invalid or missing token in Vault config credentials")
		}
		// If token is empty string, validation should have caught it.
	}
	// No else needed, validation already logged info message if creds are nil

	// Configure the wrapper
	_, err := wrapper.SetConfig(context.Background(), wrapping.WithConfigMap(configMap))
	if err != nil {
		return nil, fmt.Errorf("failed to configure Vault Transit wrapper: %w", err)
	}

	return wrapper, nil
}
