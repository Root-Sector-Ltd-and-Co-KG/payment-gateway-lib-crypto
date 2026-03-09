package credentials

import (
	"fmt"

	"github.com/root-sector-ltd-and-co-kg/payment-gateway-lib-crypto/interfaces"
	"github.com/root-sector-ltd-and-co-kg/payment-gateway-lib-crypto/kms"
	"github.com/root-sector-ltd-and-co-kg/payment-gateway-lib-crypto/kms/credentials/symmetric"
	"github.com/root-sector-ltd-and-co-kg/payment-gateway-lib-crypto/types"

	"github.com/rs/zerolog/log"
)

const maskedValue = "[MASKED]"

// credentialManager implements the CredentialsManager interface for credential encryption
type credentialManager struct {
	encryptor interfaces.SymmetricEncryptor
}

// NewManager creates a new credential manager. Returns an error if the
// encryption key is invalid so callers do not receive a nil manager.
func NewManager(encryptionKey []byte) (interfaces.CredentialsManager, error) {
	encryptor, err := symmetric.NewEncryption(encryptionKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create encryptor: %w", err)
	}

	return &credentialManager{
		encryptor: encryptor,
	}, nil
}

// EncryptCredentials encrypts KMS credentials based on provider type
func (m *credentialManager) EncryptCredentials(config *types.EncryptionConfig) error {
	if config == nil || config.Credentials == nil {
		return nil
	}

	// Create a new credentials object to store encrypted values
	newCreds := &types.KMSCredentials{}

	switch config.Provider {
	case types.ProviderAWS:
		// Encrypt AWS Access Key ID if present and not masked
		if config.Credentials.AccessKeyID != "" && config.Credentials.AccessKeyID != maskedValue {
			encrypted, err := m.encryptor.Encrypt(config.Credentials.AccessKeyID)
			if err != nil {
				return fmt.Errorf("failed to encrypt AWS access key: %w", err)
			}
			newCreds.AccessKeyID = encrypted
		}

		// Encrypt AWS Secret Access Key if present and not masked
		if config.Credentials.SecretAccessKey != "" && config.Credentials.SecretAccessKey != maskedValue {
			encrypted, err := m.encryptor.Encrypt(config.Credentials.SecretAccessKey)
			if err != nil {
				return fmt.Errorf("failed to encrypt AWS secret key: %w", err)
			}
			newCreds.SecretAccessKey = encrypted
		}

		// Encrypt session token if present and not masked
		if config.Credentials.SessionToken != "" && config.Credentials.SessionToken != maskedValue {
			encrypted, err := m.encryptor.Encrypt(config.Credentials.SessionToken)
			if err != nil {
				return fmt.Errorf("failed to encrypt AWS session token: %w", err)
			}
			newCreds.SessionToken = encrypted
		}

	case types.ProviderAzure:
		// Encrypt Azure Tenant ID if present and not masked
		if config.Credentials.TenantID != "" && config.Credentials.TenantID != maskedValue {
			encrypted, err := m.encryptor.Encrypt(config.Credentials.TenantID)
			if err != nil {
				return fmt.Errorf("failed to encrypt Azure tenant ID: %w", err)
			}
			newCreds.TenantID = encrypted
		}

		// Encrypt Azure Client ID if present and not masked
		if config.Credentials.ClientID != "" && config.Credentials.ClientID != maskedValue {
			encrypted, err := m.encryptor.Encrypt(config.Credentials.ClientID)
			if err != nil {
				return fmt.Errorf("failed to encrypt Azure client ID: %w", err)
			}
			newCreds.ClientID = encrypted
		}

		// Encrypt Azure Client Secret if present and not masked
		if config.Credentials.ClientSecret != "" && config.Credentials.ClientSecret != maskedValue {
			encrypted, err := m.encryptor.Encrypt(config.Credentials.ClientSecret)
			if err != nil {
				return fmt.Errorf("failed to encrypt Azure client secret: %w", err)
			}
			newCreds.ClientSecret = encrypted
		}

	case types.ProviderGCP:
		// Encrypt GCP Credentials JSON if present and not masked
		if config.Credentials.CredentialsJSON != "" && config.Credentials.CredentialsJSON != maskedValue {
			encrypted, err := m.encryptor.Encrypt(config.Credentials.CredentialsJSON)
			if err != nil {
				return fmt.Errorf("failed to encrypt GCP credentials JSON: %w", err)
			}
			newCreds.CredentialsJSON = encrypted
		}

	case types.ProviderVault:
		// Encrypt Vault Token if present and not masked
		if config.Credentials.Token != "" && config.Credentials.Token != maskedValue {
			encrypted, err := m.encryptor.Encrypt(config.Credentials.Token)
			if err != nil {
				return fmt.Errorf("failed to encrypt Vault token: %w", err)
			}
			newCreds.Token = encrypted
		}

	default:
		return fmt.Errorf("unsupported provider type: %s", config.Provider)
	}

	// Update the config with the new encrypted credentials
	config.Credentials = newCreds

	return nil
}

// DecryptCredentials decrypts KMS credentials based on provider type
func (m *credentialManager) DecryptCredentials(config *types.EncryptionConfig) error {
	if config == nil || config.Credentials == nil {
		return nil
	}

	// Validate provider type
	if config.Provider == "" {
		return fmt.Errorf("provider type is required for decryption")
	}

	// Create a new credentials object to store decrypted values
	newCreds := &types.KMSCredentials{}

	// Helper function to safely decrypt a value
	decryptValue := func(value string, fieldName string) (string, error) {
		if value == "" || value == maskedValue {
			return "", nil
		}

		decrypted, err := m.encryptor.Decrypt(value)
		if err != nil {
			log.Error().Err(err).Str("field", fieldName).Msg("Failed to decrypt credential field")
			return "", fmt.Errorf("failed to decrypt %s: %w", fieldName, err)
		}

		return decrypted, nil
	}

	var err error
	switch config.Provider {
	case types.ProviderAWS:
		if newCreds.AccessKeyID, err = decryptValue(config.Credentials.AccessKeyID, "AWS access key"); err != nil {
			return err
		}
		if newCreds.SecretAccessKey, err = decryptValue(config.Credentials.SecretAccessKey, "AWS secret key"); err != nil {
			return err
		}
		if newCreds.SessionToken, err = decryptValue(config.Credentials.SessionToken, "AWS session token"); err != nil {
			return err
		}

	case types.ProviderAzure:
		if newCreds.TenantID, err = decryptValue(config.Credentials.TenantID, "Azure tenant ID"); err != nil {
			return err
		}
		if newCreds.ClientID, err = decryptValue(config.Credentials.ClientID, "Azure client ID"); err != nil {
			return err
		}
		if newCreds.ClientSecret, err = decryptValue(config.Credentials.ClientSecret, "Azure client secret"); err != nil {
			return err
		}

	case types.ProviderGCP:
		if newCreds.CredentialsJSON, err = decryptValue(config.Credentials.CredentialsJSON, "GCP credentials JSON"); err != nil {
			return err
		}

	case types.ProviderVault:
		if newCreds.Token, err = decryptValue(config.Credentials.Token, "Vault token"); err != nil {
			return err
		}

	default:
		return fmt.Errorf("unsupported provider type: %s", config.Provider)
	}

	// Update the config with the decrypted credentials
	config.Credentials = newCreds

	// Log successful decryption with minimal info
	log.Trace().
		Str("provider", string(config.Provider)).
		Interface("credentialStatus", map[string]bool{
			"hasAccessKeyID":     newCreds.AccessKeyID != "",
			"hasSecretAccessKey": newCreds.SecretAccessKey != "",
			"hasTenantID":        newCreds.TenantID != "",
			"hasClientID":        newCreds.ClientID != "",
			"hasClientSecret":    newCreds.ClientSecret != "",
			"hasCredentialsJSON": newCreds.CredentialsJSON != "",
			"hasToken":           newCreds.Token != "",
		}).
		Msg("Credentials decrypted successfully")

	return nil
}

// ToMap converts KMS credentials to a map for KMS provider initialization
func ToMap(creds *types.KMSCredentials) map[string]interface{} {
	if creds == nil {
		return nil
	}

	result := make(map[string]interface{})

	// AWS credentials
	if creds.AccessKeyID != "" {
		result["accessKeyId"] = creds.AccessKeyID
	}
	if creds.SecretAccessKey != "" {
		result["secretAccessKey"] = creds.SecretAccessKey
	}
	if creds.SessionToken != "" {
		result["sessionToken"] = creds.SessionToken
	}

	// Azure credentials
	if creds.TenantID != "" {
		result["tenantId"] = creds.TenantID
	}
	if creds.ClientID != "" {
		result["clientId"] = creds.ClientID
	}
	if creds.ClientSecret != "" {
		result["clientSecret"] = creds.ClientSecret
	}

	// GCP credentials
	if creds.CredentialsJSON != "" {
		result["credentialsJson"] = creds.CredentialsJSON
	}

	// Vault credentials
	if creds.Token != "" {
		result["token"] = creds.Token
	}

	return result
}

// Helper function to convert KMS credentials to map
func convertKMSCredentialsToMap(creds interface{}) map[string]interface{} {
	if creds == nil {
		return nil
	}

	m := make(map[string]interface{})

	switch creds := creds.(type) {
	case *types.KMSCredentials:
		if creds.AccessKeyID != "" {
			m["accessKeyId"] = creds.AccessKeyID
		}
		if creds.SecretAccessKey != "" {
			m["secretAccessKey"] = creds.SecretAccessKey
		}
		if creds.SessionToken != "" {
			m["sessionToken"] = creds.SessionToken
		}
		if creds.TenantID != "" {
			m["tenantId"] = creds.TenantID
		}
		if creds.ClientID != "" {
			m["clientId"] = creds.ClientID
		}
		if creds.ClientSecret != "" {
			m["clientSecret"] = creds.ClientSecret
		}
		if creds.CredentialsJSON != "" {
			m["credentialsJson"] = creds.CredentialsJSON
		}
		if creds.Token != "" {
			m["token"] = creds.Token
		}
	case *types.EncryptionConfig:
		if creds.Credentials != nil {
			m = convertKMSCredentialsToMap(creds.Credentials)
		}
	default:
		log.Error().Msg("Unsupported credentials type")
	}

	return m
}

// Helper function to convert config to KMS config
func toKMSConfig(config *types.EncryptionConfig) kms.Config {
	if config == nil {
		// Return an empty config, maybe log a warning?
		log.Warn().Msg("toKMSConfig called with nil EncryptionConfig")
		return kms.Config{}
	}

	kmsCfg := kms.Config{
		Type: config.Provider, // Set the provider type
	}

	// Convert the generic *types.KMSCredentials to map[string]interface{}
	// This map is expected by the provider-specific structs.
	var credsMap map[string]interface{}
	if config.Credentials != nil { // Add nil check here
		credsMap = convertKMSCredentialsToMap(config.Credentials)
	} else {
		credsMap = make(map[string]interface{}) // Ensure credsMap is not nil
	}

	// Populate the appropriate nested struct based on the provider type
	switch config.Provider {
	case types.ProviderAWS:
		kmsCfg.AWS = &kms.AWSConfig{
			KeyID:       config.KeyID, // AWS uses KeyID (ARN)
			Region:      config.Region,
			Credentials: credsMap,
		}
	case types.ProviderAzure:
		kmsCfg.Azure = &kms.AzureConfig{
			KeyID:        config.KeyID, // Azure uses KeyID (URL)
			VaultAddress: config.VaultAddress,
			Credentials:  credsMap,
		}
	case types.ProviderGCP:
		kmsCfg.GCP = &kms.GCPConfig{
			// GCP uses ResourceName in the new structure
			ResourceName: config.KeyID, // Assuming KeyID from EncryptionConfig holds the ResourceName for GCP
			Credentials:  credsMap,
			// KeyRing and Location are parsed from ResourceName later in createGCPWrapper
		}
		// We might need to adjust how KeyID/ResourceName is handled if EncryptionConfig doesn't store the full ResourceName for GCP.
		// For now, assuming config.KeyID contains the GCP Resource Name based on previous context.
		// Removed check for deprecated KeyRing/Region fields as they are removed from EncryptionConfig struct.
		if kmsCfg.GCP.ResourceName == "" {
			// This check remains relevant - if KeyID (holding ResourceName) is empty, it's an issue.
			// However, the initial check in calling functions should prevent this.
			log.Error().Msg("GCP ResourceName (expected in KeyID field) is missing in EncryptionConfig during kms.Config conversion.")
		}

	case types.ProviderVault:
		kmsCfg.Vault = &kms.VaultConfig{
			KeyID:        config.KeyID, // Vault uses KeyID (key name)
			VaultAddress: config.VaultAddress,
			VaultMount:   config.VaultMount,
			Credentials:  credsMap,
		}
	default:
		// Log error for unsupported provider type
		log.Error().Str("provider", string(config.Provider)).Msg("Unsupported provider type encountered in toKMSConfig")
		// Return the partially filled kmsCfg (only Type is set)
	}

	return kmsCfg
}
