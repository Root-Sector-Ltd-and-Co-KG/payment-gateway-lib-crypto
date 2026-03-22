# Payment Gateway App Encryption Module

This module provides encryption functionality for the Payment Gateway App, offering a comprehensive suite of encryption services including field-level encryption, key management, and audit logging.

## Import Structure

This module uses the following import path structure:

```go
import "github.com/root-sector-ltd-and-co-kg/payment-gateway-lib-crypto/[package]"
```

Where `[package]` is one of:

- `audit`: Audit logging for encryption operations
- `cache`: Cache functionality for encryption operations
- `coordinator`: Coordinates between different encryption components
- `dbencryption`: Database-specific encryption functionality
- `dek`: Data Encryption Key management
- `field`: Field-level encryption functionality
- `interfaces`: Common interfaces used across the module
- `kms`: Key Management System integrations
- `types`: Common types used across the module

## Features

### Field-Level Encryption

- Secure encryption of sensitive data fields
- Support for different encryption algorithms
- Configurable encryption policies
- Searchable encryption capabilities

### Key Management

- Support for multiple KMS providers:
  - AWS KMS
  - Azure Key Vault
  - Google Cloud KMS
  - HashiCorp Vault Transit
- Data Encryption Key (DEK) management
- Key rotation and versioning
- Secure key storage and retrieval

### Caching

- Performance-optimized caching for DEKs
- Configurable cache policies
- Cache statistics and monitoring

### Audit Logging

- Comprehensive audit trails for encryption operations
- Secure logging of sensitive operations
- Integration with standard logging frameworks

### Database Encryption

- Database-specific encryption implementations
- Secure storage of encrypted data
- Efficient querying of encrypted data

## Usage

### Local Development

Add the following to your `go.mod` file:

```go
replace github.com/root-sector-ltd-and-co-kg/payment-gateway-lib-crypto => ../payment-gateway-lib-crypto
```

or `go.work` file in your root directory:

```go
go 1.26.0

use (
	./payment-gateway-lib-crypto
)
```

### Production

Use the standard Go module dependency mechanism:

```go
require github.com/root-sector-ltd-and-co-kg/payment-gateway-lib-crypto v1.0.1
```

## Directory Structure

- `audit/`: Audit logging for encryption operations
- `cache/`: Cache management for DEK and other encryption components
- `coordinator/`: Coordination between different encryption components
- `dbencryption/`: Database-specific encryption functionality
- `dek/`: Data Encryption Key management
- `field/`: Field-level encryption functionality
- `interfaces/`: Common interfaces used across the module
- `kms/`: Key Management Service interfaces and implementations
  - `credentials/`: KMS provider-specific credential management
- `types/`: Common types used across the encryption module

## Dependencies

The module requires Go 1.24.1 or later and includes the following major dependencies:

- `github.com/hashicorp/go-kms-wrapping/v2`: Core KMS functionality
- `github.com/rs/zerolog`: Structured logging
- `go.mongodb.org/mongo-driver/v2`: MongoDB support
- Various cloud provider SDKs for KMS integration

## Troubleshooting

If you encounter import errors like:

```
could not import github.com/root-sector-ltd-and-co-kg/payment-gateway-lib-crypto/... (no required module provides package "github.com/root-sector-ltd-and-co-kg/payment-gateway-lib-crypto/...")
```

Make sure that:

1. You've properly set up the `replace` directive in your `go.mod` for local development
2. You've run `go mod tidy` to update dependencies
3. The package name and path match the expected structure in this module
4. You're using a compatible Go version (1.24.1 or later)

## Security Considerations

- All encryption operations are audited
- Keys are never stored in plaintext
- Support for key rotation and versioning
- Integration with enterprise-grade KMS providers
- Configurable security policies
- Regular security updates and patches
