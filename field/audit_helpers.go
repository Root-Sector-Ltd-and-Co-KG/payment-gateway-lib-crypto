package field

import (
	"context"

	"github.com/root-sector-ltd-and-co-kg/payment-gateway-lib-crypto/audit"
	"github.com/root-sector-ltd-and-co-kg/payment-gateway-lib-crypto/types"
)

// CreateAuditEvent creates an audit event with proper context
func CreateAuditEvent(ctx context.Context, field *types.FieldEncrypted, eventType, operation string) *types.AuditEvent {
	event := audit.NewAuditEvent(eventType, operation, int(field.Version))

	// Extract context information
	collection, recordID, fieldName, fieldType := ExtractFieldInfoFromContext(ctx)
	email, userID, orgID, op := ExtractUserInfoFromContext(ctx)

	// Add context information
	if collection != "" {
		event.Context[string(audit.KeyCollection)] = collection
	}
	if recordID != "" {
		event.Context[string(audit.KeyRecordID)] = recordID
	}
	if fieldName != "" {
		event.Context[string(audit.KeyFieldName)] = fieldName
	}
	if fieldType != "" {
		event.Context[string(audit.KeyFieldType)] = fieldType
	}
	if email != "" {
		event.Context[string(audit.KeyUserEmail)] = email
	}
	if userID != "" {
		event.Context[string(audit.KeyUserID)] = userID
	}
	if orgID != "" {
		event.Context[string(audit.KeyOrgID)] = orgID
	}
	if op != "" {
		event.Context[string(audit.KeyOperation)] = op
	}

	// Add scope information extracted from context
	scope, scopeID := GetScopeAndIDFromContext(ctx)
	event.Context[string(audit.KeyScope)] = scope
	if scopeID != "" {
		// Add appropriate ID based on scope
		switch scope {
		case "organization":
			event.Context[string(audit.KeyOrgID)] = scopeID
		case "user":
			event.Context[string(audit.KeyUserID)] = scopeID
		}
		// Add other scope ID keys if necessary
	}

	return event
}
