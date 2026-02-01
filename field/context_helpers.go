package field

import (
	"context"

	"github.com/root-sector-ltd-and-co-kg/payment-gateway-lib-crypto/audit"
)

// ExtractFieldInfoFromContext extracts info from context
func ExtractFieldInfoFromContext(ctx context.Context) (collection, recordID, fieldName, fieldType string) {
	if val, ok := ctx.Value(audit.KeyCollection).(string); ok {
		collection = val
	}
	if val, ok := ctx.Value(audit.KeyRecordID).(string); ok {
		recordID = val
	}
	if val, ok := ctx.Value(audit.KeyFieldName).(string); ok {
		fieldName = val
	}
	if val, ok := ctx.Value(audit.KeyFieldType).(string); ok {
		fieldType = val
	}
	return
}

func ExtractUserInfoFromContext(ctx context.Context) (email, userID, orgID, operation string) {
	if val, ok := ctx.Value(audit.KeyUserEmail).(string); ok {
		email = val
	}
	if val, ok := ctx.Value(audit.KeyUserID).(string); ok {
		userID = val
	}
	if val, ok := ctx.Value(audit.KeyOrgID).(string); ok {
		orgID = val
	}
	if val, ok := ctx.Value(audit.KeyOperation).(string); ok {
		operation = val
	}
	return
}

// GetScopeAndIDFromContext gets scope and scopeID from context
func GetScopeAndIDFromContext(ctx context.Context) (scope string, scopeID string) {
	scope = ""   // Default to empty, let buildAAD enforce presence
	scopeID = "" // Default

	if val := ctx.Value(audit.KeyScope); val != nil {
		if str, ok := val.(string); ok && str != "" {
			scope = str
		}
	}

	// Extract OrgID specifically if scope is organization
	if scope == "organization" {
		if val := ctx.Value(audit.KeyOrgID); val != nil {
			if str, ok := val.(string); ok && str != "" {
				scopeID = str
			}
		}
	}

	return scope, scopeID
}
