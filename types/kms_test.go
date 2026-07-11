package types

import (
	"encoding/json"
	"testing"
	"time"
)

func TestEncryptionProcessDocumentJSONIncludesScopeAndDetails(t *testing.T) {
	doc := EncryptionProcessDocument{
		ID:      "process-1",
		Scope:   "organization",
		ScopeID: "org-1",
		DetailedErrors: []DetailedError{{
			OrganizationID: "org-1",
			Collection:     "invoices",
			DocumentID:     "doc-1",
			FieldName:      "client.email",
			Error:          "kms unavailable",
			Timestamp:      time.Unix(1, 0).UTC(),
		}},
	}

	payload, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	var decoded map[string]interface{}
	if err := json.Unmarshal(payload, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded["scopeId"] != "org-1" {
		t.Fatalf("expected scopeId in JSON, got %v", decoded["scopeId"])
	}
	if details, ok := decoded["detailedErrors"].([]interface{}); !ok || len(details) != 1 {
		t.Fatalf("expected detailedErrors in JSON, got %#v", decoded["detailedErrors"])
	}
}
