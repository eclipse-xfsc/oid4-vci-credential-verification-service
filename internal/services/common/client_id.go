package common

import (
	"errors"
	"strings"
)

// ClientIDFromDID builds the fixed DID-based OID4VP client identifier.
// Callers must obtain the DID from a trusted tenant gateway or tenant registry.
func ClientIDFromDID(raw string) (string, error) {
	did := strings.TrimSpace(raw)
	if !strings.HasPrefix(did, "did:") || len(strings.Split(did, ":")) < 3 || strings.ContainsAny(did, " \t\r\n?#") || strings.HasSuffix(did, ":") {
		return "", errors.New("X-DID must be a valid DID")
	}
	return "decentralized_identifier:" + did, nil
}
