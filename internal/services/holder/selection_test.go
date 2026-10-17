package holder

import "testing"

func TestFilterSelectedCredentialsRejectsEmpty(t *testing.T) {
	if _, err := FilterSelectedCredentials(nil, PresentationSelection{}); err == nil {
		t.Fatal("empty selection accepted")
	}
}
func TestFilterSelectedCredentialsRejectsClaimSelectionWithoutSupport(t *testing.T) {
	_, err := FilterSelectedCredentials(nil, PresentationSelection{Selections: []CredentialSelection{{QueryID: "identity", CredentialID: "cred", ClaimIDs: []string{"name"}}}})
	if err == nil {
		t.Fatal("unsupported claim selection accepted")
	}
}
func TestFilterSelectedCredentialsRejectsUnknownQuery(t *testing.T) {
	_, err := FilterSelectedCredentials(nil, PresentationSelection{Selections: []CredentialSelection{{QueryID: "identity", CredentialID: "cred"}}})
	if err == nil {
		t.Fatal("unknown query accepted")
	}
}
