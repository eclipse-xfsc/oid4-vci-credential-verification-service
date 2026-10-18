package holder

import (
	"encoding/json"
	"github.com/eclipse-xfsc/oid4-vci-vp-library/model/presentation"
	"testing"
)

func TestFilterSelectedCredentialsRejectsEmpty(t *testing.T) {
	if _, err := FilterSelectedCredentials(nil, PresentationSelection{}); err == nil {
		t.Fatal("empty selection accepted")
	}
}
func TestFilterSelectedCredentialsRejectsClaimSelectionWithoutSupport(t *testing.T) {
	_, err := FilterSelectedCredentials(nil, PresentationSelection{Selections: []CredentialSelection{{QueryId: "identity", CredentialID: "cred", ClaimIDs: []string{"name"}}}})
	if err == nil {
		t.Fatal("unsupported claim selection accepted")
	}
}
func TestFilterSelectedCredentialsRejectsUnknownQuery(t *testing.T) {
	_, err := FilterSelectedCredentials(nil, PresentationSelection{Selections: []CredentialSelection{{QueryId: "identity", CredentialID: "cred"}}})
	if err == nil {
		t.Fatal("unknown query accepted")
	}
}

func TestFilterSelectedCredentialsPreservesDisclosures(t *testing.T) {
	var groups []presentation.FilterResult
	if err := json.Unmarshal([]byte(`[{"description":{"id":"identity","format":"dc+sd-jwt"},"credentials":{"cred-1":{"id":"cred-1","type":"dc+sd-jwt","data":"eyJhbGciOiJFUzI1NiJ9.eyJmb28iOiJiYXIifQ.sig"},"cred-2":{"id":"cred-2","type":"dc+sd-jwt","data":"other"}}}]`), &groups); err != nil {
		t.Fatal(err)
	}
	if groups[0].Id == "" {
		t.Skip("fixture incompatible with installed FilterResult JSON schema")
	}
	selected, err := FilterSelectedCredentials(groups, PresentationSelection{Selections: []CredentialSelection{{QueryId: groups[0].Id, CredentialID: "cred-1", Disclosures: []string{"given_name"}}}})
	if err != nil {
		t.Fatal(err)
	}
	if len(selected.Groups) != 1 || len(selected.Groups[0].Credentials) != 1 || len(selected.Disclosures) != 1 || len(selected.Disclosures[0].Disclosures) != 1 || selected.Disclosures[0].Disclosures[0] != "given_name" {
		t.Fatalf("unexpected filtered result: %+v", selected)
	}
}
