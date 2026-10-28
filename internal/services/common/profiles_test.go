package common

import (
	"github.com/google/uuid"
	"testing"
)

func validTestProfile() *PresentationProfile {
	return &PresentationProfile{TenantID: "x", GroupID: "y", ProfileType: "verifier", InteractionType: "human", ProfileID: uuid.New(), Enabled: true, DID: "did:web:example.org", Origin: "https://example.org", KeyNamespace: "tenant", KeyID: "key", SigningAlgorithm: "ES256", ResponseMode: "direct_post", RequestObjectTTLSeconds: 300, PresentationPolicies: map[string]string{"mitgliedschaft": `{"credentials":[{"id":"membership","format":"dc+sd-jwt","meta":{"vct_values":["https://example.org/MembershipCredential"]}}]}`}}
}
func TestProfileValidation(t *testing.T) {
	p := validTestProfile()
	if err := ValidateProfile(p); err != nil {
		t.Fatal(err)
	}
	p.Origin = "http://example.org"
	if ValidateProfile(p) == nil {
		t.Fatal("HTTP origin accepted")
	}
	p = validTestProfile()
	p.InteractionType = "unknown"
	if ValidateProfile(p) == nil {
		t.Fatal("unknown interaction accepted")
	}
	p = validTestProfile()
	p.PresentationPolicies = nil
	if ValidateProfile(p) == nil {
		t.Fatal("empty permission set map accepted")
	}
	p = validTestProfile()
	p.ProfileType = "holder"
	p.PresentationPolicies = nil
	if err := ValidateProfile(p); err != nil {
		t.Fatal(err)
	}
}
