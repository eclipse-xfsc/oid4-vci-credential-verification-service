package services

import (
	"fmt"
	"testing"
)

func TestParsePercentEncodedUrl(t *testing.T) {
	//testUrl := "https://credential-verification-service.default.svc.cluster.local:8080%2Fv1%2Ftenants%2Ftenant_space%2Finternal%2Fpresentation%2Fproof/MEQCICWa10hPZFWuZiYobn_Bi4ENjjmLwLsfIKLCnZ-hekaOAiArXyJaGP1_axCKZai7iya8Pto1fzU94la6kYxFnroeXg/request-object/request.jwt"
	testUrl := "https://auth-cloud-wallet.xfsc.dev/realms/react-keycloak/protocol/openid-connect/auth?client_id=react-keycloak&redirect_uri=https%3A%2F%2Fcloud-wallet.xfsc.dev%2Fen%2Fwallet%2Fcredentials&response_type=code&scope=openid+profile&state=06f6feafb58d4b99b4fcf9df93376cf2&code_challenge=SrQuvTgvsgcHhr5A7KdDuRnsH9JZ9Rjk9kfdUWco_Hc&code_challenge_method=S256&response_mode=query"
	u1, err := parsePercentEncodedUrl(testUrl, false)
	if err != nil {
		t.Error(err)
	}
	fmt.Println(u1.String())
	testUrl = "https://credential-verification-service.default.svc.cluster.local:8080/v1/tenants/tenant_space/presentation/authorize?client_id=https%3A%2F%2Fcredential-verification-service.default.svc.cluster.local%3A8080%2Fpresentation%2FMEQCICWa10hPZFWuZiYobn_Bi4ENjjmLwLsfIKLCnZ-hekaOAiArXyJaGP1_axCKZai7iya8Pto1fzU94la6kYxFnroeXg\\u0026request_uri=https%3A%2F%2Fcredential-verification-service.default.svc.cluster.local%3A8080%252Fv1%252Ftenants%252Ftenant_space%252Finternal%252Fpresentation%252Fproof%2FMEQCICWa10hPZFWuZiYobn_Bi4ENjjmLwLsfIKLCnZ-hekaOAiArXyJaGP1_axCKZai7iya8Pto1fzU94la6kYxFnroeXg%2Frequest-object%2Frequest.jwt"
	u2, err := parsePercentEncodedUrl(testUrl, false)
	fmt.Println(u2.String())
	if err != nil {
		t.Error(err)
	}
}
