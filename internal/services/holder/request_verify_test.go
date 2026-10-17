package holder

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
)

func TestVerifyExternalRequestJWTRejectsUntrustedIdentity(t *testing.T) {
	header, _ := json.Marshal(map[string]string{"alg": "EdDSA", "kid": "did:web:other.example#key-1"})
	claims, _ := json.Marshal(map[string]string{"client_id": "did:web:verifier.example"})
	compact := base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(claims) + "." + base64.RawURLEncoding.EncodeToString([]byte("fake"))
	if _, err := verifyExternalRequestJWT(context.Background(), compact, "did:web:verifier.example"); err == nil || !strings.Contains(err.Error(), "kid") {
		t.Fatalf("expected kid binding rejection: %v", err)
	}
	if _, err := verifyExternalRequestJWT(context.Background(), compact, "did:web:another.example"); err == nil {
		t.Fatal("accepted mismatched client_id")
	}
}
func TestVerifyExternalRequestJWTRejectsUnsignedAndUnsupported(t *testing.T) {
	for _, alg := range []string{"none", "HS256"} {
		header, _ := json.Marshal(map[string]string{"alg": alg, "kid": "did:web:verifier.example#key-1"})
		claims, _ := json.Marshal(map[string]string{"client_id": "did:web:verifier.example"})
		compact := base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(claims) + ".AAAA"
		if _, err := verifyExternalRequestJWT(context.Background(), compact, "did:web:verifier.example"); err == nil {
			t.Fatalf("accepted %s", alg)
		}
	}
}
