package verifier

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"testing"
)

func TestExtractVerifiedSDJWTClaims(t *testing.T) {
	disclosure := base64.RawURLEncoding.EncodeToString([]byte(`["salt","test","String value"]`))
	hash := sha256.Sum256([]byte(disclosure))
	payload, _ := json.Marshal(map[string]any{"vct": "example", "_sd_alg": "sha-256", "_sd": []string{base64.RawURLEncoding.EncodeToString(hash[:])}})
	token := "e30." + base64.RawURLEncoding.EncodeToString(payload) + ".signature~" + disclosure + "~kb.header.signature"
	claims, err := extractVerifiedSDJWTClaims([]byte(token))
	if err != nil {
		t.Fatal(err)
	}
	if claims["test"] != "String value" {
		t.Fatalf("unexpected disclosure: %#v", claims)
	}
	_, err = extractVerifiedSDJWTClaims([]byte("e30." + base64.RawURLEncoding.EncodeToString(payload) + ".signature~" + base64.RawURLEncoding.EncodeToString([]byte(`["salt","test","tampered"]`)) + "~kb.header.signature"))
	if err == nil {
		t.Fatal("tampered disclosure accepted")
	}
}
