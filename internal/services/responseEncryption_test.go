package services

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"

	"github.com/eclipse-xfsc/oid4-vci-vp-library/model/presentation"
)

func TestDirectPostJWTEncryptsAuthorizationResponse(t *testing.T) {
	curve := ecdh.P256()
	verifierKey, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pub := verifierKey.PublicKey().Bytes()
	coordLen := (len(pub) - 1) / 2
	metadata := &presentation.VerifierMetadata{
		JWKS: &presentation.JWKSet{Keys: []map[string]any{{
			"kty": "EC", "crv": "P-256", "alg": "ECDH-ES", "use": "enc", "kid": "enc-1",
			"x": base64.RawURLEncoding.EncodeToString(pub[1 : 1+coordLen]),
			"y": base64.RawURLEncoding.EncodeToString(pub[1+coordLen:]),
		}}},
		EncryptedResponseEncValuesSupported: []string{"A128GCM", "A256GCM"},
	}
	response := presentation.AuthorizationResponse{
		VPToken: presentation.VPToken{"credential-1": {json.RawMessage(`"sd-jwt-presentation"`)}},
		State:   "external-state",
	}
	compact, err := (oid4vpResponseEncryptor{}).EncryptAuthorizationResponse(t.Context(), response, metadata)
	if err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(compact, ".")
	if len(parts) != 5 || parts[1] != "" {
		t.Fatalf("unexpected compact JWE: %q", compact)
	}

	headerJSON, _ := base64.RawURLEncoding.DecodeString(parts[0])
	var header struct {
		Alg string `json:"alg"`
		Enc string `json:"enc"`
		Kid string `json:"kid"`
		EPK struct {
			X string `json:"x"`
			Y string `json:"y"`
		} `json:"epk"`
	}
	if err := json.Unmarshal(headerJSON, &header); err != nil {
		t.Fatal(err)
	}
	if header.Alg != "ECDH-ES" || header.Enc != "A128GCM" || header.Kid != "enc-1" {
		t.Fatalf("unexpected JWE header: %+v", header)
	}
	ex, _ := base64.RawURLEncoding.DecodeString(header.EPK.X)
	ey, _ := base64.RawURLEncoding.DecodeString(header.EPK.Y)
	ephemeralPub, err := curve.NewPublicKey(append([]byte{4}, append(ex, ey...)...))
	if err != nil {
		t.Fatal(err)
	}
	secret, err := verifierKey.ECDH(ephemeralPub)
	if err != nil {
		t.Fatal(err)
	}
	cek := concatKDF(secret, header.Enc, 16)
	block, _ := aes.NewCipher(cek)
	gcm, _ := cipher.NewGCM(block)
	iv, _ := base64.RawURLEncoding.DecodeString(parts[2])
	ciphertext, _ := base64.RawURLEncoding.DecodeString(parts[3])
	tag, _ := base64.RawURLEncoding.DecodeString(parts[4])
	plain, err := gcm.Open(nil, iv, append(ciphertext, tag...), []byte(parts[0]))
	if err != nil {
		t.Fatal(err)
	}
	var got presentation.AuthorizationResponse
	if err := json.Unmarshal(plain, &got); err != nil {
		t.Fatal(err)
	}
	if got.State != response.State || len(got.VPToken["credential-1"]) != 1 {
		t.Fatalf("unexpected response after decrypt: %+v", got)
	}
}
