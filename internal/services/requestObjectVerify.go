package services

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	ssijwt "github.com/eclipse-xfsc/ssi-jwt/v2"
	"github.com/lestrrat-go/jwx/v2/jwt"
)

// verifyExternalRequestJWT supports the DID-based OID4VP verifier profile.
// The unverified payload is used ONLY to choose the expected DID identity.
// The SSI-JWT library resolves the DID verification method and checks the JWS.
// Other client_id methods fail closed until dedicated resolvers are provided.
func verifyExternalRequestJWT(_ context.Context, compact, outerClientID string) (map[string]interface{}, error) {
	parts := strings.Split(compact, ".")
	if len(parts) != 3 {
		return nil, errors.New("request object must be compact JWS")
	}
	decode := func(v string) (map[string]interface{}, error) {
		b, err := base64.RawURLEncoding.DecodeString(v)
		if err != nil {
			return nil, err
		}
		var m map[string]interface{}
		err = json.Unmarshal(b, &m)
		return m, err
	}
	header, err := decode(parts[0])
	if err != nil {
		return nil, err
	}
	claims, err := decode(parts[1])
	if err != nil {
		return nil, err
	}
	clientID, _ := claims["client_id"].(string)
	if clientID == "" || clientID != outerClientID {
		return nil, errors.New("outer and signed client_id mismatch")
	}
	// Supported profile: DID client_id (including the OID4VP prefixed form).
	did := strings.TrimPrefix(clientID, "decentralized_identifier:")
	if !strings.HasPrefix(did, "did:") {
		return nil, errors.New("unsupported client_id method: only DID is enabled")
	}
	kid, _ := header["kid"].(string)
	if kid == "" || !strings.HasPrefix(kid, did+"#") {
		return nil, errors.New("kid must reference a verification method of client DID")
	}
	if header["jwk"] != nil || header["jku"] != nil || header["x5u"] != nil {
		return nil, errors.New("untrusted JWS key source forbidden")
	}
	alg, _ := header["alg"].(string)
	switch alg {
	case "EdDSA", "ES256", "RS256", "PS256":
	default:
		return nil, errors.New("unsupported JWS algorithm")
	}
	token, err := ssijwt.Parse(compact, jwt.WithValidate(true))
	if err != nil {
		return nil, fmt.Errorf("DID request object signature verification failed: %w", err)
	}
	verifiedBytes, err := json.Marshal(token)
	if err != nil {
		return nil, err
	}
	var verified map[string]interface{}
	if err := json.Unmarshal(verifiedBytes, &verified); err != nil {
		return nil, err
	}
	if verified["client_id"] != clientID {
		return nil, errors.New("verified client_id mismatch")
	}
	if issuer, ok := verified["iss"].(string); ok && issuer != "" && issuer != clientID {
		return nil, errors.New("request object issuer/client_id mismatch")
	}
	return verified, nil
}
