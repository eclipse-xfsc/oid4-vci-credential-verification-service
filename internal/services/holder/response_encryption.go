package holder

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/eclipse-xfsc/oid4-vci-vp-library/model/presentation"
)

// oid4vpResponseEncryptor implements the OID4VP direct_post.jwt response
// encryption adapter. direct_post.jwt is deliberately independent from the
// credential format contained in vp_token: both dc+sd-jwt and ldp_vc can be
// transported this way.
type oid4vpResponseEncryptor struct{}

func (oid4vpResponseEncryptor) EncryptAuthorizationResponse(_ context.Context, response presentation.AuthorizationResponse, metadata *presentation.VerifierMetadata) (string, error) {
	if metadata == nil || metadata.JWKS == nil || len(metadata.JWKS.Keys) == 0 {
		return "", errors.New("direct_post.jwt requires verifier client_metadata.jwks")
	}
	key, err := selectECDHESKey(metadata.JWKS.Keys)
	if err != nil {
		return "", err
	}
	enc, keyLen, err := selectContentEncryption(metadata.EncryptedResponseEncValuesSupported)
	if err != nil {
		return "", err
	}
	return encryptECDHES(response, key, enc, keyLen)
}

func selectECDHESKey(keys []map[string]any) (map[string]any, error) {
	for _, key := range keys {
		alg, _ := key["alg"].(string)
		use, _ := key["use"].(string)
		kty, _ := key["kty"].(string)
		crv, _ := key["crv"].(string)
		if alg == "ECDH-ES" && (use == "" || use == "enc") && kty == "EC" && crv == "P-256" {
			return key, nil
		}
	}
	return nil, errors.New("direct_post.jwt requires an ECDH-ES P-256 encryption key in verifier metadata")
}

func selectContentEncryption(supported []string) (string, int, error) {
	// OID4VP permits A128GCM as the default. Prefer it when the verifier lists
	// it, then A256GCM. CBC-HMAC can be added independently without changing
	// response-mode or credential-format handling.
	if len(supported) == 0 {
		return "A128GCM", 16, nil
	}
	for _, wanted := range []string{"A128GCM", "A256GCM"} {
		for _, candidate := range supported {
			if candidate == wanted {
				if wanted == "A128GCM" {
					return wanted, 16, nil
				}
				return wanted, 32, nil
			}
		}
	}
	return "", 0, fmt.Errorf("no supported direct_post.jwt content encryption algorithm in %v", supported)
}

func encryptECDHES(response presentation.AuthorizationResponse, jwk map[string]any, enc string, keyLen int) (string, error) {
	xs, _ := jwk["x"].(string)
	ys, _ := jwk["y"].(string)
	kid, _ := jwk["kid"].(string)
	if xs == "" || ys == "" || kid == "" {
		return "", errors.New("verifier encryption JWK requires kid, x and y")
	}
	x, err := base64.RawURLEncoding.DecodeString(xs)
	if err != nil {
		return "", fmt.Errorf("decode verifier JWK x: %w", err)
	}
	y, err := base64.RawURLEncoding.DecodeString(ys)
	if err != nil {
		return "", fmt.Errorf("decode verifier JWK y: %w", err)
	}
	point := append([]byte{4}, append(x, y...)...)
	curve := ecdh.P256()
	peer, err := curve.NewPublicKey(point)
	if err != nil {
		return "", fmt.Errorf("invalid verifier P-256 key: %w", err)
	}
	ephemeral, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		return "", err
	}
	secret, err := ephemeral.ECDH(peer)
	if err != nil {
		return "", fmt.Errorf("ECDH-ES key agreement failed: %w", err)
	}
	cek := concatKDF(secret, enc, keyLen)
	block, err := aes.NewCipher(cek)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	epub := ephemeral.PublicKey().Bytes()
	coordLen := (len(epub) - 1) / 2
	header := map[string]any{
		"alg": "ECDH-ES", "enc": enc, "kid": kid,
		"epk": map[string]any{
			"kty": "EC", "crv": "P-256",
			"x": base64.RawURLEncoding.EncodeToString(epub[1 : 1+coordLen]),
			"y": base64.RawURLEncoding.EncodeToString(epub[1+coordLen:]),
		},
	}
	headerJSON, err := json.Marshal(header)
	if err != nil {
		return "", err
	}
	protected := base64.RawURLEncoding.EncodeToString(headerJSON)
	plaintext, err := json.Marshal(response)
	if err != nil {
		return "", err
	}
	iv := make([]byte, gcm.NonceSize())
	if _, err = rand.Read(iv); err != nil {
		return "", err
	}
	sealed := gcm.Seal(nil, iv, plaintext, []byte(protected))
	tagLen := gcm.Overhead()
	ciphertext, tag := sealed[:len(sealed)-tagLen], sealed[len(sealed)-tagLen:]
	return strings.Join([]string{
		protected,
		"", // ECDH-ES direct key agreement has no encrypted-key value.
		base64.RawURLEncoding.EncodeToString(iv),
		base64.RawURLEncoding.EncodeToString(ciphertext),
		base64.RawURLEncoding.EncodeToString(tag),
	}, "."), nil
}

func concatKDF(secret []byte, algorithm string, keyLen int) []byte {
	// RFC 7518 section 4.6.2 / NIST SP 800-56A Concat KDF.
	otherInfo := append(lengthPrefixed([]byte(algorithm)), lengthPrefixed(nil)...)
	otherInfo = append(otherInfo, lengthPrefixed(nil)...)
	bits := make([]byte, 4)
	binary.BigEndian.PutUint32(bits, uint32(keyLen*8))
	otherInfo = append(otherInfo, bits...)

	out := make([]byte, 0, keyLen)
	for counter := uint32(1); len(out) < keyLen; counter++ {
		h := sha256.New()
		var c [4]byte
		binary.BigEndian.PutUint32(c[:], counter)
		h.Write(c[:])
		h.Write(secret)
		h.Write(otherInfo)
		out = append(out, h.Sum(nil)...)
	}
	return out[:keyLen]
}

func lengthPrefixed(v []byte) []byte {
	out := make([]byte, 4+len(v))
	binary.BigEndian.PutUint32(out[:4], uint32(len(v)))
	copy(out[4:], v)
	return out
}
