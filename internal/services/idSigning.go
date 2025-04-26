package services

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"strings"

	"github.com/segmentio/asm/base64"
)

func decodeKey(key string) (*ecdsa.PrivateKey, error) {
	var b []byte
	var err error
	if !strings.Contains(key, "BEGIN") {
		b, err = base64.StdEncoding.DecodeString(key)
	} else {
		b = []byte(key)
	}

	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(b)
	if block == nil || block.Type != "EC PRIVATE KEY" {
		return nil, errors.New("Not a ECDSA Key")
	}

	// Parse den ASN.1-Struktur des privaten Schlüssels
	privateKey, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	return privateKey.(*ecdsa.PrivateKey), nil
}

func SignId(message, key string) (string, error) {

	privateKey, err := decodeKey(key)

	if err != nil {
		return "", err
	}

	hashed := sha256.Sum256([]byte(message))

	r, s, err := ecdsa.Sign(rand.Reader, privateKey, hashed[:])
	if err != nil {
		return "", err
	}

	signatureDER, err := asn1.Marshal(struct{ R, S *big.Int }{r, s})
	if err != nil {
		return "", err
	}

	signatureBase64 := base64.RawURLEncoding.EncodeToString(signatureDER)

	return signatureBase64, nil
}

func VerifyId(message, signatureBase64, key string) (bool, error) {

	privateKey, err := decodeKey(key)

	if err != nil {
		return false, err
	}

	hashed := sha256.Sum256([]byte(message))

	signatureDER, err := base64.RawURLEncoding.DecodeString(signatureBase64)
	if err != nil {
		fmt.Println("Error decoding signature:", err)
		return false, err
	}

	// Dekodieren der Signatur
	var signature struct{ R, S *big.Int }
	_, err = asn1.Unmarshal(signatureDER, &signature)
	if err != nil {
		fmt.Println("error unmarshalling asn1:", err)
		return false, err
	}

	// Überprüfen der Signatur
	return ecdsa.Verify(&privateKey.PublicKey, hashed[:], signature.R, signature.S), nil
}
