package services

import (
	"encoding/base64"
	"testing"
)

func Test_Signing(t *testing.T) {

	key := "LS0tLS1CRUdJTiBFQyBQUklWQVRFIEtFWS0tLS0tCk1FRUNBUUF3RXdZSEtvWkl6ajBDQVFZSUtvWkl6ajBEQVFjRUp6QWxBZ0VCQkNCNDVQQlk0aVBOY0lwTVd6emYKei9uYXdxbmxIYlhTeFdjNUJWK1hyMzB5dkE9PQotLS0tLUVORCBFQyBQUklWQVRFIEtFWS0tLS0t"
	message := "HelloWorld"

	s, err := SignId(message, key)

	if err != nil || s == "" {
		t.Error()
	}

	b, err := VerifyId(message, s, key)

	if err != nil || !b {
		t.Error()
	}

	b, err = VerifyId("1233", s, key)

	if err != nil || b {
		t.Error()
	}

	b64 := base64.StdEncoding.EncodeToString([]byte{12, 35, 45, 34, 23, 23, 1, 1, 12})

	b, err = VerifyId(message, b64, key)

	if err == nil || b {
		t.Error()
	}
}

func Test_Signing2(t *testing.T) {

	key := "-----BEGIN EC PRIVATE KEY-----\nMEECAQAwEwYHKoZIzj0CAQYIKoZIzj0DAQcEJzAlAgEBBCB45PBY4iPNcIpMWzzf\nz/nawqnlHbXSxWc5BV+Xr30yvA==\n-----END EC PRIVATE KEY-----"
	message := "HelloWorld"

	s, err := SignId(message, key)

	if err != nil || s == "" {
		t.Error()
	}

	b, err := VerifyId(message, s, key)

	if err != nil || !b {
		t.Error()
	}

	b, err = VerifyId("1233", s, key)

	if err != nil || b {
		t.Error()
	}

	b64 := base64.StdEncoding.EncodeToString([]byte{12, 35, 45, 34, 23, 23, 1, 1, 12})

	b, err = VerifyId(message, b64, key)

	if err == nil || b {
		t.Error()
	}
}
