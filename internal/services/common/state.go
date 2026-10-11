package common

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	appCommon "github.com/eclipse-xfsc/oid4-vci-credential-verification-service/internal/common"
)

type VerificationState struct {
	GroupId   string `json:"groupId"`
	RequestId string `json:"requestId"`
}

func stateSigningKey() ([]byte, error) {
	cfg := appCommon.GetEnvironment().GetConfig()
	if cfg == nil || cfg.StateSigningKey == "" {
		return nil, errors.New("state signing key is not configured")
	}
	return []byte(cfg.StateSigningKey), nil
}

// EncodeVerificationState creates an opaque-ish, URL-safe state token in the form
// base64url(payload).base64url(HMAC-SHA256(payload)). The payload is not encrypted;
// the HMAC prevents undetected modification of groupId/requestId.
func EncodeVerificationState(groupId, requestId string) (string, error) {
	if groupId == "" || requestId == "" {
		return "", errors.New("groupId and requestId must not be empty")
	}
	key, err := stateSigningKey()
	if err != nil {
		return "", err
	}
	payload, err := json.Marshal(VerificationState{GroupId: groupId, RequestId: requestId})
	if err != nil {
		return "", err
	}
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write(payload)
	signature := mac.Sum(nil)
	return base64.RawURLEncoding.EncodeToString(payload) + "." + base64.RawURLEncoding.EncodeToString(signature), nil
}

func DecodeVerificationState(state string) (VerificationState, error) {
	var v VerificationState
	parts := strings.Split(state, ".")
	if len(parts) != 2 {
		return v, errors.New("invalid verification state format")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return v, fmt.Errorf("decode verification state payload: %w", err)
	}
	signature, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return v, fmt.Errorf("decode verification state signature: %w", err)
	}
	key, err := stateSigningKey()
	if err != nil {
		return v, err
	}
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write(payload)
	if !hmac.Equal(signature, mac.Sum(nil)) {
		return v, errors.New("invalid verification state signature")
	}
	if err = json.Unmarshal(payload, &v); err != nil {
		return v, fmt.Errorf("decode verification state json: %w", err)
	}
	if v.GroupId == "" || v.RequestId == "" {
		return v, errors.New("invalid verification state")
	}
	return v, nil
}
