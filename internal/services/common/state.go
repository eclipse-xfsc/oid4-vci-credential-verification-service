package common

import (
	"encoding/base64"
	"encoding/json"
	"errors"
)

type VerificationState struct {
	GroupId   string `json:"groupId"`
	RequestId string `json:"requestId"`
}

func EncodeVerificationState(groupId, requestId string) (string, error) {
	if groupId == "" || requestId == "" {
		return "", errors.New("groupId and requestId must not be empty")
	}
	b, err := json.Marshal(VerificationState{GroupId: groupId, RequestId: requestId})
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func DecodeVerificationState(state string) (VerificationState, error) {
	var v VerificationState
	b, err := base64.RawURLEncoding.DecodeString(state)
	if err != nil {
		return v, err
	}
	if err = json.Unmarshal(b, &v); err != nil {
		return v, err
	}
	if v.GroupId == "" || v.RequestId == "" {
		return v, errors.New("invalid verification state")
	}
	return v, nil
}
