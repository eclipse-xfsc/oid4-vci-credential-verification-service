package common

import (
	"bytes"
	"encoding/json"
	logr "github.com/eclipse-xfsc/microservice-core-go/pkg/logr"
	app "github.com/eclipse-xfsc/oid4-vci-credential-verification-service/internal/common"
	"testing"
)

func TestRoutingLogFields(t *testing.T) {
	var output bytes.Buffer
	logger, err := logr.New("info", false, &output)
	if err != nil {
		t.Fatal(err)
	}
	env := app.GetEnvironment()
	previous := env.GetLogger()
	env.SetLogger(*logger)
	defer env.SetLogger(previous)
	LogRouting("test.stage", "tenant", "account-group", "request", "namespace", "crypto-group", "key", true)
	var entry map[string]interface{}
	if err := json.Unmarshal(output.Bytes(), &entry); err != nil {
		t.Fatal(err)
	}
	for key, want := range map[string]interface{}{"stage": "test.stage", "tenantId": "tenant", "groupId": "account-group", "requestId": "request", "namespace": "namespace", "keyGroup": "crypto-group", "keyId": "key", "failed": true} {
		if entry[key] != want {
			t.Errorf("%s = %v, want %v", key, entry[key], want)
		}
	}
	for _, key := range []string{"payload", "jwt", "token", "nonce", "secret", "configuration"} {
		if _, exists := entry[key]; exists {
			t.Errorf("sensitive field %s logged", key)
		}
	}
}
