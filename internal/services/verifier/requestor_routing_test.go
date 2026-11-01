package verifier

import (
	"encoding/json"
	"github.com/eclipse-xfsc/oid4-vci-credential-verification-service/internal/model"
	"testing"
)

func TestRequestObjectSignerRouting(t *testing.T) {
	row := &model.VerificationEntry{TenantId: "tenant-a", GroupId: "account-group", RequestId: "authorization-id", ProfileKeyNamespace: "crypto-namespace", ProfileKeyGroup: "crypto-group", ProfileKeyID: "key-a"}
	req := createRequestObjectTokenRequest(row, []byte("payload"))
	raw, err := json.Marshal(req)
	if err != nil {
		t.Fatal(err)
	}
	var wire map[string]interface{}
	if err := json.Unmarshal(raw, &wire); err != nil {
		t.Fatal(err)
	}
	for key, want := range map[string]string{"tenant_id": row.TenantId, "group_id": row.GroupId, "namespace": row.ProfileKeyNamespace, "group": row.ProfileKeyGroup, "key": row.ProfileKeyID} {
		if wire[key] != want {
			t.Errorf("%s = %v, want %s", key, wire[key], want)
		}
	}
	if req.RequestId == "" || req.RequestId == row.RequestId {
		t.Fatal("signer call requires its own correlation ID")
	}
	if string(req.Payload) != "payload" {
		t.Fatal("payload changed")
	}
}
