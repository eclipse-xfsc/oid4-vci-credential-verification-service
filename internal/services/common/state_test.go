package common

import (
	"strings"
	"testing"

	appCommon "github.com/eclipse-xfsc/oid4-vci-credential-verification-service/internal/common"
	"github.com/eclipse-xfsc/oid4-vci-credential-verification-service/internal/model"
)

func configureStateSigningKey(t *testing.T, key string) {
	t.Helper()
	cfg := &model.Config{StateSigningKey: key}
	appCommon.GetEnvironment().SetConfig(cfg)
	t.Cleanup(func() { appCommon.GetEnvironment().SetConfig(nil) })
}

func TestVerificationStateRoundTrip(t *testing.T) {
	configureStateSigningKey(t, "test-state-signing-key-with-enough-entropy")
	state, err := EncodeVerificationState("group/with:special chars", "request-123")
	if err != nil {
		t.Fatal(err)
	}
	got, err := DecodeVerificationState(state)
	if err != nil {
		t.Fatal(err)
	}
	if got.GroupId != "group/with:special chars" || got.RequestId != "request-123" {
		t.Fatalf("unexpected roundtrip: %#v", got)
	}
}

func TestVerificationStateRejectsTampering(t *testing.T) {
	configureStateSigningKey(t, "test-state-signing-key-with-enough-entropy")
	state, err := EncodeVerificationState("group-a", "request-123")
	if err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(state, ".")
	if len(parts) != 2 {
		t.Fatalf("unexpected state format: %q", state)
	}
	// Keep the signature but replace the signed payload with another valid payload.
	other, err := EncodeVerificationState("group-b", "request-123")
	if err != nil {
		t.Fatal(err)
	}
	otherParts := strings.Split(other, ".")
	tampered := otherParts[0] + "." + parts[1]
	if _, err := DecodeVerificationState(tampered); err == nil {
		t.Fatal("expected tampered state to be rejected")
	}
}

func TestVerificationStateRequiresKey(t *testing.T) {
	appCommon.GetEnvironment().SetConfig(&model.Config{})
	t.Cleanup(func() { appCommon.GetEnvironment().SetConfig(nil) })
	if _, err := EncodeVerificationState("group-a", "request-123"); err == nil {
		t.Fatal("expected missing signing key to fail")
	}
}
