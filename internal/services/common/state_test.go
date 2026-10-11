package common

import "testing"

func TestVerificationStateRoundTrip(t *testing.T) {
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
