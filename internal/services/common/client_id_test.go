package common

import "testing"

func TestClientIDFromDID(t *testing.T) {
	got, err := ClientIDFromDID("did:web:tenant.example.org")
	if err != nil || got != "decentralized_identifier:did:web:tenant.example.org" {
		t.Fatalf("got %q, err %v", got, err)
	}
	for _, bad := range []string{"", "https://tenant.example.org", "decentralized_identifier:did:web:tenant.example.org", "did:", "did:web:"} {
		if _, err := ClientIDFromDID(bad); err == nil {
			t.Errorf("accepted %q", bad)
		}
	}
}
