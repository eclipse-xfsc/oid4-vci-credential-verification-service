package common

import "testing"

func TestResolveTenantEndpoint(t *testing.T) {
	tests := []struct {
		origin, endpoint, want string
		fail                   bool
	}{
		{"https://demo-tenant.example.de", "/wallet/authorize", "https://demo-tenant.example.de/wallet/authorize", false},
		{"https://demo-tenant2.example.de", "/wallet/authorize", "https://demo-tenant2.example.de/wallet/authorize", false},
		{"", "https://wallet.example.com/consent", "https://wallet.example.com/consent", false},
		{"", "/wallet/authorize", "", true},
		{"https://example.com/evil", "/wallet/authorize", "", true},
		{"https://example.com", "//evil.example/", "", true},
	}
	for _, tt := range tests {
		got, err := ResolveTenantEndpoint(tt.origin, tt.endpoint)
		if (err != nil) != tt.fail || (!tt.fail && got != tt.want) {
			t.Errorf("ResolveTenantEndpoint(%q, %q) = %q, %v", tt.origin, tt.endpoint, got, err)
		}
	}
}
