package services

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/eclipse-xfsc/oid4-vci-credential-verification-service/internal/model"
)

func TestExternalURLsRequireHTTPSOutsideDev(t *testing.T) {
	prod := &model.Config{}
	if _, err := validateOutboundURL("http://example.org/request.jwt", prod, true); err == nil {
		t.Fatal("HTTP must be rejected in production")
	}
	if _, err := validateOutboundURL("https://127.0.0.1/private", prod, true); err == nil {
		t.Fatal("loopback must be rejected in production")
	}
	dev := &model.Config{IsDev: true}
	if _, err := validateOutboundURL("http://127.0.0.1/request.jwt", dev, true); err != nil {
		t.Fatal(err)
	}
}

func TestRedirectsAreNotFollowed(t *testing.T) {
	targetCalled := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/redirect" {
			http.Redirect(w, r, "/target", http.StatusFound)
			return
		}
		targetCalled = true
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()
	resp, err := secureHTTPClient().Get(server.URL + "/redirect")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("expected 302, got %d", resp.StatusCode)
	}
	if targetCalled {
		t.Fatal("redirect target was called")
	}
}
