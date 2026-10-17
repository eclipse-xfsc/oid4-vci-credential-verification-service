package verifier

import (
	"testing"

	"github.com/eclipse-xfsc/oid4-vci-vp-library/model/types"
)

func TestPresentationVerifyFormat(t *testing.T) {
	tests := []struct {
		name    string
		format  types.CredentialFormat
		want    string
		wantErr bool
	}{
		{name: "ldp vc", format: types.LDPVC, want: "ldp_vc"},
		{name: "sd jwt", format: types.SDJWT, want: "dc+sd-jwt"},
		{name: "unsupported", format: types.CredentialFormat("mso_mdoc"), wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := presentationVerifyFormat(tt.format)
			if (err != nil) != tt.wantErr {
				t.Fatalf("presentationVerifyFormat() error = %v, wantErr %v", err, tt.wantErr)
			}
			if got != tt.want {
				t.Fatalf("presentationVerifyFormat() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestPresentationBytesSDJWT(t *testing.T) {
	got, err := presentationBytes([]byte(`"header.payload.signature~disclosure~kbjwt"`), types.SDJWT)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "header.payload.signature~disclosure~kbjwt" {
		t.Fatalf("unexpected SD-JWT presentation: %q", got)
	}
}

func TestPresentationBytesLDPVC(t *testing.T) {
	raw := []byte(`{"@context":["https://www.w3.org/2018/credentials/v1"],"type":["VerifiablePresentation"]}`)
	got, err := presentationBytes(raw, types.LDPVC)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(raw) {
		t.Fatalf("presentation changed: %s", got)
	}
}
