package services

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"testing"

	"github.com/eclipse-xfsc/microservice-core-go/pkg/logr"

	"github.com/eclipse-xfsc/oid4-vci-credential-verification-service/internal/model"
	"github.com/eclipse-xfsc/oid4-vci-vp-library/model/presentation"
	"github.com/stretchr/testify/require"
)

func TestFromProofModelToPresentation(t *testing.T) {
	file, err := os.Open("./pres_test.json")
	require.Nil(t, err)
	bdata, err := io.ReadAll(file)
	require.Nil(t, err)
	var payload []presentation.FilterResult
	err = json.Unmarshal(bdata, &payload)
	require.Nil(t, err)
	proof := model.ProofModel{
		Payload:       payload,
		SignNamespace: "test",
		SignKey:       "test",
		SignGroup:     "test",
		HolderDid:     "test",
	}
	pres, err := fromProofModelToPresentation(proof, logr.Logger{})
	b, _ := json.MarshalIndent(pres, "", " ")
	fmt.Println(string(b))
	require.Nil(t, err)

}
