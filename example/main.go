package main

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	cloudeventprovider "github.com/eclipse-xfsc/cloud-event-provider"
	"github.com/eclipse-xfsc/nats-message-library/common"
	"github.com/eclipse-xfsc/oid4-vci-credential-verification-service/pkg/messaging"
	"github.com/eclipse-xfsc/oid4-vci-vp-library/model/presentation"
)

func main() {

	createCredentialClient, err := cloudeventprovider.New(
		cloudeventprovider.Config{Protocol: cloudeventprovider.ProtocolTypeNats, Settings: cloudeventprovider.NatsConfig{
			Url:          "nats://localhost:4222",
			TimeoutInSec: time.Hour,
		}},
		cloudeventprovider.ConnectionTypeReq,
		"request",
	)

	if err != nil {
		panic(err)
	}

	var req messaging.PresentationAuthorizationCreationRequest
	req = messaging.PresentationAuthorizationCreationRequest{
		Request:  common.Request{TenantId: "tenant_space", RequestId: "sdfdfdf", GroupId: "xy"},
		ClientID: "decentralized_identifier:did:web:verifier.example",
		DCQLQuery: presentation.DCQLQuery{Credentials: []presentation.CredentialQuery{{
			ID:     "developer_credential",
			Format: "ldp_vc",
			Meta:   map[string]any{},
			Claims: []presentation.ClaimQuery{{Path: presentation.ClaimsPathPointer{"credentialSubject", "given_name"}}},
		}}},
		Ttl:              3000,
		TenantUri:        "localhost:8080",
		RequestObjectUri: "localhost:8080/v1/tenants/tenant_space/presentation/proof",
		TargetUri:        "localhost:8080/v1/tenants/tenant_space/presentation",
	}

	b, _ := json.Marshal(req)

	testEvent, _ := cloudeventprovider.NewEvent("test-issuer", messaging.PresentationAuthorizationType, b)

	ev, err := createCredentialClient.RequestCtx(context.Background(), testEvent)

	if err != nil {
		fmt.Println(err.Error())
		return
	}

	var rep messaging.PresentationAuthorizationCreationReply

	err = json.Unmarshal(ev.Data(), &rep)

	if err != nil {
		fmt.Println(err.Error())
		return
	}

	if rep.BaseReply.Error != nil {
		fmt.Println("error")
		return
	}

	fmt.Println(rep.PresentationId)
	fmt.Println("\n")
	fmt.Println(rep.RequestUri)

}
