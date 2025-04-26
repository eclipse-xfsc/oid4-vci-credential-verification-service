package main

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"gitlab.eclipse.org/eclipse/xfsc/libraries/messaging/cloudeventprovider"
	"gitlab.eclipse.org/eclipse/xfsc/libraries/ssi/oid4vip/model/presentation"
	"github.com/eclipse-xfsc/oid4-vci-credential-verification-service/pkg/messaging"
	"gitlab.eclipse.org/eclipse/xfsc/organisational-credential-manager-w-stack/libraries/messaging/common"
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
		Request: common.Request{
			TenantId:  "tenant_space",
			RequestId: "sdfdfdf",
			GroupId:   "xy",
		},
		PresentationDefinition: presentation.PresentationDefinition{
			Description: presentation.Description{
				Id:      "23343434343434",
				Name:    "test",
				Purpose: "I wanna see it!",
			},
			InputDescriptors: []presentation.InputDescriptor{
				presentation.InputDescriptor{
					Description: presentation.Description{
						Id:      "Developer Credential",
						Name:    "Developer Credential Request",
						Purpose: "I wanna see it!",
					},
					Format: presentation.Format{
						LDPVC: req.PresentationDefinition.Format.LDP,
					},
					Constraints: presentation.Constraints{
						Fields: []presentation.Field{
							presentation.Field{
								Path: []string{"$.credentialSubject.given_name"},
							},
						},
					},
				},
			},
		},
		Ttl:              3000,
		TenantUri:        "localhost:8080",
		RequestObjectUri: "localhost:8080/v1/tenants/tenant_space/presentation/proof",
		TargetUri:        "localhost:8080/v1/tenants/tenant_space/presentation",
		Nonce:            []byte{34, 34, 11},
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
