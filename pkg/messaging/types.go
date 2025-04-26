package messaging

import (
	"gitlab.eclipse.org/eclipse/xfsc/libraries/ssi/oid4vip/model/presentation"
	"gitlab.eclipse.org/eclipse/xfsc/organisational-credential-manager-w-stack/libraries/messaging/common"
)

const (
	PresentationAuthorizationType       = "verifier.presentation.authorization"
	PresentationAuthorizationErrorType  = "verifier.presentation.authorization.error"
	PresentationAuthorizationRemoteType = "verifier.presentation.authorization.remote"
)

type PresentationAuthorizationCreationRequest struct {
	common.Request
	PresentationDefinition presentation.PresentationDefinition `json:"presentationDefinition"`
	Ttl                    int                                 `json:"ttl"`
	TenantUri              string                              `json:"tenant_uri"`
	TargetUri              string                              `json:"target_uri"`
	RequestObjectUri       string                              `json:"requestobject_uri"`
	Nonce                  []byte                              `json:"nonce"`
}

type PresentationAuthorizationCreationReply struct {
	BaseReply      common.Reply
	PresentationId string `json:"presentation_id"`
	RequestUri     string `json:"request_uri"`
}

type PresentationAuthorizationRemoteRequest struct {
	common.Request
	ClientId   string `json:"clientId"`
	RequestUri string `json:"request_uri"`
	Ttl        int    `json:"ttl"`
	Did        string `json:"did"`
	Key        string `json:"key"`
}

type PresentationAuthorizationRemoteReply struct {
	common.Reply
}

const (
	ProofNotifyType = "verifier.proof.notification"
)

type ProofNotifyEvent struct {
	common.Reply
	PresentationId string `json:"presentation_id"`
	Status         string `json:"status"`
}
