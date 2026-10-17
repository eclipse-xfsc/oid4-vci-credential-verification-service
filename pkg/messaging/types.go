package messaging

import (
	"github.com/eclipse-xfsc/nats-message-library/common"
	"github.com/eclipse-xfsc/oid4-vci-vp-library/model/presentation"
)

const (
	PresentationAuthorizationType       = "verifier.presentation.authorization"
	PresentationAuthorizationErrorType  = "verifier.presentation.authorization.error"
	PresentationAuthorizationRemoteType = "verifier.presentation.authorization.remote"
)

type PresentationAuthorizationCreationRequest struct {
	common.Request
	DCQLQuery        presentation.DCQLQuery `json:"dcql_query"`
	ClientID         string                 `json:"client_id"`
	Ttl              int                    `json:"ttl"`
	TenantUri        string                 `json:"tenant_uri"`
	TargetUri        string                 `json:"target_uri"`
	RequestObjectUri string                 `json:"requestobject_uri"`
	Nonce            []byte                 `json:"nonce"`
}

type PresentationAuthorizationCreationReply struct {
	BaseReply      common.Reply
	PresentationId string `json:"presentation_id"`
	RequestUri     string `json:"request_uri"`
}

type PresentationAuthorizationRemoteRequest struct {
	common.Request

	URL string `json:"url"`

	Ttl int    `json:"ttl,omitempty"`
	Did string `json:"did,omitempty"`
	Key string `json:"key,omitempty"`
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
