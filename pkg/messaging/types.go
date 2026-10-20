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
	PresentationPolicyID string `json:"presentation_policy_id"`
	ClientID             string `json:"client_id"`
	Ttl                  int    `json:"ttl"`
	TenantUri            string `json:"tenant_uri"`
	TargetUri            string `json:"target_uri"`
	RequestObjectUri     string `json:"requestobject_uri"`
	Nonce                []byte `json:"nonce"`
}

type PresentationAuthorizationCreationReply struct {
	BaseReply      common.Reply
	PresentationId string `json:"presentation_id"`
	RequestUri     string `json:"request_uri"`
}

type PresentationAuthorizationRemoteRequest struct {
	common.Request

	URL         string `json:"url"`
	ConsentMode string `json:"consentMode"`

	Ttl       int    `json:"ttl,omitempty"`
	Did       string `json:"did,omitempty"`
	Key       string `json:"key,omitempty"`
	Namespace string `json:"namespace,omitempty"`
	Group     string `json:"group,omitempty"`
}

type PresentationAuthorizationRemoteReply struct {
	common.Reply
	PresentationId string `json:"presentation_id"`
}

const (
	ProofNotifyType = "verifier.proof.notification"
)

type ProofNotifyEvent struct {
	common.Reply
	PresentationId string `json:"presentation_id"`
	Status         string `json:"status"`
}

const PresentationResultGetType = "verifier.presentation.result.get"
const PresentationResultReplyType = "verifier.presentation.result.reply"

type PresentationResultGetRequest struct {
	TenantID       string `json:"tenant_id"`
	GroupID        string `json:"group_id"`
	PresentationID string `json:"presentation_id"`
}

type PresentationResultGetReply struct {
	PresentationID string               `json:"presentation_id"`
	RequestID      string               `json:"request_id,omitempty"`
	GroupID        string               `json:"group_id,omitempty"`
	Status         string               `json:"status,omitempty"`
	Presentation   presentation.VPToken `json:"presentation,omitempty"`
	Error          string               `json:"error,omitempty"`
}
