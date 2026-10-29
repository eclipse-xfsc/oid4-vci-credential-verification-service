package verifier

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/eclipse-xfsc/oid4-vci-vp-library/model/presentation"

	logr "github.com/eclipse-xfsc/microservice-core-go/pkg/logr"

	"github.com/cloudevents/sdk-go/v2/event"
	cloudeventprovider "github.com/eclipse-xfsc/cloud-event-provider"
	msg "github.com/eclipse-xfsc/crypto-provider-service/v2/pkg/messaging"
	commonMessageTypes "github.com/eclipse-xfsc/nats-message-library/common"
	"github.com/eclipse-xfsc/oid4-vci-credential-verification-service/internal/model"
	"github.com/eclipse-xfsc/oid4-vci-credential-verification-service/internal/services/common"
	"github.com/eclipse-xfsc/oid4-vci-credential-verification-service/pkg/messaging"
	"github.com/google/uuid"
)

type PresentationRequestor struct {
	client                   *cloudeventprovider.CloudEventProviderClient
	notifyClient             *cloudeventprovider.CloudEventProviderClient
	storageClient            *cloudeventprovider.CloudEventProviderClient
	signerClient             *cloudeventprovider.CloudEventProviderClient
	logger                   logr.Logger
	presentationRequestTopic string
	storagePubTopic          string
	config                   *model.Config
}

const CredentialApiGroup = "/presentation"
const InternalApiGroup = "/internal"
const DirectGroup = "/proof"

func (requestor *PresentationRequestor) Initialize(config *model.Config, logger logr.Logger) error {
	requestor.logger = logger
	requestor.config = config

	if config.PresentationRequest == "" {
		return errors.New("Invalid Subject for Nats.")
	}

	requestor.presentationRequestTopic = config.PresentationRequest
	requestor.storagePubTopic = config.StorageRequest

	client, err := cloudeventprovider.New(cloudeventprovider.Config{Protocol: cloudeventprovider.ProtocolTypeNats, Settings: cloudeventprovider.NatsConfig{
		Url:          config.Nats.Url,
		QueueGroup:   config.Nats.QueueGroup,
		TimeoutInSec: time.Minute,
	}}, cloudeventprovider.Rep, config.PresentationRequest)

	if err != nil {
		logger.Error(err, "Error during message creation")
		return err
	}

	requestor.client = client

	client2, err := cloudeventprovider.New(cloudeventprovider.Config{Protocol: config.Protocol, Settings: cloudeventprovider.NatsConfig{
		Url:          config.Nats.Url,
		QueueGroup:   config.Nats.QueueGroup,
		TimeoutInSec: time.Minute,
	}}, cloudeventprovider.Pub, config.ProofNotify)

	if err != nil {
		logger.Error(err, "Error during message creation")
		return err
	}

	requestor.notifyClient = client2

	client3, err := cloudeventprovider.New(cloudeventprovider.Config{Protocol: config.Protocol, Settings: cloudeventprovider.NatsConfig{
		Url:          config.Nats.Url,
		QueueGroup:   config.Nats.QueueGroup,
		TimeoutInSec: time.Minute,
	}}, cloudeventprovider.Pub, config.StorageRequest)

	if err != nil {
		logger.Error(err, "Error during message creation")
		return err
	}

	requestor.storageClient = client3

	client4, err := cloudeventprovider.New(cloudeventprovider.Config{Protocol: config.Protocol, Settings: cloudeventprovider.NatsConfig{
		Url:          config.Nats.Url,
		QueueGroup:   config.Nats.QueueGroup,
		TimeoutInSec: time.Minute,
	}}, cloudeventprovider.Req, config.SignerService.SignerTopic)

	if err != nil {
		logger.Error(err, "Error during message creation")
		return err
	}

	requestor.signerClient = client4

	return err
}

func (requestor *PresentationRequestor) GetRequestObjectAndSetObjectFetched(ctx context.Context, schema, host, path string, id string, tenantId, groupId, did, key string) ([]byte, error) {

	// The request-object endpoint is called by external wallets, which do not
	// send XFSC-specific x-groupId headers. Derive the group exclusively from
	// the cryptographically verified state token.
	state, err := common.DecodeVerificationState(id)
	if err != nil {
		return nil, fmt.Errorf("invalid request object state: %w", err)
	}

	requestor.logger.Info("OID4VP request object requested", "tenantId", tenantId, "groupId", state.GroupId, "requestId", state.RequestId)
	row, err := common.GetEntryFromDb(ctx, tenantId, id)

	if err == nil {
		if row.GroupId != state.GroupId || row.RequestId != state.RequestId {
			return nil, errors.New("request object state does not match stored authorization")
		}
		if row.ProfileKeyNamespace == "" || row.ProfileKeyID == "" {
			return nil, errors.New("missing signer snapshot in authorization state")
		}

		clientUrl, err := url.Parse(row.ProfileOrigin + common.VerifierRequestObjectPath + "/" + url.PathEscape(id))
		if err != nil {
			return nil, err
		}

		authRequest := presentation.AuthorizationRequest{
			ClientID:     row.ClientId,
			ResponseURI:  clientUrl.String(),
			ResponseType: "vp_token",
			Nonce:        row.Nonce,
			State:        id,
			ResponseMode: "direct_post",
			DCQLQuery:    &row.DCQLQuery,
		}
		requestor.logger.Info("OID4VP authorization request prepared", "tenantId", tenantId, "groupId", state.GroupId, "requestId", state.RequestId, "clientId", authRequest.ClientID, "responseUri", authRequest.ResponseURI, "responseMode", authRequest.ResponseMode, "responseType", authRequest.ResponseType)
		if err := authRequest.Validate(); err != nil {
			return nil, fmt.Errorf("invalid OID4VP authorization request: %w", err)
		}

		pb, err := json.Marshal(authRequest)
		if err != nil {
			return nil, err
		}

		// Explicit opt-in: this logs the full authorization request including nonce, state and DCQL.
		// Enable only temporarily in a protected development environment.
		if os.Getenv("OID4VP_DEBUG_REQUEST_OBJECT") == "true" {
			requestor.logger.Info("OID4VP DEBUG unsigned request object payload", "payload", string(pb))
		}

		var req = msg.CreateTokenRequest{
			Request: commonMessageTypes.Request{
				TenantId:  tenantId,
				RequestId: uuid.NewString(),
			},
			Namespace: row.ProfileKeyNamespace,
			Key:       row.ProfileKeyID,
			Payload:   pb,
		}

		js, err := json.Marshal(req)

		if err != nil {
			return nil, err
		}

		ev, err := cloudeventprovider.NewEvent("request", "signer.signToken", js)

		if err != nil {
			return nil, err
		}

		requestor.logger.Info("OID4VP sending signing request", "tenantId", tenantId, "requestId", state.RequestId, "namespace", row.ProfileKeyNamespace, "keyId", row.ProfileKeyID)
		res, err := requestor.signerClient.RequestCtx(ctx, ev)

		if err != nil {
			return nil, err
		}

		var rep msg.CreateTokenReply

		err = json.Unmarshal(res.DataEncoded, &rep)

		if err != nil {
			return nil, err
		}

		requestor.logger.Info("OID4VP signer replied", "tenantId", tenantId, "requestId", state.RequestId, "tokenBytes", len(rep.Token))
		if os.Getenv("OID4VP_DEBUG_REQUEST_OBJECT") == "true" {
			requestor.logger.Info("OID4VP DEBUG signed request object JWT", "jwt", string(rep.Token))
		}

		err = common.UpdateDbStatus(ctx, tenantId, string(model.PresentationRequestObjectFetched), id)

		if err != nil {
			return nil, err
		}

		return rep.Token, nil
	}
	return nil, err
}

func (requestor *PresentationRequestor) reply(ctx context.Context, event event.Event) (*event.Event, error) {
	if event.Type() == messaging.PresentationResultGetType {
		var query messaging.PresentationResultGetRequest
		if err := json.Unmarshal(event.Data(), &query); err != nil {
			return requestor.presentationResultReply(messaging.PresentationResultGetReply{Error: "invalid request JSON"})
		}
		if query.TenantID == "" || query.GroupID == "" || query.PresentationID == "" {
			return requestor.presentationResultReply(messaging.PresentationResultGetReply{Error: "tenant_id, group_id and presentation_id required"})
		}
		row, err := common.GetEntryFromDb(ctx, query.TenantID, query.PresentationID)
		if err != nil {
			return requestor.presentationResultReply(messaging.PresentationResultGetReply{PresentationID: query.PresentationID, Error: "transaction not found"})
		}
		if row.GroupId != query.GroupID {
			return requestor.presentationResultReply(messaging.PresentationResultGetReply{PresentationID: query.PresentationID, Error: "group access denied"})
		}
		reply := messaging.PresentationResultGetReply{PresentationID: query.PresentationID, RequestID: row.RequestId, GroupID: row.GroupId, Status: row.State}
		if row.State == string(model.PresentationReceived) && len(row.Presentation) > 0 {
			reply.Presentation = row.Presentation
		} else {
			reply.Error = "verified presentation not yet available"
		}
		return requestor.presentationResultReply(reply)
	}

	if strings.Compare(event.Type(), messaging.PresentationAuthorizationType) == 0 {

		var authorizationRequest messaging.PresentationAuthorizationCreationRequest

		reply := messaging.PresentationAuthorizationCreationReply{
			BaseReply: commonMessageTypes.Reply{
				TenantId:  authorizationRequest.TenantId,
				RequestId: authorizationRequest.RequestId,
			},
		}

		err := json.Unmarshal(event.Data(), &authorizationRequest)

		if err != nil {
			return nil, errors.New("problem during marshaling")
		}

		if authorizationRequest.PermissionSet == "" {
			return requestor.AuthorizationReplyError(reply, errors.New("permission_set required"), "invalid authorization")
		}

		state, err := common.EncodeVerificationState(authorizationRequest.GroupId, authorizationRequest.RequestId)
		if err != nil {
			return requestor.AuthorizationReplyError(reply, err, "error during state creation")
		}

		reply.PresentationId = state // compatibility: this field now carries the opaque verification state
		profile, profileErr := common.GetPresentationProfile(ctx, authorizationRequest.TenantId, authorizationRequest.GroupId, "verifier", "machine")
		if profileErr != nil {
			return requestor.AuthorizationReplyError(reply, profileErr, "profile lookup failed")
		}
		clientID := "decentralized_identifier:" + profile.DID
		reply.RequestUri, err = requestor.buildUri(profile.Origin, clientID, state)

		requestOptions := common.PresentationRequestOptions{
			TenantId:  authorizationRequest.TenantId,
			RequestId: authorizationRequest.RequestId,
			GroupId:   authorizationRequest.GroupId,
			Ttl:       authorizationRequest.Ttl,
			ClientId:  clientID,
		}

		if err != nil {
			return requestor.AuthorizationReplyError(reply, err, "error during build uri")
		}

		_, err = requestor.CreateFromPolicy(ctx, authorizationRequest.TenantId, authorizationRequest.GroupId, "machine", authorizationRequest.PermissionSet, requestOptions)

		if err != nil {
			return requestor.AuthorizationReplyError(reply, err, "error during db adding")
		}

		b, err := json.Marshal(reply)

		if err != nil {
			return requestor.AuthorizationReplyError(reply, err, "error in json marshalling")
		}

		e, err := cloudeventprovider.NewEvent(requestor.presentationRequestTopic, messaging.PresentationAuthorizationType, b)

		return &e, err
	}

	reply := messaging.PresentationAuthorizationCreationReply{}

	return requestor.AuthorizationReplyError(reply, errors.ErrUnsupported, "error in json marshalling")
}

// CreateFromPolicy is shared by internal HTTP and NATS entrypoints.
func (requestor *PresentationRequestor) CreateFromPolicy(ctx context.Context, tenant, group, interaction, permissionSet string, options common.PresentationRequestOptions) (*PresentationPolicy, error) {
	policy, profile, err := ResolvePresentationPolicy(ctx, tenant, group, interaction, permissionSet)
	if err != nil {
		return nil, err
	}
	options.ClientId = "decentralized_identifier:" + profile.DID
	options.ProfileOrigin = profile.Origin
	options.ProfileInteraction = interaction
	options.ProfileKeyNamespace = profile.KeyNamespace
	options.ProfileKeyID = profile.KeyID
	if options.Ttl == 0 {
		options.Ttl = profile.RequestObjectTTLSeconds
	}
	if err = requestor.CreatePresentationRequest(policy.DCQLQuery, options, ctx); err != nil {
		return nil, err
	}
	return policy, nil
}

func (requestor *PresentationRequestor) CreatePresentationRequest(query presentation.DCQLQuery, options common.PresentationRequestOptions, ctx context.Context) error {
	if err := query.Validate(); err != nil {
		return err
	}
	if _, err := presentation.ParseClientIdentifier(options.ClientId); err != nil {
		return fmt.Errorf("invalid client_id: %w", err)
	}
	return common.AddDCQLQueryToDb(query, options, ctx)
}

func (requestor *PresentationRequestor) AuthorizationReplyError(reply messaging.PresentationAuthorizationCreationReply, err error, message string) (*event.Event, error) {

	reply.BaseReply = commonMessageTypes.Reply{
		Error: &commonMessageTypes.Error{
			Status: 500,
			Msg:    fmt.Sprintf("%s: %s", message, err.Error()),
		},
	}

	b, err := json.Marshal(reply)

	if err != nil {
		requestor.logger.Error(err, message, err)
	}

	e, err := cloudeventprovider.NewEvent(requestor.presentationRequestTopic, messaging.PresentationAuthorizationErrorType, b)

	return &e, err
}

func (requestor *PresentationRequestor) Listen() {
	for {
		if err := requestor.client.Reply(requestor.reply); err != nil {
			requestor.logger.Error(err, "Subscription failed.")
		}
	}
}

func (requestor *PresentationRequestor) Close() {
	requestor.client.Close()
}

func (requestor *PresentationRequestor) Alive() bool {
	return requestor.client.Alive()
}

func (requestor *PresentationRequestor) buildUri(origin, clientID, id string) (string, error) {
	base, err := url.Parse(origin)
	if err != nil || base.Scheme != "https" || base.Host == "" {
		return "", errors.New("invalid profile origin")
	}
	requestURI := origin + common.VerifierRequestObjectPath + "/" + url.PathEscape(id) + "/request-object/request.jwt"
	q := url.Values{"client_id": {clientID}, "request_uri": {requestURI}}
	return "openid4vp://?" + q.Encode(), nil
}

func (requestor *PresentationRequestor) publishStatus(tenantId string, requestId string, presentationId string, status string) {

	msg := messaging.ProofNotifyEvent{
		Reply: commonMessageTypes.Reply{
			TenantId:  tenantId,
			RequestId: requestId,
		},
		PresentationId: presentationId,
		Status:         status,
	}
	b, err := json.Marshal(msg)

	if err != nil {
		requestor.logger.Error(err, "error in json marshalling", err)
		return
	}

	e, err := cloudeventprovider.NewEvent(requestor.presentationRequestTopic, messaging.ProofNotifyType, b)

	if err != nil {
		requestor.logger.Error(err, "error in json marshalling", err)
		return
	}

	err = requestor.notifyClient.Pub(e)

	if err != nil {
		requestor.logger.Error(err, "error in json marshalling", err)
		return
	}
}

func (requestor *PresentationRequestor) presentationResultReply(reply messaging.PresentationResultGetReply) (*event.Event, error) {
	data, err := json.Marshal(reply)
	if err != nil {
		return nil, err
	}
	e, err := cloudeventprovider.NewEvent(requestor.presentationRequestTopic, messaging.PresentationResultReplyType, data)
	if err != nil {
		return nil, err
	}
	return &e, nil
}
