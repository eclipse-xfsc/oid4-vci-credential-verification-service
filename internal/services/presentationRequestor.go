package services

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	"gitlab.eclipse.org/eclipse/xfsc/libraries/ssi/oid4vip/model/presentation"

	"github.com/cloudevents/sdk-go/v2/event"
	"github.com/google/uuid"
	"gitlab.eclipse.org/eclipse/xfsc/libraries/messaging/cloudeventprovider"
	logr "gitlab.eclipse.org/eclipse/xfsc/libraries/microservice/core/pkg/logr"
	"github.com/eclipse-xfsc/oid4-vci-credential-verification-service/internal/model"
	"github.com/eclipse-xfsc/oid4-vci-credential-verification-service/internal/services/common"
	"github.com/eclipse-xfsc/oid4-vci-credential-verification-service/pkg/messaging"
	commonMessageTypes "gitlab.eclipse.org/eclipse/xfsc/organisational-credential-manager-w-stack/libraries/messaging/common"
	msg "gitlab.eclipse.org/eclipse/xfsc/tsa/signer/pkg/messaging"
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

	if config.Topics.PresentationRequest == "" {
		return errors.New("Invalid Subject for Nats.")
	}

	requestor.presentationRequestTopic = config.Topics.PresentationRequest
	requestor.storagePubTopic = config.Topics.StorageRequest

	client, err := cloudeventprovider.New(cloudeventprovider.Config{Protocol: cloudeventprovider.ProtocolTypeNats, Settings: cloudeventprovider.NatsConfig{
		Url:          config.Messaging.Nats.Url,
		QueueGroup:   config.Messaging.Nats.QueueGroup,
		TimeoutInSec: time.Minute,
	}}, cloudeventprovider.Rep, config.Topics.PresentationRequest)

	if err != nil {
		logger.Error(err, "Error during message creation")
		return err
	}

	requestor.client = client

	client2, err := cloudeventprovider.New(cloudeventprovider.Config{Protocol: config.Messaging.Protocol, Settings: cloudeventprovider.NatsConfig{
		Url:          config.Messaging.Nats.Url,
		QueueGroup:   config.Messaging.Nats.QueueGroup,
		TimeoutInSec: time.Minute,
	}}, cloudeventprovider.Pub, config.Topics.ProofNotify)

	if err != nil {
		logger.Error(err, "Error during message creation")
		return err
	}

	requestor.notifyClient = client2

	client3, err := cloudeventprovider.New(cloudeventprovider.Config{Protocol: config.Messaging.Protocol, Settings: cloudeventprovider.NatsConfig{
		Url:          config.Messaging.Nats.Url,
		QueueGroup:   config.Messaging.Nats.QueueGroup,
		TimeoutInSec: time.Minute,
	}}, cloudeventprovider.Pub, config.Topics.StorageRequest)

	if err != nil {
		logger.Error(err, "Error during message creation")
		return err
	}

	requestor.storageClient = client3

	client4, err := cloudeventprovider.New(cloudeventprovider.Config{Protocol: config.Messaging.Protocol, Settings: cloudeventprovider.NatsConfig{
		Url:          config.Messaging.Nats.Url,
		QueueGroup:   config.Messaging.Nats.QueueGroup,
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

	row, err := common.GetEntryFromDb(ctx, tenantId, id)

	if err == nil {

		clientUrl := url.URL{
			Scheme: schema,
			Host:   host,
			Path:   path + "/" + id,
		}

		tok := make(map[string]interface{})
		tok["client_id"] = did
		tok["response_uri"] = clientUrl.String()
		tok["response_type"] = "vp_token"
		tok["nonce"] = row.Nonce
		tok["state"] = id
		tok["response_mode"] = "direct_post"
		tok["presentation_definition"] = row.PresentationDefinition
		tok["client_id_scheme"] = "did"

		pb, err := json.Marshal(tok)
		if err != nil {
			return nil, err
		}

		var req = msg.CreateTokenRequest{
			Request: commonMessageTypes.Request{
				TenantId:  tenantId,
				RequestId: uuid.NewString(),
			},
			Namespace: tenantId,
			Key:       key,
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

		res, err := requestor.signerClient.RequestCtx(ctx, ev)

		if err != nil {
			return nil, err
		}

		var rep msg.CreateTokenReply

		err = json.Unmarshal(res.DataEncoded, &rep)

		if err != nil {
			return nil, err
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

		err = authorizationRequest.PresentationDefinition.CheckPresentationDefinition()

		if err != nil {
			return requestor.AuthorizationReplyError(reply, err, "error during check presentation")
		}

		id, err := SignId(authorizationRequest.TenantId, requestor.config.SigningKey)

		if err != nil {
			return requestor.AuthorizationReplyError(reply, err, "error during id creation")
		}

		reply.PresentationId = id
		reply.RequestUri = requestor.buildUri(authorizationRequest, id)

		requestOptions := common.PresentationRequestOptions{
			TenantId:  authorizationRequest.TenantId,
			Id:        id,
			RequestId: authorizationRequest.RequestId,
			GroupId:   authorizationRequest.GroupId,
			Ttl:       authorizationRequest.Ttl,
		}

		err = common.AddPresentationDefinitonToDb(authorizationRequest.PresentationDefinition, requestOptions, ctx)

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

func (requestor *PresentationRequestor) CreatePresentationRequest(definition presentation.PresentationDefinition, options common.PresentationRequestOptions, ctx context.Context) error {
	return common.AddPresentationDefinitonToDb(definition, options, ctx)
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

func (requestor *PresentationRequestor) buildUri(request messaging.PresentationAuthorizationCreationRequest, id string) string {

	requestObjectUrl := url.URL{
		Scheme: requestor.config.ExternalPresentation.ClientUrlSchema,
		Host:   request.RequestObjectUri,
		Path:   "/" + id + "/request-object/request.jwt",
	}

	authUrl := url.URL{
		Scheme: requestor.config.ExternalPresentation.ClientUrlSchema,
		Host:   request.TargetUri,
		Path:   "/authorize",
	}

	clientUrl := url.URL{
		Scheme: requestor.config.ExternalPresentation.ClientUrlSchema,
		Host:   request.TenantUri,
		Path:   CredentialApiGroup + DirectGroup + "/" + id,
	}

	query := authUrl.Query()
	query.Add("client_id", clientUrl.String())
	query.Add("request_uri", requestObjectUrl.String())
	authUrl.RawQuery = query.Encode()
	return requestor.config.ExternalPresentation.ClientUrlSchema + "://" + request.TargetUri + authUrl.RequestURI()
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
