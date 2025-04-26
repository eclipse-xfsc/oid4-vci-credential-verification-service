package services

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/cloudevents/sdk-go/v2/event"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"gitlab.eclipse.org/eclipse/xfsc/libraries/messaging/cloudeventprovider"
	logr "gitlab.eclipse.org/eclipse/xfsc/libraries/microservice/core/pkg/logr"
	"gitlab.eclipse.org/eclipse/xfsc/libraries/ssi/oid4vip/model/types"
	"github.com/eclipse-xfsc/oid4-vci-credential-verification-service/internal/model"
	serviceCommon "github.com/eclipse-xfsc/oid4-vci-credential-verification-service/internal/services/common"
	"github.com/eclipse-xfsc/oid4-vci-credential-verification-service/pkg/messaging"
	"gitlab.eclipse.org/eclipse/xfsc/organisational-credential-manager-w-stack/libraries/messaging/common"
)

type AuthorizationHandler struct {
	client    *cloudeventprovider.CloudEventProviderClient
	pubClient *cloudeventprovider.CloudEventProviderClient
	logger    logr.Logger
	config    *model.Config
}

func (handler *AuthorizationHandler) HandleRequestObject(ctx context.Context, clientId string, request_uri string, tenantId string, config *model.Config, authUrl *url.URL) (string, error) {
	if config.ExternalPresentation.ClientIdPolicy != "" {
		var clientIdObject map[string]interface{} = make(map[string]interface{})
		clientIdObject["clientId"] = clientId
		//Check for ClientId, redirect Uris etc.
		res, err := GetPolicyResult(clientIdObject, config.ExternalPresentation.ClientIdPolicy)

		if err != nil {
			return "", err
		}

		val, exist := res["allow"]

		if !exist || val != "true" {
			return "", errors.New("policy forbids the processing")
		}
	}

	object, err := getRequestObject(request_uri, ctx)

	if err != nil {
		return "", err
	}

	if object.ResponseMode != types.DirectPost {
		return "", errors.ErrUnsupported
	}

	if config.ExternalPresentation.RequestObjectPolicy != "" {
		//Check for ClientId, redirect Uris etc.
		res, err := GetPolicyResult(object, config.ExternalPresentation.RequestObjectPolicy)

		if err != nil {
			return "", err
		}

		val, exist := res["allow"]

		if !exist || val != "true" {
			return "", errors.New("policy forbidds the processing")
		}
	}

	if err != nil {
		return "", errors.Join(
			fmt.Errorf("could not parse AuthorizeEndpoint: %s", config.ExternalPresentation.AuthorizeEndpoint),
			err,
		)
	}

	requestId := uuid.New().String()

	//Unique value, if present use it for random id instead of own one
	if object.State != "" {
		requestId = object.State
	}

	id, err := SignId(tenantId, config.SigningKey)

	if err != nil {
		return "", errors.Join(errors.New("error during signing"), err)
	}

	err = serviceCommon.StoreRequest(ctx, requestId, tenantId, id, object)

	if err != nil {
		return "", err
	}

	query := authUrl.Query()
	query.Add("presentation", id)
	query.Add("nonce", object.Nonce)
	authUrl.RawQuery = query.Encode()

	return authUrl.String(), nil
}

// HandleAuthorizationRequest godoc
// @Summary Handles the authorization request
// @Description Handles the authorization request by checking the client_id and request_uri parameters, and then handling the request object
// @Tags external
// @Param tenantId path string true "Tenant ID"
// @Param client_id query string true "Client ID"
// @Param request_uri query string true "Request URI"
// @Param authUrl query string false "Auth URL"
// @Success 302
// @Failure 400 {object} ServerErrorResponse
// @Failure 500 {object} ServerErrorResponse
// @Router /presentation/authorize [get]
func (handler *AuthorizationHandler) HandleAuthorizationRequest(c *gin.Context, config *model.Config) {
	client_id, a := c.GetQuery("client_id")
	request_uri, b := c.GetQuery("request_uri")
	authUrl, err := ResolveAuthUrl(c, config)
	if err != nil {
		return
	}
	if a && b {
		tenantId, b := c.Params.Get("tenantId")
		// carry headers to the request_uri call
		ctx := context.WithValue(c.Request.Context(), HeaderContextKey, c.Request.Header)
		if b {
			redirect_uri, err := handler.HandleRequestObject(ctx, client_id, request_uri, tenantId, config, authUrl)

			if err == nil {
				handler.logger.Info("Redirect to: " + redirect_uri)
				c.Redirect(302, redirect_uri)
			} else {
				ErrorResponse(c, "Request could not be handled", err)
			}
		} else {
			ErrorResponse(c, "Path Variable missing.", errors.ErrUnsupported)
		}
	} else {
		ErrorResponse(c, "URI parameter missing.", errors.ErrUnsupported)
	}
}

func ResolveAuthUrl(c *gin.Context, config *model.Config) (*url.URL, error) {
	var authUrl *url.URL
	var err error
	if c != nil {
		if authUrlParam, ok := c.GetQuery("authUrl"); ok {
			authUrl, err = parsePercentEncodedUrl(authUrlParam, false)
			if err == nil {
				return authUrl, nil
			}
		}
	}
	authUrl, err = url.Parse(config.ExternalPresentation.AuthorizeEndpoint)
	if err != nil {
		return nil, ErrorResponse(c, "AuthorizeEndpoint is not parsable", err)
	}
	return authUrl, nil
}

func (handler *AuthorizationHandler) Initialize(config *model.Config, logger logr.Logger) error {
	handler.logger = logger
	handler.config = config

	if config.Topics.Authorization == "" {
		return errors.New("Invalid Subject for Nats.")
	}
	client, err := cloudeventprovider.New(cloudeventprovider.Config{Protocol: cloudeventprovider.ProtocolTypeNats, Settings: cloudeventprovider.NatsConfig{
		Url:          config.Messaging.Nats.Url,
		QueueGroup:   config.Messaging.Nats.QueueGroup,
		TimeoutInSec: time.Minute,
	}}, cloudeventprovider.ConnectionTypeSub, config.Topics.Authorization)

	if err != nil {
		logger.Logger.Error(err, "Error during message creation")
		return err
	}

	handler.client = client

	client2, err := cloudeventprovider.New(cloudeventprovider.Config{Protocol: cloudeventprovider.ProtocolTypeNats, Settings: cloudeventprovider.NatsConfig{
		Url:          config.Messaging.Nats.Url,
		QueueGroup:   config.Messaging.Nats.QueueGroup,
		TimeoutInSec: time.Minute,
	}}, cloudeventprovider.ConnectionTypePub, config.Topics.AuthorizationReply)

	if err != nil {
		logger.Logger.Error(err, "Error during message creation")
		return err
	}

	handler.pubClient = client2

	return err
}

func (handler *AuthorizationHandler) receive(event event.Event) {

	if event.Type() == messaging.PresentationAuthorizationRemoteType {
		ctx := context.Background()
		var remoteRequest messaging.PresentationAuthorizationRemoteRequest

		err := json.Unmarshal(event.Data(), &remoteRequest)

		if err != nil {
			handler.logger.Error(err, "Error unmarshalling Remoterequest")
			return
		}
		authUrl, err := ResolveAuthUrl(nil, handler.config)

		headers := http.Header{}
		headers.Add("X-NAMESPACE", remoteRequest.TenantId)
		headers.Add("X-GROUP", remoteRequest.GroupId)
		headers.Add("X-KEY", remoteRequest.Key)
		headers.Add("X-DID", remoteRequest.Did)

		ctx = context.WithValue(ctx, HeaderContextKey, headers)

		_, err = handler.HandleRequestObject(ctx, remoteRequest.ClientId, remoteRequest.RequestUri, remoteRequest.TenantId, handler.config, authUrl)

		if err != nil {
			handler.logger.Error(err, "Error during request object handling")
			return
		}

		resp := messaging.PresentationAuthorizationRemoteReply{
			Reply: common.Reply{
				RequestId: remoteRequest.RequestId,
				TenantId:  remoteRequest.TenantId,
			},
		}

		b, err := json.Marshal(resp)

		if err != nil {
			handler.logger.Error(err, "error in json marshalling", err)
			return
		}

		e, err := cloudeventprovider.NewEvent(handler.config.Topics.AuthorizationReply, messaging.PresentationAuthorizationRemoteType, b)
		if err != nil {
			handler.logger.Error(err, "Error during object publication handling")
		}
		//Publish New Record
		err = handler.pubClient.PubCtx(ctx, e)

		if err != nil {
			handler.logger.Error(err, "Error during object publication handling")
		}
	}
}

func (handler *AuthorizationHandler) Listen() {
	for {
		if err := handler.client.SubCtx(context.Background(), handler.receive); err != nil {
			handler.logger.Error(err, "Subscription failed.")
		}
	}
}

func (handler *AuthorizationHandler) Close() {
	handler.client.Close()
}

func (handler *AuthorizationHandler) Alive() bool {
	return handler.client.Alive()
}
