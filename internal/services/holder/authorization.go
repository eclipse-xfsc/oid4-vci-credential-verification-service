package holder

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	shared "github.com/eclipse-xfsc/oid4-vci-credential-verification-service/internal/services/common"
	"net/http"
	"net/url"
	"strings"
	"time"

	logr "github.com/eclipse-xfsc/microservice-core-go/pkg/logr"

	"github.com/cloudevents/sdk-go/v2/event"
	cloudeventprovider "github.com/eclipse-xfsc/cloud-event-provider"
	"github.com/eclipse-xfsc/nats-message-library/common"
	"github.com/eclipse-xfsc/oid4-vci-credential-verification-service/internal/model"
	serviceCommon "github.com/eclipse-xfsc/oid4-vci-credential-verification-service/internal/services/common"
	"github.com/eclipse-xfsc/oid4-vci-credential-verification-service/pkg/messaging"
	"github.com/eclipse-xfsc/oid4-vci-vp-library/model/types"
	"github.com/gin-gonic/gin"
)

type AuthorizationHandler struct {
	client    *cloudeventprovider.CloudEventProviderClient
	pubClient *cloudeventprovider.CloudEventProviderClient
	logger    logr.Logger
	config    *model.Config
}

// ProcessedAuthorizationRequest contains the data needed by entry-point-specific flows.
type ProcessedAuthorizationRequest struct {
	State string
	Nonce string
}

func (handler *AuthorizationHandler) HandleRequestObject(ctx context.Context, clientId string, request_uri string, tenantId string, groupId string, requestId string, consentMode string, ttl int, config *model.Config) (*ProcessedAuthorizationRequest, error) {
	if consentMode != model.ConsentManual && consentMode != model.ConsentAuto {
		return nil, errors.New("consentMode must be manual or auto")
	}
	if ttl <= 0 || ttl > 86400 {
		return nil, errors.New("ttl must be 1..86400 seconds")
	}
	if groupId == "" || requestId == "" {
		return nil, errors.New("groupId and requestId must not be empty")
	}
	if config.ExternalPresentation.ClientIdPolicy != "" {
		var clientIdObject map[string]interface{} = make(map[string]interface{})
		clientIdObject["clientId"] = clientId
		//Check for ClientId, redirect Uris etc.
		res, err := GetPolicyResult(clientIdObject, config.ExternalPresentation.ClientIdPolicy)

		if err != nil {
			return nil, err
		}

		if !policyAllows(res) {
			return nil, errors.New("policy forbids the processing")
		}
	}

	object, err := getRequestObject(request_uri, clientId, ctx)

	if err != nil {
		return nil, err
	}
	if err := object.AuthorizationRequest.Validate(); err != nil {
		return nil, fmt.Errorf("invalid OID4VP request object: %w", err)
	}
	if clientId != object.ClientID {
		return nil, errors.New("client_id does not match request object")
	}

	if object.ResponseMode != string(types.DirectPost) && object.ResponseMode != string(types.DirectPostJwt) {
		return nil, fmt.Errorf("unsupported response_mode %q", object.ResponseMode)
	}

	if config.ExternalPresentation.RequestObjectPolicy != "" {
		//Check for ClientId, redirect Uris etc.
		res, err := GetPolicyResult(object, config.ExternalPresentation.RequestObjectPolicy)

		if err != nil {
			return nil, err
		}

		if !policyAllows(res) {
			return nil, errors.New("policy forbidds the processing")
		}
	}

	state, err := serviceCommon.EncodeVerificationState(groupId, requestId)
	if err != nil {
		return nil, errors.Join(errors.New("error creating verification state"), err)
	}

	blocked, err := serviceCommon.IsVerifierBlocked(ctx, tenantId, groupId, object.ClientID)
	if err != nil {
		return nil, err
	}
	if blocked {
		return nil, errors.New("verifier is blocked")
	}
	err = serviceCommon.StoreRequest(ctx, requestId, tenantId, groupId, consentMode, ttl, object)

	if err != nil {
		return nil, err
	}

	return &ProcessedAuthorizationRequest{State: state, Nonce: object.Nonce}, nil
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
// @Failure 400 {object} shared.ServerErrorResponse
// @Failure 500 {object} shared.ServerErrorResponse
// @Router /v1/tenants/{tenantId}/presentation/authorize [get]
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
			groupId := c.GetHeader("x-groupId")
			if groupId == "" {
				groupId = c.GetHeader("x-group")
			}
			requestId := c.GetHeader("x-requestId")
			if requestId == "" {
				requestId = c.GetHeader("x-request-id")
			}
			processed, err := handler.HandleRequestObject(ctx, client_id, request_uri, tenantId, groupId, requestId, model.ConsentManual, 3600, config)
			if err != nil {
				shared.ErrorResponse(c, "Request could not be handled", err)
				return
			}
			redirectURI := buildAuthorizationRedirect(authUrl, processed)
			handler.logger.Info("Redirect to: " + redirectURI)
			c.Redirect(http.StatusFound, redirectURI)
		} else {
			shared.ErrorResponse(c, "Path Variable missing.", errors.ErrUnsupported)
		}
	} else {
		shared.ErrorResponse(c, "URI parameter missing.", errors.ErrUnsupported)
	}
}

// buildAuthorizationRedirect constructs a local consent URL without mutating config URLs.
func buildAuthorizationRedirect(authURL *url.URL, processed *ProcessedAuthorizationRequest) string {
	redirectURL := *authURL
	query := redirectURL.Query()
	query.Set("presentation", processed.State)
	query.Set("nonce", processed.Nonce)
	redirectURL.RawQuery = query.Encode()
	return redirectURL.String()
}

func ResolveAuthUrl(c *gin.Context, config *model.Config) (*url.URL, error) {
	var authUrl *url.URL
	var err error
	if c != nil && config.IsDev {
		if authUrlParam, ok := c.GetQuery("authUrl"); ok {
			authUrl, err = parsePercentEncodedUrl(authUrlParam, false)
			if err == nil {
				return authUrl, nil
			}
		}
	}
	authUrl, err = shared.ValidateOutboundURL(config.ExternalPresentation.AuthorizeEndpoint, config, true)
	if err != nil {
		return nil, shared.ErrorResponse(c, "AuthorizeEndpoint is not parsable", err)
	}
	return authUrl, nil
}

func (handler *AuthorizationHandler) Initialize(config *model.Config, logger logr.Logger) error {
	handler.logger = logger
	handler.config = config

	if config.Authorization == "" {
		return errors.New("Invalid Subject for Nats.")
	}
	client, err := cloudeventprovider.New(cloudeventprovider.Config{Protocol: cloudeventprovider.ProtocolTypeNats, Settings: cloudeventprovider.NatsConfig{
		Url:          config.Nats.Url,
		QueueGroup:   config.Nats.QueueGroup,
		TimeoutInSec: time.Minute,
	}}, cloudeventprovider.ConnectionTypeSub, config.Authorization)

	if err != nil {
		logger.Logger.Error(err, "Error during message creation")
		return err
	}

	handler.client = client

	client2, err := cloudeventprovider.New(cloudeventprovider.Config{Protocol: cloudeventprovider.ProtocolTypeNats, Settings: cloudeventprovider.NatsConfig{
		Url:          config.Nats.Url,
		QueueGroup:   config.Nats.QueueGroup,
		TimeoutInSec: time.Minute,
	}}, cloudeventprovider.ConnectionTypePub, config.AuthorizationReply)

	if err != nil {
		logger.Logger.Error(err, "Error during message creation")
		return err
	}

	handler.pubClient = client2

	return err
}

// parseRemoteOID4VPURL extracts the untrusted outer client_id and request_uri.
// Their binding and the Request Object signature are verified downstream.
func parseRemoteOID4VPURL(raw string) (string, string, error) {
	if strings.TrimSpace(raw) == "" {
		return "", "", errors.New("url is required")
	}
	u, err := url.Parse(raw)
	if err != nil {
		return "", "", fmt.Errorf("invalid OID4VP URL: %w", err)
	}
	if u.Scheme != "openid4vp" || u.Host != "" || u.Fragment != "" || u.User != nil {
		return "", "", errors.New("expected openid4vp://? authorization request URL")
	}
	q, err := url.ParseQuery(u.RawQuery)
	if err != nil {
		return "", "", fmt.Errorf("invalid OID4VP query: %w", err)
	}
	for _, key := range []string{"client_id", "request_uri", "request"} {
		if len(q[key]) > 1 {
			return "", "", fmt.Errorf("duplicate OID4VP parameter %s", key)
		}
	}
	if len(q["request"]) != 0 {
		return "", "", errors.New("inline request objects are not supported; use request_uri")
	}
	clientID := strings.TrimSpace(q.Get("client_id"))
	requestURI := strings.TrimSpace(q.Get("request_uri"))
	if clientID == "" || requestURI == "" {
		return "", "", errors.New("client_id and request_uri are required")
	}
	parsed, err := url.Parse(requestURI)
	if err != nil || parsed.Host == "" || (parsed.Scheme != "https" && parsed.Scheme != "http") || parsed.User != nil || parsed.Fragment != "" {
		return "", "", errors.New("request_uri must be an absolute HTTP(S) URL")
	}
	// Outbound URL policy and SSRF restrictions are applied by getRequestObject.
	return clientID, requestURI, nil
}

func (handler *AuthorizationHandler) receive(ev event.Event) {
	if ev.Type() != messaging.PresentationAuthorizationRemoteType {
		return
	}
	ctx := context.Background()
	var remoteRequest messaging.PresentationAuthorizationRemoteRequest
	if err := json.Unmarshal(ev.Data(), &remoteRequest); err != nil {
		handler.logger.Error(err, "Invalid remote authorization CloudEvent payload")
		return
	}
	if strings.TrimSpace(remoteRequest.TenantId) == "" || strings.TrimSpace(remoteRequest.GroupId) == "" || strings.TrimSpace(remoteRequest.RequestId) == "" {
		handler.logger.Error(errors.New("tenantId, groupId and requestId are required"), "Invalid remote authorization context")
		return
	}
	if remoteRequest.Ttl == 0 {
		remoteRequest.Ttl = 3600
	}
	clientID, requestURI, err := parseRemoteOID4VPURL(remoteRequest.URL)
	if err != nil {
		handler.logger.Error(err, "Invalid OID4VP link")
		return
	}
	headers := http.Header{}
	headers.Set("X-NAMESPACE", remoteRequest.TenantId)
	headers.Set("X-GROUP", remoteRequest.GroupId)
	headers.Set("X-KEY", remoteRequest.Key)
	headers.Set("X-DID", remoteRequest.Did)
	ctx = context.WithValue(ctx, HeaderContextKey, headers)
	processed, err := handler.HandleRequestObject(ctx, clientID, requestURI, remoteRequest.TenantId, remoteRequest.GroupId, remoteRequest.RequestId, remoteRequest.ConsentMode, remoteRequest.Ttl, handler.config)
	if err != nil {
		handler.logger.Error(err, "Error during request object handling")
		return
	}
	if remoteRequest.ConsentMode == model.ConsentAuto {
		row, err := serviceCommon.GetEntryFromDb(ctx, remoteRequest.TenantId, processed.State)
		if err != nil {
			handler.logger.Error(err, "Cannot reload auto consent request")
		} else {
			go func() {
				sign := model.FulfillPresentationRequest{HolderDid: remoteRequest.Did, SignKey: remoteRequest.Key, SignNamespace: remoteRequest.TenantId, SignGroup: remoteRequest.GroupId}
				if err := AutoConsent(context.Background(), handler.config, row, sign); err != nil {
					handler.logger.Error(err, "Auto consent processing failed")
				}
			}()
		}
	}
	resp := messaging.PresentationAuthorizationRemoteReply{Reply: common.Reply{
		RequestId: remoteRequest.RequestId, TenantId: remoteRequest.TenantId,
	}, PresentationId: processed.State}
	b, err := json.Marshal(resp)
	if err != nil {
		handler.logger.Error(err, "Error marshaling remote authorization reply")
		return
	}
	e, err := cloudeventprovider.NewEvent(handler.config.AuthorizationReply, messaging.PresentationAuthorizationRemoteType, b)
	if err != nil {
		handler.logger.Error(err, "Error creating remote authorization reply")
		return
	}
	if err := handler.pubClient.PubCtx(ctx, e); err != nil {
		handler.logger.Error(err, "Error publishing remote authorization reply")
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

// IntakeLink resolves and stores an OID4VP link without issuing a browser redirect.
func (handler *AuthorizationHandler) IntakeLink(ctx context.Context, raw, tenant, group, requestID, mode string, ttl int, cfg *model.Config) (*ProcessedAuthorizationRequest, error) {
	client, uri, err := parseRemoteOID4VPURL(raw)
	if err != nil {
		return nil, err
	}
	return handler.HandleRequestObject(ctx, client, uri, tenant, group, requestID, mode, ttl, cfg)
}
