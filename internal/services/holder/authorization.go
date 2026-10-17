package holder

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/cloudevents/sdk-go/v2/event"
	logr "github.com/eclipse-xfsc/microservice-core-go/pkg/logr"
	"github.com/eclipse-xfsc/oid4-vci-credential-verification-service/internal/model"
	serviceCommon "github.com/eclipse-xfsc/oid4-vci-credential-verification-service/internal/services/common"
	shared "github.com/eclipse-xfsc/oid4-vci-credential-verification-service/internal/services/common"
	"github.com/eclipse-xfsc/oid4-vci-credential-verification-service/pkg/messaging"
	"github.com/eclipse-xfsc/oid4-vci-vp-library/model/types"
	"github.com/gin-gonic/gin"
	"github.com/nats-io/nats.go"
)

type AuthorizationHandler struct {
	client *nats.Conn
	sub    *nats.Subscription
	logger logr.Logger
	config *model.Config
}

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
		clientIdObject := map[string]interface{}{"clientId": clientId}
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
	if err := serviceCommon.StoreRequest(ctx, requestId, tenantId, groupId, consentMode, ttl, object); err != nil {
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
	clientID, a := c.GetQuery("client_id")
	requestURI, b := c.GetQuery("request_uri")
	authURL, err := ResolveAuthUrl(c, config)
	if err != nil {
		return
	}
	if a && b {
		tenantID, ok := c.Params.Get("tenantId")
		ctx := context.WithValue(c.Request.Context(), HeaderContextKey, c.Request.Header)
		if ok {
			groupID := c.GetHeader("x-groupId")
			if groupID == "" {
				groupID = c.GetHeader("x-group")
			}
			requestID := c.GetHeader("x-requestId")
			if requestID == "" {
				requestID = c.GetHeader("x-request-id")
			}
			processed, err := handler.HandleRequestObject(ctx, clientID, requestURI, tenantID, groupID, requestID, model.ConsentManual, 3600, config)
			if err != nil {
				shared.ErrorResponse(c, "Request could not be handled", err)
				return
			}
			redirectURI := buildAuthorizationRedirect(authURL, processed)
			handler.logger.Info("Redirect to: " + redirectURI)
			c.Redirect(http.StatusFound, redirectURI)
		} else {
			shared.ErrorResponse(c, "Path Variable missing.", errors.ErrUnsupported)
		}
	} else {
		shared.ErrorResponse(c, "URI parameter missing.", errors.ErrUnsupported)
	}
}

func buildAuthorizationRedirect(authURL *url.URL, processed *ProcessedAuthorizationRequest) string {
	redirectURL := *authURL
	query := redirectURL.Query()
	query.Set("presentation", processed.State)
	query.Set("nonce", processed.Nonce)
	redirectURL.RawQuery = query.Encode()
	return redirectURL.String()
}

func ResolveAuthUrl(c *gin.Context, config *model.Config) (*url.URL, error) {
	var authURL *url.URL
	var err error
	if c != nil && config.IsDev {
		if authUrlParam, ok := c.GetQuery("authUrl"); ok {
			authURL, err = parsePercentEncodedUrl(authUrlParam, false)
			if err == nil {
				return authURL, nil
			}
		}
	}
	authURL, err = shared.ValidateOutboundURL(config.ExternalPresentation.AuthorizeEndpoint, config, true)
	if err != nil {
		return nil, shared.ErrorResponse(c, "AuthorizeEndpoint is not parsable", err)
	}
	return authURL, nil
}

func (handler *AuthorizationHandler) Initialize(config *model.Config, logger logr.Logger) error {
	handler.logger = logger
	handler.config = config
	if strings.TrimSpace(config.Authorization) == "" {
		return errors.New("NATS authorization subject is required")
	}
	nc, err := nats.Connect(config.Nats.Url, nats.Name("xfsc-holder-authorization"), nats.Timeout(10*time.Second), nats.MaxReconnects(-1))
	if err != nil {
		return fmt.Errorf("connect to NATS: %w", err)
	}
	handler.client = nc
	return nil
}

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
	return clientID, requestURI, nil
}

type RemoteAuthorizationResult struct {
	RequestID      string `json:"requestId,omitempty"`
	TenantID       string `json:"tenantId,omitempty"`
	PresentationID string `json:"presentationId,omitempty"`
	Status         string `json:"status"`
	Error          string `json:"error,omitempty"`
}

func (handler *AuthorizationHandler) receive(msg *nats.Msg) {
	if msg.Reply == "" {
		handler.logger.Error(errors.New("missing NATS reply subject"), "Remote authorization requires request/reply")
		return
	}
	result := RemoteAuthorizationResult{Status: "failed"}
	defer func() {
		replyEvent := event.New()
		replyEvent.SetSource("xfsc-holder")
		replyEvent.SetType(messaging.PresentationAuthorizationRemoteType)
		if err := replyEvent.SetData("application/json", result); err != nil {
			handler.logger.Error(err, "Cannot create authorization reply")
			return
		}
		data, err := json.Marshal(replyEvent)
		if err != nil {
			handler.logger.Error(err, "Cannot marshal reply CloudEvent")
			return
		}
		if err := msg.Respond(data); err != nil {
			handler.logger.Error(err, "Cannot send authorization reply")
		}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	var ev event.Event
	if err := json.Unmarshal(msg.Data, &ev); err != nil {
		result.Error = fmt.Sprintf("invalid CloudEvent: %v", err)
		return
	}
	if ev.Type() != messaging.PresentationAuthorizationRemoteType {
		result.Error = fmt.Sprintf("unsupported event type: %s", ev.Type())
		return
	}
	var remoteRequest messaging.PresentationAuthorizationRemoteRequest
	if err := json.Unmarshal(ev.Data(), &remoteRequest); err != nil {
		result.Error = fmt.Sprintf("invalid remote authorization payload: %v", err)
		return
	}
	result.RequestID = remoteRequest.RequestId
	result.TenantID = remoteRequest.TenantId
	if strings.TrimSpace(remoteRequest.TenantId) == "" || strings.TrimSpace(remoteRequest.GroupId) == "" || strings.TrimSpace(remoteRequest.RequestId) == "" {
		result.Error = "tenantId, groupId and requestId are required"
		return
	}
	if remoteRequest.Ttl == 0 {
		remoteRequest.Ttl = 3600
	}
	clientID, requestURI, err := parseRemoteOID4VPURL(remoteRequest.URL)
	if err != nil {
		result.Error = err.Error()
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
		result.Error = fmt.Sprintf("authorization request failed: %v", err)
		return
	}
	result.PresentationID = processed.State
	if remoteRequest.ConsentMode == model.ConsentManual {
		result.Status = "pending"
		return
	}
	row, err := serviceCommon.GetEntryFromDb(ctx, remoteRequest.TenantId, processed.State)
	if err != nil {
		result.Error = fmt.Sprintf("cannot reload presentation request: %v", err)
		return
	}
	sign := model.FulfillPresentationRequest{HolderDid: remoteRequest.Did, SignKey: remoteRequest.Key, SignNamespace: remoteRequest.TenantId, SignGroup: remoteRequest.GroupId}
	if err := AutoConsent(ctx, handler.config, row, sign); err != nil {
		result.Error = fmt.Sprintf("auto consent failed: %v", err)
		handler.logger.Error(err, "Auto consent processing failed", "requestId", remoteRequest.RequestId)
		return
	}
	result.Status = "completed"
}

func (handler *AuthorizationHandler) Listen() {
	if handler.client == nil {
		handler.logger.Error(errors.New("NATS client not initialized"), "Cannot start authorization listener")
		return
	}
	var sub *nats.Subscription
	var err error
	if handler.config.Nats.QueueGroup != "" {
		sub, err = handler.client.QueueSubscribeSync(handler.config.Authorization, handler.config.Nats.QueueGroup)
	} else {
		sub, err = handler.client.SubscribeSync(handler.config.Authorization)
	}
	if err != nil {
		handler.logger.Error(err, "Cannot subscribe to authorization subject")
		return
	}
	handler.sub = sub
	if err := handler.client.FlushTimeout(10 * time.Second); err != nil {
		handler.logger.Error(err, "Cannot initialize NATS subscription")
		return
	}
	handler.logger.Info("NATS authorization request/reply listener started")
	for {
		msg, err := sub.NextMsg(time.Second)
		if err != nil {
			if errors.Is(err, nats.ErrTimeout) {
				continue
			}
			if errors.Is(err, nats.ErrConnectionClosed) || errors.Is(err, nats.ErrBadSubscription) {
				return
			}
			handler.logger.Error(err, "Error receiving authorization request")
			continue
		}
		handler.receive(msg)
	}
}

func (handler *AuthorizationHandler) Close() {
	if handler.sub != nil {
		_ = handler.sub.Unsubscribe()
	}
	if handler.client != nil {
		handler.client.Close()
	}
}

func (handler *AuthorizationHandler) Alive() bool {
	return handler.client != nil && !handler.client.IsClosed() && handler.client.IsConnected()
}

func (handler *AuthorizationHandler) IntakeLink(ctx context.Context, raw, tenant, group, requestID, mode string, ttl int, cfg *model.Config) (*ProcessedAuthorizationRequest, error) {
	client, uri, err := parseRemoteOID4VPURL(raw)
	if err != nil {
		return nil, err
	}
	return handler.HandleRequestObject(ctx, client, uri, tenant, group, requestID, mode, ttl, cfg)
}
