package verifier

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	shared "github.com/eclipse-xfsc/oid4-vci-credential-verification-service/internal/services/common"
	"io"
	"net/http"
	"strings"
	"time"

	cloudeventprovider "github.com/eclipse-xfsc/cloud-event-provider"
	storageMessaging "github.com/eclipse-xfsc/credential-storage-service/pkg/messaging"
	commonMessageTypes "github.com/eclipse-xfsc/nats-message-library/common"
	"github.com/eclipse-xfsc/oid4-vci-credential-verification-service/internal/model"
	commonServices "github.com/eclipse-xfsc/oid4-vci-credential-verification-service/internal/services/common"
	"github.com/eclipse-xfsc/oid4-vci-vp-library/model/presentation"
	"github.com/eclipse-xfsc/oid4-vci-vp-library/model/types"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

// HandleProof receives an OID4VP 1.0 direct_post response. vp_token is a JSON
// object keyed by DCQL credential-query ID; presentation_submission is not used.
func HandleProof(c *gin.Context, requestor *PresentationRequestor, config *model.Config) {
	if c.ContentType() != "application/x-www-form-urlencoded" {
		shared.ErrorResponse(c, "Wrong content Type", errors.New("unsupported media type"))
		return
	}

	id := c.Param("id")
	tenantID := c.Param("tenantId")
	row, err := commonServices.GetEntryFromDb(c.Request.Context(), tenantID, id)
	if err != nil {
		shared.ErrorResponse(c, "Verification transaction not found", err)
		return
	}

	// This verifier advertises direct_post only. Reject encrypted responses
	// explicitly instead of interpreting them as an absent vp_token.
	if c.PostForm("response") != "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "direct_post.jwt is not configured on this verifier"})
		return
	}
	state := c.PostForm("state")
	expectedState := row.AuthorizationState
	if expectedState == "" {
		expectedState = id // legacy locally generated verifier transactions
	}
	if state == "" || state != expectedState {
		shared.ErrorResponse(c, "Invalid state", errors.New("OID4VP response state does not match the verification transaction"))
		return
	}

	raw := c.PostForm("vp_token")
	if raw == "" {
		shared.ErrorResponse(c, "Form data missing", errors.New("vp_token is required"))
		return
	}

	var vpToken presentation.VPToken
	if err := json.Unmarshal([]byte(raw), &vpToken); err != nil {
		shared.ErrorResponse(c, "VP token cannot be parsed", err)
		return
	}
	if err := vpToken.ValidateAgainst(&row.DCQLQuery); err != nil {
		shared.ErrorResponse(c, "VP token does not satisfy DCQL query", err)
		return
	}

	if err := requestor.CheckPresentations(c.Request.Context(), id, tenantID, vpToken); err != nil {
		shared.ErrorResponse(c, "error during receiving", err)
		return
	}
	c.JSON(http.StatusOK, nil)
}

func (requestor *PresentationRequestor) CheckPresentations(ctx context.Context, id, tenantID string, token presentation.VPToken) error {
	row, err := commonServices.GetEntryFromDb(ctx, tenantID, id)
	if err != nil {
		return err
	}

	if err := token.ValidateAgainst(&row.DCQLQuery); err != nil {
		return fmt.Errorf("VP token does not satisfy DCQL: %w", err)
	}
	for queryID, values := range token {
		credentialQuery, err := credentialQueryByID(row.DCQLQuery, queryID)
		if err != nil {
			return err
		}

		verifyFormat, err := presentationVerifyFormat(credentialQuery.Format)
		if err != nil {
			return fmt.Errorf("credential query %s: %w", queryID, err)
		}

		for _, raw := range values {
			presentationBytes, err := presentationBytes(raw, credentialQuery.Format)
			if err != nil {
				return fmt.Errorf("credential query %s: %w", queryID, err)
			}

			result, err := requestor.verifyPresentation(ctx, presentationBytes, verifyFormat, row.ClientId, row.Nonce)
			if err != nil {
				return fmt.Errorf("credential query %s: presentation verification failed: %w", queryID, err)
			}
			if !result.Valid {
				_ = commonServices.UpdateDbStatus(ctx, tenantID, string(model.PresentationRejected), id)
				return fmt.Errorf("credential query %s: presentation is not valid", queryID)
			}

			// For JSON-LD presentations we can additionally evaluate the contained
			// credentials locally against the exact DCQL credential query. For
			// SD-JWT, the crypto-provider performs disclosure, nonce and audience
			// verification; the returned disclosed credential is checked when present.
			if credentialQuery.Format == types.LDPVC {
				var object map[string]any
				if err := json.Unmarshal(raw, &object); err != nil {
					return fmt.Errorf("credential query %s: expected JSON presentation: %w", queryID, err)
				}
				if err := validateDCQLCredentialMatch(queryID, object, row.DCQLQuery); err != nil {
					return err
				}
			} else if credentialQuery.Format == types.SDJWT {
				// Crypto verification alone is insufficient: required DCQL claims
				// must also be present in the disclosed, verified credential.
				disclosed := result.DisclosedCredential
				if disclosed == nil {
					// Derive top-level claims locally only AFTER the crypto-provider
					// has accepted the issuer signature and key binding.
					var err error
					disclosed, err = extractVerifiedSDJWTClaims(presentationBytes)
					if err != nil {
						return fmt.Errorf("credential query %s: extract SD-JWT claims: %w", queryID, err)
					}
				}
				if err := validateDisclosedCredential(queryID, disclosed, *credentialQuery); err != nil {
					return err
				}
			}
		}
	}

	encoded, err := json.Marshal(token)
	if err != nil {
		return err
	}
	if err := commonServices.StorePresentation(ctx, id, tenantID, encoded); err != nil {
		return err
	}
	requestor.forwardPresentation(tenantID, row.RequestId, row.GroupId, encoded)
	requestor.publishStatus(tenantID, row.RequestId, id, string(model.PresentationReceived))
	return nil
}

func credentialQueryByID(query presentation.DCQLQuery, queryID string) (*presentation.CredentialQuery, error) {
	for i := range query.Credentials {
		if query.Credentials[i].ID == queryID {
			return &query.Credentials[i], nil
		}
	}
	return nil, fmt.Errorf("unknown DCQL credential query %q", queryID)
}

func presentationVerifyFormat(format types.CredentialFormat) (string, error) {
	switch format {
	case types.LDPVC:
		return "ldp_vc", nil
	case types.SDJWT:
		return "dc+sd-jwt", nil
	default:
		return "", fmt.Errorf("presentation verification for format %q is not supported by crypto-provider-service", format)
	}
}

func presentationBytes(raw json.RawMessage, format types.CredentialFormat) ([]byte, error) {
	if format == types.SDJWT {
		var compact string
		if err := json.Unmarshal(raw, &compact); err != nil {
			return nil, fmt.Errorf("SD-JWT presentation must be encoded as a JSON string: %w", err)
		}
		return []byte(compact), nil
	}
	if !json.Valid(raw) {
		return nil, errors.New("presentation is not valid JSON")
	}
	return []byte(raw), nil
}

type presentationVerifyResult struct {
	Valid               bool `json:"valid"`
	DisclosedCredential any  `json:"disclosedCredential,omitempty"`
}

func (requestor *PresentationRequestor) verifyPresentation(ctx context.Context, value []byte, format, audience, nonce string) (*presentationVerifyResult, error) {
	payload := struct {
		Presentation []byte `json:"presentation"`
		Aud          string `json:"aud,omitempty"`
		Nonce        string `json:"nonce,omitempty"`
	}{
		Presentation: value,
		Aud:          audience,
		Nonce:        nonce,
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("marshal presentation verification request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, requestor.config.SignerService.PresentationVerifyUrl, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("create presentation verification request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("x-format", format)

	requestor.logger.Debug("Sending presentation to crypto-provider verification endpoint", "format", format)
	client := &http.Client{Timeout: 20 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("crypto-provider presentation verify call: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, 2<<20))
	if err != nil {
		return nil, fmt.Errorf("read crypto-provider presentation verify response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("crypto-provider presentation verify returned HTTP %d: %s", resp.StatusCode, string(respBody))
	}

	var result presentationVerifyResult
	if err := json.Unmarshal(respBody, &result); err != nil {
		return nil, fmt.Errorf("decode crypto-provider presentation verify response: %w", err)
	}
	return &result, nil
}

// extractVerifiedSDJWTClaims reconstructs top-level disclosures for DCQL matching.
// It MUST only be called after successful cryptographic verification of the full
// presentation (including holder key binding) by the crypto-provider.
// Nested disclosures are deliberately rejected until supported end-to-end.
func extractVerifiedSDJWTClaims(compact []byte) (map[string]any, error) {
	parts := strings.Split(string(compact), "~")
	if len(parts) < 2 {
		return nil, errors.New("invalid SD-JWT serialization")
	}
	jwtParts := strings.Split(parts[0], ".")
	if len(jwtParts) != 3 {
		return nil, errors.New("invalid issuer JWT")
	}
	payloadBytes, err := base64.RawURLEncoding.DecodeString(jwtParts[1])
	if err != nil {
		return nil, err
	}
	var payload map[string]any
	if err := json.Unmarshal(payloadBytes, &payload); err != nil {
		return nil, err
	}
	if alg, ok := payload["_sd_alg"].(string); ok && alg != "sha-256" {
		return nil, fmt.Errorf("unsupported disclosure digest %s", alg)
	}
	allowed := map[string]bool{}
	hashes, _ := payload["_sd"].([]any)
	for _, h := range hashes {
		if v, ok := h.(string); ok {
			allowed[v] = true
		}
	}
	// The last component is the KB-JWT, or empty if key binding is absent.
	for _, encoded := range parts[1 : len(parts)-1] {
		if encoded == "" {
			continue
		}
		digest := sha256.Sum256([]byte(encoded))
		if !allowed[base64.RawURLEncoding.EncodeToString(digest[:])] {
			return nil, errors.New("unrecognized SD-JWT disclosure")
		}
		data, err := base64.RawURLEncoding.DecodeString(encoded)
		if err != nil {
			return nil, err
		}
		var values []any
		if err := json.Unmarshal(data, &values); err != nil {
			return nil, err
		}
		if len(values) != 3 {
			return nil, errors.New("unsupported SD-JWT disclosure structure")
		}
		name, ok := values[1].(string)
		if !ok || name == "" {
			return nil, errors.New("invalid disclosure claim name")
		}
		if _, exists := payload[name]; exists {
			return nil, fmt.Errorf("duplicate disclosed claim %q", name)
		}
		payload[name] = values[2]
	}
	delete(payload, "_sd")
	delete(payload, "_sd_alg")
	return payload, nil
}

func validateDisclosedCredential(queryID string, disclosed any, credentialQuery presentation.CredentialQuery) error {
	candidates := map[string]any{"disclosed": disclosed}
	single := presentation.DCQLQuery{Credentials: []presentation.CredentialQuery{credentialQuery}}
	matches, err := single.Filter(candidates)
	if err != nil {
		return fmt.Errorf("evaluate disclosed credential for DCQL query %q: %w", queryID, err)
	}
	if len(matches) == 0 || len(matches[0].Credentials) == 0 {
		return fmt.Errorf("disclosed credential does not satisfy DCQL query %q", queryID)
	}
	return nil
}

func validateDCQLCredentialMatch(queryID string, vp map[string]any, query presentation.DCQLQuery) error {
	credentialQuery, err := credentialQueryByID(query, queryID)
	if err != nil {
		return err
	}
	rawCredentials, ok := vp["verifiableCredential"]
	if !ok {
		return fmt.Errorf("presentation for %q contains no verifiableCredential", queryID)
	}
	items, ok := rawCredentials.([]any)
	if !ok {
		items = []any{rawCredentials}
	}
	candidates := make(map[string]any, len(items))
	for i, credential := range items {
		candidates[fmt.Sprintf("credential-%d", i)] = credential
	}
	single := presentation.DCQLQuery{Credentials: []presentation.CredentialQuery{*credentialQuery}}
	matches, err := single.Filter(candidates)
	if err != nil {
		return fmt.Errorf("evaluate DCQL credential query %q: %w", queryID, err)
	}
	if len(matches) == 0 || len(matches[0].Credentials) == 0 {
		return fmt.Errorf("presentation does not contain a credential matching DCQL query %q", queryID)
	}
	return nil
}

func (requestor *PresentationRequestor) forwardPresentation(tenantId string, requestId string, groupId string, presentation []byte) {

	msg := storageMessaging.StorageServiceStoreMessage{
		Request: commonMessageTypes.Request{
			TenantId:  tenantId,
			RequestId: requestId,
			GroupId:   groupId,
		},
		AccountId: groupId,
		Type:      storageMessaging.StorePresentationType,
		Payload:   presentation,
		Id:        uuid.NewString(),
	}
	b, err := json.Marshal(msg)

	if err != nil {
		requestor.logger.Error(err, "error in json marshalling", err)
		return
	}

	e, err := cloudeventprovider.NewEvent(requestor.storagePubTopic, storageMessaging.StorePresentationType, b)

	if err != nil {
		requestor.logger.Error(err, "error in json marshalling", err)
		return
	}

	err = requestor.storageClient.PubCtx(context.Background(), e)

	if err != nil {
		requestor.logger.Error(err, "error in json marshalling", err)
		return
	}
}

// HandleGetVerifiedPresentation returns a presentation only after verification
// and successful persistence. The state parameter is HMAC-protected by middleware.
// @Router /v1/tenants/{tenantId}/internal/presentations/{id} [get]
func HandleGetVerifiedPresentation(c *gin.Context) {
	row, err := commonServices.GetEntryFromDb(c.Request.Context(), c.Param("tenantId"), c.Param("id"))
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "verification transaction not found"})
		return
	}
	groupID := strings.TrimSpace(c.GetHeader("x-groupid"))
	if groupID == "" || groupID != row.GroupId {
		c.JSON(http.StatusForbidden, gin.H{"error": "group access denied"})
		return
	}
	if row.State != string(model.PresentationReceived) || len(row.Presentation) == 0 {
		c.JSON(http.StatusConflict, gin.H{"status": row.State, "error": "verified presentation not yet available"})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"presentationId": c.Param("id"), "requestId": row.RequestId,
		"groupId": row.GroupId, "status": row.State,
		"presentation": row.Presentation,
	})
}

// HandleListVerifiedPresentations lists verified presentation metadata for the
// authenticated tenant/group context. VP tokens are intentionally omitted.
// @Router /v1/tenants/{tenantId}/internal/presentations [get]
func HandleListVerifiedPresentations(c *gin.Context) {
	groupID := strings.TrimSpace(c.GetHeader("x-groupid"))
	if groupID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "x-groupid required"})
		return
	}
	rows, err := commonServices.GetEntriesFromDb(c.Request.Context(), c.Param("tenantId"), groupID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "cannot list presentations"})
		return
	}
	items := make([]gin.H, 0, len(rows))
	for _, row := range rows {
		if row.State != string(model.PresentationReceived) || len(row.Presentation) == 0 {
			continue
		}
		state, err := commonServices.EncodeVerificationState(row.GroupId, row.RequestId)
		if err != nil {
			continue
		}
		items = append(items, gin.H{
			"presentationId":      state,
			"requestId":           row.RequestId,
			"groupId":             row.GroupId,
			"status":              row.State,
			"lastUpdateTimeStamp": row.LastUpdateTimeStamp,
		})
	}
	c.JSON(http.StatusOK, gin.H{"presentations": items})
}
