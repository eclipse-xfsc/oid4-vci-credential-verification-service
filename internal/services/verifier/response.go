package verifier

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	shared "github.com/eclipse-xfsc/oid4-vci-credential-verification-service/internal/services/common"
	"io"
	"net/http"

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

	state := c.PostForm("state")
	if state == "" || state != id {
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
			} else if credentialQuery.Format == types.SDJWT && result.DisclosedCredential != nil {
				if err := validateDisclosedCredential(queryID, result.DisclosedCredential, *credentialQuery); err != nil {
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
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("crypto-provider presentation verify call: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
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
