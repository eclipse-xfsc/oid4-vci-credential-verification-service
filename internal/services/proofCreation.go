package services

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	logr "github.com/eclipse-xfsc/microservice-core-go/pkg/logr"

	commonTypes "github.com/eclipse-xfsc/oid4-vci-credential-verification-service/internal/common"
	"github.com/eclipse-xfsc/oid4-vci-credential-verification-service/internal/model"
	"github.com/eclipse-xfsc/oid4-vci-credential-verification-service/internal/services/common"
	"github.com/eclipse-xfsc/oid4-vci-vp-library/model/presentation"
	"github.com/eclipse-xfsc/oid4-vci-vp-library/model/types"
	"github.com/gin-gonic/gin"
)

const (
	AssignError         = "Assign Error"
	RecordNotFoundError = "Record not found"
	BodyError           = "Can not read body."
	MarshallingError    = "Error during marshalling"
	SignError           = "Error during Signing"
	TransmitError       = "Transmit Error"
	PostResponseError   = "Error posting data to response uri"
)

// HandleCreateProofById godoc
// @Summary Completes and proof request by signing and posting it
// @Description Completes and proof request by signing and posting it
// @Tags internal
// @Accept json
// @Produce json
// @Param tenantId path string true "Tenant ID"
// @Param id path string true "Proof ID"
// @Param body body model.ProofModel true "Proof Model"
// @Success 200
// @Failure 400 {object} ServerErrorResponse
// @Failure 500 {object} ServerErrorResponse
// @Router /v1/tenants/{tenantId}/internal/proofs/proof/{id} [post]
func HandleCreateProofById(ctx *gin.Context, config *model.Config) {
	handleCreateProof(ctx, config, false)
}

// HandleCreateProofByRequestId godoc
// @Summary Completes and proof request by signing and posting it
// @Description Completes and proof request by signing and posting it
// @Tags internal
// @Accept json
// @Produce json
// @Param tenantId path string true "Tenant ID"
// @Param id path string true "Proof RequestID"
// @Param body body model.ProofModel true "Proof Model"
// @Success 200
// @Failure 400 {object} ServerErrorResponse
// @Failure 500 {object} ServerErrorResponse
// @Router /v1/tenants/{tenantId}/internal/proofs/proof/request/{id} [post]
func HandleCreateProofByRequestId(ctx *gin.Context, config *model.Config) {
	handleCreateProof(ctx, config, true)
}

func handleCreateProof(ctx *gin.Context, config *model.Config, byRequestId bool) {
	id := ctx.Param("id")
	tenantId := ctx.Param("tenantId")
	context := ctx.Request.Context()
	logger := commonTypes.GetEnvironment().GetLogger()

	reqBody, err := io.ReadAll(ctx.Request.Body)

	if err != nil {
		ErrorResponse(ctx, BodyError, errors.New(BodyError))
		return
	}

	ctx.Request.Body.Close()

	var body model.ProofModel

	err = json.Unmarshal(reqBody, &body)

	if err != nil {
		ErrorResponse(ctx, MarshallingError, err)
		return
	}

	var row *model.VerificationEntry
	if byRequestId {
		row, err = common.GetEntryFromDbByRequestId(context, tenantId, id)
	} else {
		row, err = common.GetEntryFromDb(context, tenantId, id)
	}
	if err != nil {
		ErrorResponse(ctx, RecordNotFoundError, err)
		return
	}
	acquired, err := common.TryBeginFulfillment(context, row)
	if err != nil {
		ErrorResponse(ctx, "Cannot lock fulfillment", err)
		return
	}
	if !acquired {
		ctx.JSON(http.StatusConflict, gin.H{"error": "presentation already fulfilling or completed"})
		return
	}
	transmitted := false
	defer func() {
		if !transmitted {
			_ = common.ReleaseFulfillment(context, row)
		}
	}()
	res, err := signerServiceSignPresentations(body, row, logger, config)
	if err != nil {
		ErrorResponse(ctx, SignError, err)
		return
	}
	if err := res.ValidateAgainst(&row.DCQLQuery); err != nil {
		ErrorResponse(ctx, "DCQL validation failed", err)
		return
	}
	err = postResponse(context, res, row, logger)
	if err != nil {
		_ = ErrorResponse(ctx, PostResponseError, err)
		return
	}

	transmitted = true
	err = common.UpdateDbStatus(context, tenantId, string(model.PresentationTransmitted), id)

	if err != nil {
		ErrorResponse(ctx, TransmitError, err)
		return
	}

	ctx.JSON(200, nil)
	return
}

// HandleFulfillProofById resolves matching credentials from Credential Storage,
// creates/signs the VP token and submits it to the external verifier. This is
// the holder-side execution step and must only be called after the application
// has authorized disclosure.
func HandleFulfillProofById(ctx *gin.Context, config *model.Config) {
	id := ctx.Param("id")
	tenantID := ctx.Param("tenantId")
	logger := commonTypes.GetEnvironment().GetLogger()

	row, err := common.GetEntryFromDb(ctx.Request.Context(), tenantID, id)
	if err != nil {
		ErrorResponse(ctx, RecordNotFoundError, err)
		return
	}

	var request model.FulfillPresentationRequest
	if err := ctx.ShouldBindJSON(&request); err != nil {
		ErrorResponse(ctx, BodyError, err)
		return
	}
	if request.HolderDid == "" || request.SignKey == "" {
		ErrorResponse(ctx, BodyError, errors.New("holderDid and signKey are required"))
		return
	}
	if request.SignNamespace == "" {
		request.SignNamespace = tenantID
	}
	if request.SignGroup == "" {
		request.SignGroup = row.GroupId
	}

	acquired, err := common.TryBeginFulfillment(ctx.Request.Context(), row)
	if err != nil {
		ErrorResponse(ctx, "Cannot lock fulfillment", err)
		return
	}
	if !acquired {
		ctx.JSON(http.StatusConflict, gin.H{"error": "presentation already fulfilling or completed"})
		return
	}
	transmitted := false
	defer func() {
		if !transmitted {
			_ = common.ReleaseFulfillment(ctx.Request.Context(), row)
		}
	}()

	groups, err := resolveCredentials(ctx.Request.Context(), config, row)
	if err != nil {
		ErrorResponse(ctx, "Credential selection failed", err)
		return
	}
	groups, err = applyCredentialSelectionPolicy(row.TenantId, row.GroupId, row.ClientId, row.DCQLQuery, groups, config.ExternalPresentation.CredentialSelectionPolicy)
	if err != nil {
		ErrorResponse(ctx, "Credential disclosure denied", err)
		return
	}

	proof := model.ProofModel{
		Payload:       groups,
		SignNamespace: request.SignNamespace,
		SignKey:       request.SignKey,
		SignGroup:     request.SignGroup,
		HolderDid:     request.HolderDid,
	}
	vpToken, err := signerServiceSignPresentations(proof, row, logger, config)
	if err != nil {
		ErrorResponse(ctx, SignError, err)
		return
	}
	if err := vpToken.ValidateAgainst(&row.DCQLQuery); err != nil {
		ErrorResponse(ctx, "DCQL validation failed", err)
		return
	}
	if err := postResponse(ctx.Request.Context(), vpToken, row, logger); err != nil {
		ErrorResponse(ctx, PostResponseError, err)
		return
	}
	transmitted = true // Never retry after a successful network submission.
	if err := common.UpdateDbStatus(ctx.Request.Context(), tenantID, string(model.PresentationTransmitted), id); err != nil {
		ErrorResponse(ctx, TransmitError, err)
		return
	}
	ctx.JSON(http.StatusOK, gin.H{"status": model.PresentationTransmitted})
}

// HandleGetProofRequestById godoc
// @Summary Retrieves a proof request by its ID
// @Description Retrieves a proof request by its ID
// @Tags internal
// @Accept json
// @Produce json
// @Param tenantId path string true "Tenant ID"
// @Param id path string true "Proof ID"
// @Success 200 {object} model.VerificationEntry
// @Failure 400 {object} ServerErrorResponse
// @Failure 500 {object} ServerErrorResponse
// @Router /v1/tenants/{tenantId}/internal/proofs/proof/{id} [get]
func HandleGetProofRequestById(ctx *gin.Context, config *model.Config) {
	handleGetProofRequest(ctx, config, false)
}

// HandleGetProofRequestByRequestId godoc
// @Summary Retrieves a proof request by its request ID
// @Description Retrieves a proof request by its request ID
// @Tags internal
// @Accept json
// @Produce json
// @Param tenantId path string true "Tenant ID"
// @Param id path string true "Proof RequestID"
// @Success 200 {object} model.VerificationEntry
// @Failure 400 {object} ServerErrorResponse
// @Failure 500 {object} ServerErrorResponse
// @Router /v1/tenants/{tenantId}/internal/proofs/proof/request/{id} [get]
func HandleGetProofRequestByRequestId(ctx *gin.Context, config *model.Config) {
	handleGetProofRequest(ctx, config, true)
}

func handleGetProofRequest(ctx *gin.Context, config *model.Config, byRequestId bool) {
	id := ctx.Param("id")
	tenantId := ctx.Param("tenantId")
	var row *model.VerificationEntry
	var err error
	if byRequestId {
		row, err = common.GetEntryFromDbByRequestId(ctx.Request.Context(), tenantId, id)
	} else {
		row, err = common.GetEntryFromDb(ctx.Request.Context(), tenantId, id)
	}
	if err == nil {
		ctx.JSON(200, row)
		return
	} else {
		ErrorResponse(ctx, RecordNotFoundError, errors.New(RecordNotFoundError))
	}
}

// HandleAssignProof godoc
// @Summary Assigns record to account
// @Description Assigns record to account
// @Tags internal
// @Accept json
// @Produce json
// @Param tenantId path string true "Tenant ID"
// @Param id path string true "Proof ID"
// @Param groupId path string true "Group ID"
// @Success 200
// @Failure 400 {object} ServerErrorResponse
// @Failure 500 {object} ServerErrorResponse
// @Router /v1/tenants/{tenantId}/internal/proofs/proof/{id}/assign/{groupId} [put]
func HandleAssignProof(ctx *gin.Context, config *model.Config) {
	id := ctx.Param("id")
	tenantId := ctx.Param("tenantId")
	groupId := ctx.Param("groupId")
	err := common.AssignEntryToGroup(ctx.Request.Context(), tenantId, id, groupId)

	if err == nil {
		ctx.AbortWithStatus(200)
		return
	} else {
		ErrorResponse(ctx, AssignError, errors.New(AssignError))
	}
}

// HandleListProof godoc
// @Summary Lists proofs for a group
// @Description Lists proofs for a group
// @Tags internal
// @Accept json
// @Produce json
// @Param tenantId path string true "Tenant ID"
// @Param groupId path string true "Group ID"
// @Success 200 {array} model.VerificationEntry
// @Failure 400 {object} ServerErrorResponse
// @Failure 500 {object} ServerErrorResponse
// @Router /v1/tenants/{tenantId}/internal/list/proofs/{groupId} [get]
func HandleListProof(ctx *gin.Context, config *model.Config) {
	groupId := ctx.Param("groupId")
	tenantId := ctx.Param("tenantId")

	row, err := common.GetEntriesFromDb(ctx.Request.Context(), tenantId, groupId)

	if err == nil {
		ctx.JSON(200, row)
		return
	} else {
		ErrorResponse(ctx, RecordNotFoundError, errors.New(RecordNotFoundError))
	}
}

func postResponse(ctx context.Context, vpToken presentation.VPToken, row *model.VerificationEntry, logger logr.Logger) error {
	if row == nil {
		return errors.New("row empty")
	}
	if err := vpToken.ValidateAgainst(&row.DCQLQuery); err != nil {
		return err
	}

	var formdata url.Values
	switch row.ResponseMode {
	case string(types.DirectPost):
		var err error
		formdata, err = getFormData(vpToken, row)
		if err != nil {
			return err
		}
	case string(types.DirectPostJwt):
		response := presentation.AuthorizationResponse{VPToken: vpToken, State: row.AuthorizationState}
		compact, err := (oid4vpResponseEncryptor{}).EncryptAuthorizationResponse(ctx, response, row.ClientMetadata)
		if err != nil {
			return fmt.Errorf("encrypt direct_post.jwt response: %w", err)
		}
		formdata = url.Values{"response": {compact}}
	default:
		return fmt.Errorf("unsupported response_mode %q", row.ResponseMode)
	}

	endpoint, err := validateOutboundURL(row.ResponseUri, commonTypes.GetEnvironment().GetConfig(), true)
	if err != nil {
		return fmt.Errorf("invalid response_uri: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint.String(), strings.NewReader(formdata.Encode()))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rep, err := externalHTTPClient(commonTypes.GetEnvironment().GetConfig()).Do(req)
	if err != nil {
		logger.Error(err, "Error during posting response", "responseUri", row.ResponseUri)
		return err
	}
	defer rep.Body.Close()
	if rep.StatusCode < http.StatusOK || rep.StatusCode >= http.StatusMultipleChoices {
		body, _ := io.ReadAll(rep.Body)
		return fmt.Errorf("response uri %s responded with %d: %s", row.ResponseUri, rep.StatusCode, string(body))
	}
	return nil
}

func getFormData(vpToken presentation.VPToken, row *model.VerificationEntry) (url.Values, error) {
	if row == nil {
		return nil, errors.New("row empty")
	}
	if err := vpToken.ValidateAgainst(&row.DCQLQuery); err != nil {
		return nil, err
	}
	encoded, err := vpToken.JSONString()
	if err != nil {
		return nil, err
	}
	formdata := url.Values{}
	formdata.Set("vp_token", encoded)
	if row.AuthorizationState != "" {
		formdata.Set("state", row.AuthorizationState)
	}
	return formdata, nil
}

func signerServiceSignPresentations(payload model.ProofModel, row *model.VerificationEntry, logger logr.Logger, config *model.Config) (presentation.VPToken, error) {
	result := make(presentation.VPToken, len(payload.Payload))
	for _, group := range payload.Payload {
		queryID := group.Id
		if queryID == "" {
			return nil, errors.New("DCQL query id is required")
		}

		switch group.Format {
		case types.SDJWT:
			if row == nil {
				return nil, errors.New("SD-JWT presentation requires transaction audience and nonce")
			}
			for _, credential := range group.Credentials {
				compact, ok := credential.(string)
				if !ok {
					return nil, fmt.Errorf("DCQL query %s contains a non-string SD-JWT credential", queryID)
				}
				request := map[string]interface{}{
					"group": payload.SignGroup, "issuer": payload.HolderDid, "key": payload.SignKey,
					"namespace": payload.SignNamespace, "presentation": compact,
					"format": string(types.SDJWT), "aud": row.ClientId, "nonce": row.Nonce,
					"disclosureFrame": []string{},
				}
				signed, err := processPresentationData(request, logger, config)
				if err != nil {
					return nil, err
				}
				result[queryID] = append(result[queryID], json.RawMessage(signed))
			}
		case types.LDPVC:
			var verPres map[string]interface{}
			filledTemplate := fmt.Sprintf(payloadtemplate, queryID, payload.HolderDid)
			if err := json.Unmarshal([]byte(filledTemplate), &verPres); err != nil {
				return nil, err
			}
			credentials := make([]interface{}, 0, len(group.Credentials))
			for _, cred := range group.Credentials {
				credentials = append(credentials, cred)
			}
			verPres["verifiableCredential"] = credentials
			request := getSignerServiceProofPayload(payload.SignGroup, payload.HolderDid, payload.SignKey, payload.SignNamespace, verPres)
			request["format"] = string(types.LDPVC)
			if row != nil {
				request["aud"] = row.ClientId
				request["nonce"] = row.Nonce
			}
			signed, err := processPresentationData(request, logger, config)
			if err != nil {
				return nil, err
			}
			result[queryID] = append(result[queryID], json.RawMessage(signed))
		default:
			return nil, fmt.Errorf("unsupported presentation format %q for DCQL query %s", group.Format, queryID)
		}
	}
	return result, nil
}

func processPresentationData(presentationRequest map[string]interface{}, logger logr.Logger, config *model.Config) ([]byte, error) {
	p, err := json.Marshal(presentationRequest)
	if err != nil {
		return nil, err
	}
	endpoint, err := validateOutboundURL(config.SignerService.PresentationSignUrl, config, false)
	if err != nil {
		return nil, fmt.Errorf("invalid signer URL: %w", err)
	}
	req, err := http.NewRequest(http.MethodPost, endpoint.String(), bytes.NewReader(p))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	rep, err := secureHTTPClient().Do(req)
	if err != nil {
		return nil, fmt.Errorf("signer service call failed: %w", err)
	}
	defer rep.Body.Close()
	respBody, err := io.ReadAll(io.LimitReader(rep.Body, maxHTTPResponseBytes+1))
	if err != nil {
		return nil, err
	}
	if int64(len(respBody)) > maxHTTPResponseBytes {
		return nil, errors.New("signer response exceeds size limit")
	}
	if rep.StatusCode < 200 || rep.StatusCode >= 300 {
		return nil, fmt.Errorf("signer service returned HTTP %d: %s", rep.StatusCode, strings.TrimSpace(string(respBody)))
	}
	return respBody, nil
}

func fromProofModelToPresentation(payload model.ProofModel, logger logr.Logger) ([]map[string]interface{}, error) {
	var res = make([]map[string]interface{}, 0)
	for _, pres := range payload.Payload {
		var verPres map[string]interface{}
		filledTemplate := fmt.Sprintf(payloadtemplate, pres.Id, payload.HolderDid)
		err := json.Unmarshal([]byte(filledTemplate), &verPres)
		if err != nil {
			logger.Error(err, "Error unmarshalling presentation")
			return nil, err
		}
		var credentials = make([]interface{}, 0)
		for _, cred := range pres.Credentials {
			credentials = append(credentials, cred)
		}
		verPres["verifiableCredential"] = credentials
		proof := getSignerServiceProofPayload(payload.SignGroup, payload.HolderDid, payload.SignKey, payload.SignNamespace, verPres)
		res = append(res, proof)
	}

	return res, nil
}

const payloadtemplate = `{
    "@context": [
        "https://www.w3.org/2018/credentials/v1",
		"https://w3id.org/security/suites/jws-2020/v1"
    ],
    "type": [
        "VerifiablePresentation"
    ],
    "verifiableCredential": [
    ],
    "id": "%s",
    "holder": "%s"
}`

const signerServicePayloadTemplate = `{
	"group": "Group",
	"issuer": "Quaerat odit optio.",
	"key": "key1",
	"namespace": "transit",
	"presentation": "Mollitia architecto rem beatae mollitia."
}`

func getSignerServiceProofPayload(group string, issuer string, key string, namespace string, presentation map[string]interface{}) map[string]interface{} {
	res := make(map[string]interface{})
	res["group"] = group
	res["issuer"] = issuer
	res["key"] = key
	res["namespace"] = namespace
	res["presentation"] = presentation
	return res
}
