package services

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"

	"github.com/gin-gonic/gin"
	logr "gitlab.eclipse.org/eclipse/xfsc/libraries/microservice/core/pkg/logr"
	"gitlab.eclipse.org/eclipse/xfsc/libraries/ssi/oid4vip/model/presentation"
	commonTypes "github.com/eclipse-xfsc/oid4-vci-credential-verification-service/internal/common"
	"github.com/eclipse-xfsc/oid4-vci-credential-verification-service/internal/model"
	"github.com/eclipse-xfsc/oid4-vci-credential-verification-service/internal/services/common"
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
// @Router /internal/proofs/proof/{id} [post]
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
// @Router /internal/proofs/proof/request/{id} [post]
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

	res, err := signerServiceSignLdpJson(body, logger, config)

	if err != nil {
		ErrorResponse(ctx, SignError, err)
		return
	}

	var row *model.VerificationEntry
	if byRequestId {
		row, err = common.GetEntryFromDbByRequestId(context, tenantId, id)
	} else {
		row, err = common.GetEntryFromDb(context, tenantId, id)
	}
	if err != nil {
		_ = ErrorResponse(ctx, RecordNotFoundError, err)
		return
	}
	for _, pres := range res {
		err = postResponse(pres, row, body, logger)

		if err != nil {
			_ = ErrorResponse(ctx, PostResponseError, err)
			//TODO Retry?
			return
		}
	}

	err = common.UpdateDbStatus(context, tenantId, string(model.PresentationTransmitted), id)

	if err != nil {
		ErrorResponse(ctx, TransmitError, err)
		return
	}

	ctx.JSON(200, nil)
	return
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
// @Router /internal/proofs/proof/{id} [get]
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
// @Router /internal/proofs/proof/request/{id} [get]
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
// @Router /internal/proofs/proof/{id}/assign/{groupId} [put]
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
// @Router /internal/list/proofs/{groupId} [get]
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

func postResponse(vpToken []byte, row *model.VerificationEntry, proofModel model.ProofModel, logger logr.Logger) error {

	formdata, err := getFormData(vpToken, row, proofModel, logger)
	if err != nil {
		return err
	}

	rep, err := GetHttpClient().PostForm(row.ResponseUri, formdata)

	if err != nil {
		logger.Error(err, "Error during posting response", "responseUri", row.ResponseUri)
		return err
	}

	if rep.StatusCode != 200 {
		err = fmt.Errorf("response uri %s responded an error", row.ResponseUri)
		b, er := io.ReadAll(rep.Body)
		if er == nil {
			err = errors.Join(err, errors.New(string(b)))
		}
		logger.Error(err, "")
		return err
	}
	return nil
}

func getFormData(vpToken []byte, row *model.VerificationEntry, proofModel model.ProofModel, logger logr.Logger) (url.Values, error) {
	if row == nil {
		return nil, errors.New("row empty")
	}

	var descriptors []presentation.Description = make([]presentation.Description, 0)
	for _, filter := range proofModel.Payload {
		descriptors = append(descriptors, filter.Description)
	}

	submission := presentation.CreateSubmission(row.PresentationDefinition.Id, descriptors)

	bytes, err := json.Marshal(submission)

	if err != nil {
		logger.Error(err, "created invalid submission")
		return nil, err
	}

	formdata := url.Values{}
	formdata.Add("vp_token", string(vpToken))
	formdata.Add("presentation_submission", string(bytes))
	return formdata, nil
}

func signerServiceSignLdpJson(payload model.ProofModel, logger logr.Logger, config *model.Config) ([][]byte, error) {
	presentations, err := fromProofModelToPresentation(payload, logger)
	if err != nil {
		return nil, err
	}
	var res = make([][]byte, 0)

	for _, pres := range presentations {
		b, err := processPresentationData(err, pres, logger, config)
		if err != nil {
			return nil, err
		}
		res = append(res, b)
	}
	return res, nil
}

func processPresentationData(err error, presentation map[string]interface{}, logger logr.Logger, config *model.Config) ([]byte, error) {
	p, err := json.Marshal(presentation)

	if err != nil {
		logger.Error(err, "Error marshalling presentations.")
		return nil, err
	}

	logger.Debug("sending presentation to sign", "presentation\n", string(p))

	rep, err := http.DefaultClient.Post(config.SignerService.PresentationSignUrl, "application/json", bytes.NewBuffer(p))

	if err != nil {
		logger.Error(err, "Error during signer service call")
		return nil, err
	}

	respBody, err := io.ReadAll(rep.Body)

	if err != nil {
		logger.Error(err, "Error during response body read")
		return nil, err
	}

	defer rep.Body.Close()

	if rep.StatusCode != http.StatusOK {
		return nil, errors.New("signer service call error. result was: " + string(respBody))
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
