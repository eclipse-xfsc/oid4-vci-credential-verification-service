package services

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"gitlab.eclipse.org/eclipse/xfsc/libraries/messaging/cloudeventprovider"
	"gitlab.eclipse.org/eclipse/xfsc/libraries/ssi/oid4vip/model/presentation"
	"gitlab.eclipse.org/eclipse/xfsc/libraries/ssi/oid4vip/model/types"
	oidtypes "gitlab.eclipse.org/eclipse/xfsc/libraries/ssi/oid4vip/model/types"
	"github.com/eclipse-xfsc/oid4-vci-credential-verification-service/internal/common"
	"github.com/eclipse-xfsc/oid4-vci-credential-verification-service/internal/model"
	commonServices "github.com/eclipse-xfsc/oid4-vci-credential-verification-service/internal/services/common"
	commonMessageTypes "gitlab.eclipse.org/eclipse/xfsc/organisational-credential-manager-w-stack/libraries/messaging/common"
	storageMessaging "gitlab.eclipse.org/eclipse/xfsc/organisational-credential-manager-w-stack/storage-service/pkg/messaging"
)

// HandleProof godoc
// @Summary Handles the proof request
// @Description Handles the proof request by checking the content type and form data, and then processing the presentations
// @Tags external
// @Accept x-www-form-urlencoded
// @Produce json
// @Param tenantId path string true "Tenant ID"
// @Param id path string true "Proof ID"
// @Param vp_token formData string true "The presentation token"
// @Param presentation_submission formData string true "The presentation submission"
// @Success 200
// @Failure 400 {object} ServerErrorResponse
// @Failure 500 {object} ServerErrorResponse
// @Router /presentation/proof/{id} [post]
func HandleProof(c *gin.Context, requestor *PresentationRequestor, config *model.Config) {

	if c.ContentType() != "application/x-www-form-urlencoded" {
		ErrorResponse(c, "Wrong content Type", errors.New("unsuported media type"))
		return
	}
	var response presentation.ResponseParameters

	vp_token := strings.Replace(c.Request.FormValue("vp_token"), "\n", "", -1)
	submission := strings.Replace(c.Request.FormValue("presentation_submission"), "\n", "", -1)

	if vp_token == "" || submission == "" {
		ErrorResponse(c, "Form data missing.", errors.New("form data missing"))
		return
	}

	err := json.Unmarshal([]byte(submission), &response.PresentationSubmission)

	if err != nil {
		ErrorResponse(c, "Form data missing.", errors.New("form data failure in presentation data"))
		return
	}

	err = response.PresentationSubmission.CheckSubmissionData()

	if err != nil {
		ErrorResponse(c, "Form data missing.", errors.New("form data missing"))
		return
	}

	var element interface{}
	err = json.Unmarshal([]byte(vp_token), &element)
	var elements = []interface{}{element}
	if err != nil {
		ErrorResponse(c, "Presentation cant be parsed", errors.New("presentation cant be parsed"))
		return
	}

	///Check Formats first
	var supported = true
	for _, x := range response.PresentationSubmission.DescriptorMap {
		if strings.Compare(x.Format, string(types.LDPVP)) == 0 {
			supported = true
		} else {
			supported = false
			break
		}
		//TODO add more types
	}

	if !supported {
		ErrorResponse(c, "Presentation not supported", errors.New("presentation format not supported"))
		return
	}

	id := c.Param("id")
	tenantId := c.Param("tenantId")
	ctx := c.Request.Context()

	err = requestor.CheckPresentations(ctx, id, tenantId, elements, response.PresentationSubmission.DescriptorMap, common.GetEnvironment())

	if err != nil {
		ErrorResponse(c, "error during receiving", errors.New("error during receiving"))
		return
	}

	c.JSON(200, nil)
}

func (requestor *PresentationRequestor) CheckPresentations(ctx context.Context, id string, tenantId string, elements []interface{}, decriptorMap []presentation.Descriptor, env *common.Environment) error {

	//Check Presentations really
	var validPresentations = true
	for i, x := range decriptorMap {
		if strings.Compare(x.Format, string(oidtypes.LDPVP)) == 0 {
			err, b := requestor.signerServiceCheckUpLdpJson(elements[i].(map[string]interface{}), id, tenantId)
			if err != nil {
				requestor.logger.Error(err, "signer service check failed")
				return err
			}

			validPresentations = validPresentations && b
		}

		if strings.Compare(x.Format, string(oidtypes.JWTVC)) == 0 {
			//TODO Other formats
		}
	}

	if validPresentations {
		for i, x := range decriptorMap {
			if strings.Compare(x.Format, string(oidtypes.LDPVP)) == 0 {
				row, err := commonServices.GetEntryFromDb(ctx, tenantId, id)

				if err != nil && row.RequestId == "" {
					requestor.logger.Error(err, "did not find process presentation definition")
					return err
				}
				b, err := json.Marshal(elements[i])
				if err != nil {
					requestor.logger.Error(err, "cannot unmarshal presentation")
					return errors.New("cannot unmarshal presentation")
				}
				err = commonServices.StorePresentation(ctx, id, tenantId, b)

				if err != nil {
					requestor.logger.Error(err, "store presentation failed")
					return err
				}

				requestor.forwardPresentation(tenantId, row.RequestId, row.GroupId, b)
				requestor.publishStatus(tenantId, row.RequestId, id, string(model.PresentationReceived))
			}

			if strings.Compare(x.Format, string(oidtypes.JWTVC)) == 0 {
				//TODO Other formats
			}
		}
	} else {
		err := commonServices.UpdateDbStatus(ctx, tenantId, string(model.PresentationRejected), id)

		if err != nil {
			requestor.logger.Error(err, "failed to update status")
			return err
		}
		//No bad return by purpose, sender shall think that all was fine (but nothing will happen) --> Sender can't try and error which presentation may be accepted.
	}

	return nil
}

func (requestor *PresentationRequestor) signerServiceCheckUpLdpJson(j map[string]interface{}, id string, tenantId string) (error, bool) {
	presBytes, err := json.Marshal(j)
	if err != nil {
		requestor.logger.Error(err, "Error marshalling presentation")
		return err, false
	}
	verPres := map[string][]byte{"presentation": presBytes}
	body, err := json.Marshal(verPres)
	if err != nil {
		requestor.logger.Error(err, "Error marshalling presentation")
		return err, false

	}
	requestor.logger.Info("Checking presentation", "body", string(body))
	if err != nil {
		requestor.logger.Error(err, "Error marshalling signer service request")
		return err, false
	}
	requestor.logger.Debug("Sending to signer service PresentationVerifyUrl", "body", string(body))
	rep, err := http.DefaultClient.Post(requestor.config.SignerService.PresentationVerifyUrl, "application/json", bytes.NewBuffer(body))

	if err != nil {
		requestor.logger.Error(err, "Error during signer service call")
		return err, false
	}

	respBody, err := io.ReadAll(rep.Body)

	if err != nil {
		requestor.logger.Error(err, "Error during response body read")
		return err, false
	}

	rep.Body.Close()

	if rep.StatusCode != http.StatusOK {
		return errors.New("signer service call error. result was: " + string(respBody)), false
	}

	var resultBody map[string]interface{}

	err = json.Unmarshal(respBody, &resultBody)

	if err != nil {
		requestor.logger.Error(err, "Error during response body read")
		return err, false
	}

	valid, ok := resultBody["valid"]

	if ok {
		b, ok := valid.(bool)
		if ok {
			return nil, b
		}
	}

	return nil, false
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
