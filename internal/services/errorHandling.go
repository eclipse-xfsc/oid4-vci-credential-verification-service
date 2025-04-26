package services

import (
	"errors"

	"github.com/gin-gonic/gin"
	"github.com/eclipse-xfsc/oid4-vci-credential-verification-service/internal/common"
)

type ServerErrorResponse struct {
	Message string `json:"message"`
}

func ErrorResponse(c *gin.Context, err string, exception error) error {
	log := common.GetEnvironment().GetLogger()
	if exception != nil {
		log.Error(exception, "Detailed Error: "+exception.Error())
	} else {
		log.Error(errors.New(err), err)
	}

	c.JSON(400, ServerErrorResponse{
		Message: err,
	})
	return errors.New(err)
}

func InternalErrorResponse(c *gin.Context, err string, exception error) error {
	log := common.GetEnvironment().GetLogger()
	if exception != nil {
		log.Error(exception, "Detailed Error: "+exception.Error())
	} else {
		log.Error(errors.New(err), err)
	}

	c.JSON(500, ServerErrorResponse{
		Message: err,
	})
	return errors.New(err)
}
