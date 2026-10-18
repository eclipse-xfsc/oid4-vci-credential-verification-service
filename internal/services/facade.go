// Package services retains compatibility with callers while the implementation
// lives in the holder, verifier and common packages.
package services

import (
	"github.com/eclipse-xfsc/oid4-vci-credential-verification-service/internal/model"
	"github.com/eclipse-xfsc/oid4-vci-credential-verification-service/internal/services/common"
	"github.com/eclipse-xfsc/oid4-vci-credential-verification-service/internal/services/holder"
	"github.com/eclipse-xfsc/oid4-vci-credential-verification-service/internal/services/verifier"
	"github.com/gin-gonic/gin"
)

type AuthorizationHandler = holder.AuthorizationHandler
type ProcessedAuthorizationRequest = holder.ProcessedAuthorizationRequest
type PresentationRequestor = verifier.PresentationRequestor
type ServerErrorResponse = common.ServerErrorResponse

const (
	CredentialApiGroup = verifier.CredentialApiGroup
	InternalApiGroup   = verifier.InternalApiGroup
	DirectGroup        = verifier.DirectGroup
)

func ErrorResponse(c *gin.Context, message string, err error) error {
	return common.ErrorResponse(c, message, err)
}
func InternalErrorResponse(c *gin.Context, message string, err error) error {
	return common.InternalErrorResponse(c, message, err)
}
func HandleProof(c *gin.Context, r *PresentationRequestor, cfg *model.Config) {
	verifier.HandleProof(c, r, cfg)
}
func HandleCreateProofById(c *gin.Context, cfg *model.Config) { holder.HandleCreateProofById(c, cfg) }
func HandleCreateProofByRequestId(c *gin.Context, cfg *model.Config) {
	holder.HandleCreateProofByRequestId(c, cfg)
}
func HandleGetProofRequestById(c *gin.Context, cfg *model.Config) {
	holder.HandleGetProofRequestById(c, cfg)
}
func HandleGetProofRequestByRequestId(c *gin.Context, cfg *model.Config) {
	holder.HandleGetProofRequestByRequestId(c, cfg)
}
func HandleAssignProof(c *gin.Context, cfg *model.Config) { holder.HandleAssignProof(c, cfg) }
func HandleListProof(c *gin.Context, cfg *model.Config)   { holder.HandleListProof(c, cfg) }
