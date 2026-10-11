package middleware

import (
	"net/http"

	"github.com/eclipse-xfsc/oid4-vci-credential-verification-service/internal/common"
	serviceCommon "github.com/eclipse-xfsc/oid4-vci-credential-verification-service/internal/services/common"
	"github.com/gin-gonic/gin"
)

const (
	VerificationGroupIDContextKey   = "verificationGroupId"
	VerificationRequestIDContextKey = "verificationRequestId"
)

// VerifyState validates the HMAC-protected verification state carried in the
// legacy :id route parameter and exposes its groupId/requestId to handlers.
func VerifyState(_ *common.Environment) gin.HandlerFunc {
	return func(ctx *gin.Context) {
		state, ok := ctx.Params.Get("id")
		if !ok || state == "" {
			ctx.AbortWithStatus(http.StatusUnauthorized)
			return
		}

		verificationState, err := serviceCommon.DecodeVerificationState(state)
		if err != nil {
			ctx.AbortWithStatus(http.StatusUnauthorized)
			return
		}

		ctx.Set(VerificationGroupIDContextKey, verificationState.GroupId)
		ctx.Set(VerificationRequestIDContextKey, verificationState.RequestId)
		ctx.Next()
	}
}
