package middleware

import (
	"github.com/gin-gonic/gin"
	"github.com/eclipse-xfsc/oid4-vci-credential-verification-service/internal/common"
	"github.com/eclipse-xfsc/oid4-vci-credential-verification-service/internal/services"
)

func VerifyId(env *common.Environment) gin.HandlerFunc {
	return func(ctx *gin.Context) {
		id, b := ctx.Params.Get("id")
		tenantId, b2 := ctx.Params.Get("tenantId")

		if b && b2 {
			allow, err := services.VerifyId(tenantId, id, env.GetConfig().SigningKey)
			if !allow || err != nil {
				ctx.AbortWithStatus(401)
			}
		} else {
			ctx.AbortWithStatus(401)
		}
	}
}
