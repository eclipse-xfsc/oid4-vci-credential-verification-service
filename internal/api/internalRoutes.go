package api

import (
	"github.com/gin-gonic/gin"
	core "gitlab.eclipse.org/eclipse/xfsc/libraries/microservice/core/pkg/server"
	"github.com/eclipse-xfsc/oid4-vci-credential-verification-service/internal/common"
	"github.com/eclipse-xfsc/oid4-vci-credential-verification-service/internal/middleware"
	"github.com/eclipse-xfsc/oid4-vci-credential-verification-service/internal/services"
)

// TODO Better Nats?
func AddInternalRoutes(server *core.Server, requestor *services.PresentationRequestor) {
	server.Add(func(rg *gin.RouterGroup) {
		config := common.GetEnvironment().GetConfig()
		g := rg.Group(services.InternalApiGroup)

		pR := g.Group("proofs")
		pR.Use(middleware.VerifyId(common.GetEnvironment()))

		//Requests an incoming ID from the Database
		pR.GET("/proof/:id", func(ctx *gin.Context) {
			services.HandleGetProofRequestById(ctx, config)
		})

		pR.GET("/proof/request/:id", func(ctx *gin.Context) {
			services.HandleGetProofRequestByRequestId(ctx, config)
		})

		//Completes and proof request by signing and posting it
		pR.POST("/proof/:id", func(ctx *gin.Context) {
			services.HandleCreateProofById(ctx, config)
		})

		//Completes and proof request by signing and posting it
		pR.POST("/proof/request/:id", func(ctx *gin.Context) {
			services.HandleCreateProofByRequestId(ctx, config)
		})

		//Assigns record to account
		pR.PUT("/proof/:id/assign/:groupId", func(ctx *gin.Context) {
			services.HandleAssignProof(ctx, config)
		})

		pL := g.Group("list")

		//listing it
		pL.GET("/proofs/:groupId", func(ctx *gin.Context) {
			services.HandleListProof(ctx, config)
		})

	})
}
