package api

import (
	core "github.com/eclipse-xfsc/microservice-core-go/pkg/server"
	svcCommon "github.com/eclipse-xfsc/oid4-vci-credential-verification-service/internal/services/common"
	"github.com/google/uuid"
	"net/http"
	"net/url"
	"strings"

	"github.com/eclipse-xfsc/oid4-vci-credential-verification-service/internal/common"
	"github.com/eclipse-xfsc/oid4-vci-credential-verification-service/internal/middleware"
	"github.com/eclipse-xfsc/oid4-vci-credential-verification-service/internal/services"
	"github.com/gin-gonic/gin"
)

// TODO Better Nats?
func AddInternalRoutes(server *core.Server, requestor *services.PresentationRequestor) {
	server.Add(func(rg *gin.RouterGroup) {
		config := common.GetEnvironment().GetConfig()
		g := rg.Group(services.InternalApiGroup)

		g.POST("/presentations/authorization", func(c *gin.Context) {
			var body struct {
				PresentationPolicyID string `json:"presentationPolicyId"`
				TTL                  int    `json:"ttl"`
				ClientID             string `json:"clientId"`
			}
			if err := c.ShouldBindJSON(&body); err != nil || body.PresentationPolicyID == "" || body.ClientID == "" {
				c.JSON(http.StatusBadRequest, gin.H{"error": "presentationPolicyId and clientId required"})
				return
			}
			tenant := c.Param("tenantId")
			group := c.GetHeader("x-groupid")
			if tenant == "" || group == "" {
				c.JSON(http.StatusBadRequest, gin.H{"error": "tenantId and x-groupid required"})
				return
			}
			if body.TTL == 0 {
				body.TTL = 3600
			}
			if body.TTL < 1 || body.TTL > 86400 {
				c.JSON(http.StatusBadRequest, gin.H{"error": "ttl must be between 1 and 86400"})
				return
			}
			requestID := uuid.NewString()
			options := svcCommon.PresentationRequestOptions{TenantId: tenant, GroupId: group, RequestId: requestID, Ttl: body.TTL, ClientId: body.ClientID}
			policy, err := requestor.CreateFromPolicy(c.Request.Context(), tenant, group, body.PresentationPolicyID, options)
			if err != nil {
				c.JSON(http.StatusBadGateway, gin.H{"error": err.Error()})
				return
			}
			state, err := svcCommon.EncodeVerificationState(group, requestID)
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
				return
			}
			public := strings.TrimRight(config.PublicBasePath, "/")
			// PUBLICBASEPATH must be an absolute HTTPS origin + tenant prefix for this endpoint.
			base, err := url.Parse(public)
			if err != nil || base.Scheme != "https" || base.Host == "" {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "PUBLICBASEPATH must be absolute HTTPS URL to public tenant prefix"})
				return
			}
			requestURI := public + "/presentation/proof/" + url.PathEscape(state) + "/request-object/request.jwt"
			link := "openid4vp://?" + url.Values{"request_uri": {requestURI}, "client_id": {body.ClientID}}.Encode()
			c.JSON(http.StatusCreated, gin.H{"presentationId": state, "requestId": requestID, "presentationPolicyId": policy.ID, "policyVersion": policy.Version, "authorizationUrl": link, "requestUri": requestURI, "ttl": body.TTL})
		})

		// Trusted internal verifier retrieval. Do not expose through external routes.
		// Group isolation is enforced by the handler using x-groupid.
		v := g.Group("presentations")
		v.GET("", func(ctx *gin.Context) {
			services.HandleListVerifiedPresentations(ctx)
		})
		v.GET("/:id", func(ctx *gin.Context) {
			services.HandleGetVerifiedPresentation(ctx)
		})

		pR := g.Group("proofs")
		pR.Use(middleware.VerifyState(common.GetEnvironment()))

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
