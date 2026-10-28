package api

import (
	core "github.com/eclipse-xfsc/microservice-core-go/pkg/server"
	svcCommon "github.com/eclipse-xfsc/oid4-vci-credential-verification-service/internal/services/common"
	"github.com/google/uuid"
	"net/http"
	"net/url"

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

		// Administrative profile API: expose only through the trusted internal gateway.
		admin := g.Group("/presentation-profiles", middleware.ProfileAdminJWT())
		admin.GET("", func(c *gin.Context) {
			tenant, group := c.Param("tenantId"), c.GetHeader("x-groupid")
			if tenant == "" || group == "" {
				c.JSON(http.StatusBadRequest, gin.H{"error": "tenant and x-groupid required"})
				return
			}
			profiles, err := svcCommon.ListPresentationProfilesForAdmin(c.Request.Context(), tenant, group)
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to list presentation profiles"})
				return
			}
			c.JSON(http.StatusOK, profiles)
		})
		admin.DELETE("/:profileType/:interactionType", func(c *gin.Context) {
			tenant, group := c.Param("tenantId"), c.GetHeader("x-groupid")
			if tenant == "" || group == "" || !svcCommon.ValidProfileType(c.Param("profileType")) || !svcCommon.ValidInteractionType(c.Param("interactionType")) {
				c.JSON(http.StatusBadRequest, gin.H{"error": "invalid tenant, group, profile type or interaction type"})
				return
			}
			if err := svcCommon.DeletePresentationProfileForAdmin(c.Request.Context(), tenant, group, c.Param("profileType"), c.Param("interactionType")); err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to delete presentation profile"})
				return
			}
			c.Status(http.StatusNoContent)
		})
		admin.GET("/:profileType/:interactionType", func(c *gin.Context) {
			tenant, group := c.Param("tenantId"), c.GetHeader("x-groupid")
			profile, err := svcCommon.GetPresentationProfileForAdmin(c.Request.Context(), tenant, group, c.Param("profileType"), c.Param("interactionType"))
			if err != nil {
				c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
				return
			}
			c.JSON(http.StatusOK, profile)
		})
		admin.PUT("/:profileType/:interactionType", func(c *gin.Context) {
			tenant, group := c.Param("tenantId"), c.GetHeader("x-groupid")
			if tenant == "" || group == "" {
				c.JSON(http.StatusBadRequest, gin.H{"error": "tenant and group required"})
				return
			}
			var profile svcCommon.PresentationProfile
			if err := c.ShouldBindJSON(&profile); err != nil {
				c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
				return
			}
			profile.TenantID = tenant
			profile.GroupID = group
			profile.ProfileType = c.Param("profileType")
			profile.InteractionType = c.Param("interactionType")
			if profile.ProfileID == uuid.Nil {
				profile.ProfileID = uuid.New()
			}
			// Preserve the stable UUID across updates.
			old, err := svcCommon.GetPresentationProfileForAdmin(c.Request.Context(), tenant, group, profile.ProfileType, profile.InteractionType)
			if err == nil {
				profile.ProfileID = old.ProfileID
				profile.CreatedAt = old.CreatedAt
			}
			if err := svcCommon.SavePresentationProfile(c.Request.Context(), &profile); err != nil {
				c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
				return
			}
			c.JSON(http.StatusOK, profile)
		})
		g.POST("/presentations/authorization", func(c *gin.Context) {
			var body struct {
				PermissionSet string `json:"permissionSet"`
				TTL           int    `json:"ttl"`
			}
			if err := c.ShouldBindJSON(&body); err != nil || body.PermissionSet == "" {
				c.JSON(http.StatusBadRequest, gin.H{"error": "permissionSet required"})
				return
			}
			tenant := c.Param("tenantId")
			group := c.GetHeader("x-groupid")
			if tenant == "" || group == "" {
				c.JSON(http.StatusBadRequest, gin.H{"error": "tenantId and x-groupid required"})
				return
			}

			if body.TTL < 0 || body.TTL > 86400 {
				c.JSON(http.StatusBadRequest, gin.H{"error": "ttl must be between 1 and 86400"})
				return
			}
			profile, err := svcCommon.GetPresentationProfile(c.Request.Context(), tenant, group, "verifier", "human")
			if err != nil {
				c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
				return
			}
			clientID, err := svcCommon.ClientIDFromDID(profile.DID)
			if err != nil {
				c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
				return
			}
			origin, err := svcCommon.TenantOrigin(profile.Origin)
			if err != nil {
				c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
				return
			}
			if body.TTL == 0 {
				body.TTL = profile.RequestObjectTTLSeconds
			}
			requestID := uuid.NewString()
			options := svcCommon.PresentationRequestOptions{TenantId: tenant, GroupId: group, RequestId: requestID, Ttl: body.TTL, ClientId: clientID}
			policy, err := requestor.CreateFromPolicy(c.Request.Context(), tenant, group, "human", body.PermissionSet, options)
			if err != nil {
				c.JSON(http.StatusBadGateway, gin.H{"error": err.Error()})
				return
			}
			state, err := svcCommon.EncodeVerificationState(group, requestID)
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
				return
			}
			requestURI := origin.String() + "/api/verifier/presentation/proof/" + url.PathEscape(state) + "/request-object/request.jwt"
			link := "openid4vp://?" + url.Values{"request_uri": {requestURI}, "client_id": {clientID}}.Encode()
			c.JSON(http.StatusCreated, gin.H{"presentationId": state, "requestId": requestID, "permissionSet": policy.ID, "authorizationUrl": link, "requestUri": requestURI, "ttl": body.TTL})
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
