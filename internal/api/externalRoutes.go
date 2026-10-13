package api

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"

	core "github.com/eclipse-xfsc/microservice-core-go/pkg/server"

	"github.com/eclipse-xfsc/oid4-vci-credential-verification-service/internal/common"
	"github.com/eclipse-xfsc/oid4-vci-credential-verification-service/internal/middleware"
	"github.com/eclipse-xfsc/oid4-vci-credential-verification-service/internal/model"
	"github.com/eclipse-xfsc/oid4-vci-credential-verification-service/internal/services"
	svcCommon "github.com/eclipse-xfsc/oid4-vci-credential-verification-service/internal/services/common"
	"github.com/eclipse-xfsc/oid4-vci-vp-library/model/presentation"
	"github.com/gin-gonic/gin"
)

const (
	UnsupportedResponseType = "Unsupported ResponseType"
	NoClientId              = "No Client Id"
	NoResponseType          = "No ResponseType"
	NoRedirectUri           = "No Redirect Uri"
	NoNonce                 = "No nonce"
	NoDCQLQuery             = "No DCQL query present"
	TenantIdMissing         = "Tenant Id missing"

	DefaultPresentationRequestTTL = 3600
)

func AddExternalRoutes(server *core.Server, authHandler *services.AuthorizationHandler, requestor *services.PresentationRequestor) {
	server.Add(func(rg *gin.RouterGroup) {
		config := common.GetEnvironment().GetConfig()
		g := rg.Group(services.CredentialApiGroup)
		mWGroup := g.Group(services.DirectGroup)
		mWGroup.Use(middleware.VerifyState(common.GetEnvironment()))
		mWGroup.GET("/:id/request-object/request.jwt", func(ctx *gin.Context) {
			ResponseRequestObject(ctx, requestor, config)
		})

		//Receiving the proof from a direct post call
		mWGroup.POST("/:id", func(ctx *gin.Context) {
			services.HandleProof(ctx, requestor, config)
		})

		//allowing redirects from externals
		if config.ExternalPresentation.Enabled {
			g.GET("/authorize", func(ctx *gin.Context) {
				authHandler.HandleAuthorizationRequest(ctx, config)
			})

			g.GET("/request", HandleRequestPresentation(requestor, config))
		}
	})
}

// HandleRequestPresentation godoc
// @Summary Handles the request for presentation
// @Description Handles the request for presentation by creating a presentation request with the provided parameters
// @Tags external
// @Produce application/jwt
// @Param x-tenantId header string true "Tenant ID"
// @Param requestId query string true "Request ID"
// @Param x-groupId header string true "Group ID"
// @Param x-ttl header int 200 "TTL"
// @Param x-did header int false "DID"
// @Param x-key header int false "KEY"
// @Param dcqlQuery query string true "DCQL query base64url encoded"
// @Success 200 {string} jwt
// @Failure 400 {object} services.ServerErrorResponse
// @Failure 500 {object} services.ServerErrorResponse
// @Router /presentation/request [get]
func HandleRequestPresentation(requestor *services.PresentationRequestor, config *model.Config) func(ctx *gin.Context) {
	return func(ctx *gin.Context) {
		queryParams := ctx.Request.URL.Query()
		ttl, err := strconv.Atoi(ctx.Request.Header.Get("x-ttl"))
		if err != nil {
			ttl = DefaultPresentationRequestTTL
		}
		clientID := ctx.Request.Header.Get("x-client-id")
		if clientID == "" {
			did := ctx.Request.Header.Get("x-did")
			if did != "" {
				clientID = "decentralized_identifier:" + did
			}
		}
		var options = svcCommon.PresentationRequestOptions{
			TenantId: ctx.Request.Header.Get("x-tenantId"), RequestId: queryParams.Get("requestId"),
			GroupId: ctx.Request.Header.Get("x-groupId"), Ttl: ttl, ClientId: clientID,
		}
		state, err := svcCommon.EncodeVerificationState(options.GroupId, options.RequestId)
		if err != nil {
			services.ErrorResponse(ctx, "Error creating verification state", err)
			return
		}
		var query presentation.DCQLQuery
		queryReader := base64.NewDecoder(base64.RawURLEncoding, strings.NewReader(queryParams.Get("dcqlQuery")))
		err = json.NewDecoder(queryReader).Decode(&query)
		if err != nil {
			services.ErrorResponse(ctx, "Error decoding DCQL query", err)
			return
		}
		err = requestor.CreatePresentationRequest(query, options, ctx.Request.Context())
		if err != nil {
			services.ErrorResponse(ctx, "Error creating presentation request", err)
			return
		}
		JwtResponse(ctx, requestor, config.PublicBasePath, state, options.TenantId, options.GroupId, ctx.Request.Header.Get("x-did"), ctx.Request.Header.Get("x-key"), config.ExternalPresentation.ClientUrlSchema)
	}
}

// ResponseRequestObject godoc
// @Summary Responds with a request object
// @Description Responds with a request object by fetching the request object and setting it as fetched
// @Tags external
// @Produce application/jwt
// @Param x-tenantId header string true "Tenant ID"
// @Param x-groupId header string true "Group ID"
// @Param id path string true "Proof ID"
// @Success 200 {string} jwt
// @Failure 400 {object} services.ServerErrorResponse
// @Failure 500 {object} services.ServerErrorResponse
// @Router /presentation/proof/{id}/request-object/request.jwt [get]
func ResponseRequestObject(c *gin.Context, requestor *services.PresentationRequestor, config *model.Config) {

	id, b := c.Params.Get("id")
	tenantId, b2 := c.Params.Get("tenantId")

	path := strings.Replace(c.Request.RequestURI, "/"+id+"/request-object/request.jwt", "", -1)
	if b && b2 {
		JwtResponse(c, requestor, path, id, tenantId, c.Request.Header.Get("x-groupId"), c.Request.Header.Get("x-did"), c.Request.Header.Get("x-key"), config.ExternalPresentation.ClientUrlSchema)

	} else {
		services.ErrorResponse(c, "Params not found.", http.ErrNotSupported)
	}
}

func JwtResponse(c *gin.Context, requestor *services.PresentationRequestor, path string, id string, tenantId, groupId, did, key, schema string) {

	str, err := requestor.GetRequestObjectAndSetObjectFetched(c.Request.Context(), schema, c.Request.Host, path, id, tenantId, groupId, did, key)

	if err != nil {
		services.ErrorResponse(c, "Request object fetching failed.", err)
	}
	c.Header("Content-Type", "application/jwt")
	c.JSON(200, string(str))
}
