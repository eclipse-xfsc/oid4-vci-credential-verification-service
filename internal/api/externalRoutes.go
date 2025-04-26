package api

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"
	core "gitlab.eclipse.org/eclipse/xfsc/libraries/microservice/core/pkg/server"
	"gitlab.eclipse.org/eclipse/xfsc/libraries/ssi/oid4vip/model/presentation"
	"github.com/eclipse-xfsc/oid4-vci-credential-verification-service/internal/common"
	"github.com/eclipse-xfsc/oid4-vci-credential-verification-service/internal/middleware"
	"github.com/eclipse-xfsc/oid4-vci-credential-verification-service/internal/model"
	"github.com/eclipse-xfsc/oid4-vci-credential-verification-service/internal/services"
	svcCommon "github.com/eclipse-xfsc/oid4-vci-credential-verification-service/internal/services/common"
)

const (
	UnsupportedResponseType  = "Unsupported ResponseType"
	NoClientId               = "No Client Id"
	NoResponseType           = "No ResponseType"
	NoRedirectUri            = "No Redirect Uri"
	NoNonce                  = "No nonce"
	NoPresentationDefinition = "No Presentation Definition present"
	TenantIdMissing          = "Tenant Id missing"

	DefaultPresentationRequestTTL = 3600
)

func AddExternalRoutes(server *core.Server, authHandler *services.AuthorizationHandler, requestor *services.PresentationRequestor) {
	server.Add(func(rg *gin.RouterGroup) {
		config := common.GetEnvironment().GetConfig()
		g := rg.Group(services.CredentialApiGroup)
		mWGroup := g.Group(services.DirectGroup)
		mWGroup.Use(middleware.VerifyId(common.GetEnvironment()))
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
// @Param presentationDefinition query string true "Presentation Definition base64 url encoded"
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
		var options = svcCommon.PresentationRequestOptions{
			TenantId:  ctx.Request.Header.Get("x-tenantId"),
			RequestId: queryParams.Get("requestId"),
			GroupId:   ctx.Request.Header.Get("x-groupId"),
			Ttl:       ttl,
		}
		id, err := services.SignId(options.TenantId, config.SigningKey)
		if err != nil {
			services.ErrorResponse(ctx, "Error signing id", err)
			return
		}
		options.Id = id
		var definition presentation.PresentationDefinition
		definitionReader := base64.NewDecoder(base64.URLEncoding, strings.NewReader(queryParams.Get("presentationDefinition")))
		if err != nil {
			services.ErrorResponse(ctx, "Error decoding presentation definition", err)
			return
		}
		err = json.NewDecoder(definitionReader).Decode(&definition)
		if err != nil {
			services.ErrorResponse(ctx, "Error decoding presentation definition json", err)
			return
		}
		err = requestor.CreatePresentationRequest(definition, options, ctx.Request.Context())
		if err != nil {
			services.ErrorResponse(ctx, "Error creating presentation request", err)
			return
		}
		JwtResponse(ctx, requestor, config.PublicBasePath, id, options.TenantId, options.GroupId, ctx.Request.Header.Get("x-did"), ctx.Request.Header.Get("x-key"), config.ExternalPresentation.ClientUrlSchema)
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
		JwtResponse(c, requestor, path, id, tenantId, c.Request.Header.Get("x-group"), c.Request.Header.Get("x-did"), c.Request.Header.Get("x-key"), config.ExternalPresentation.ClientUrlSchema)

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

func RespondToken(c *gin.Context, authRequest presentation.RequestObject, tenantId string) {

	r, err := http.NewRequest("GET", authRequest.PresentationDefinitionUri, nil)
	r.Header.Add("Content-Type", "application/json")
	if err != nil {
		services.InternalErrorResponse(c, err.Error(), err)
		return
	}

	client := &http.Client{}
	res, err := client.Do(r)
	if err != nil {
		services.InternalErrorResponse(c, "Presentation Definition URI not reachable.", err)
		return
	}

	defer res.Body.Close()

	var presentationDefinition presentation.PresentationDefinition

	derr := json.NewDecoder(res.Body).Decode(&presentationDefinition)
	if derr != nil {
		services.InternalErrorResponse(c, "Presentation Definition not valid.", err)
		return
	}
}
