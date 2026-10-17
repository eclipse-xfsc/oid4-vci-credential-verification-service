package api

import (
	"crypto/rand"
	"encoding/hex"
	"github.com/eclipse-xfsc/oid4-vci-credential-verification-service/internal/model"
	svc "github.com/eclipse-xfsc/oid4-vci-credential-verification-service/internal/services/common"
	"github.com/eclipse-xfsc/oid4-vci-credential-verification-service/internal/services/holder"
	"github.com/gin-gonic/gin"
	"net/http"
	"strings"
)

// holderContext is supplied by the trusted XFSC gateway and microservice-core-go.
// The URL tenant is authoritative; forwarded headers are routing context, not authentication.
type holderContext struct {
	TenantID  string
	GroupID   string
	Namespace string
	Group     string
	Host      string
}

func resolveHolderContext(c *gin.Context) (holderContext, bool) {
	tenant := strings.TrimSpace(c.Param("tenantId"))
	headerTenant := strings.TrimSpace(c.GetHeader("x-tenantid"))
	if tenant == "" || (headerTenant != "" && headerTenant != tenant) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "tenant context missing or conflicting"})
		return holderContext{}, false
	}
	groupID := strings.TrimSpace(c.GetHeader("x-groupid"))
	namespace := strings.TrimSpace(c.GetHeader("x-namespace"))
	keyGroup := strings.TrimSpace(c.GetHeader("x-group"))
	if groupID == "" || namespace == "" || keyGroup == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "x-groupid, x-namespace and x-group headers are required"})
		return holderContext{}, false
	}
	return holderContext{TenantID: tenant, GroupID: groupID, Namespace: namespace, Group: keyGroup, Host: c.GetHeader("x-host")}, true
}

// requireHolderContext enforces the expected upstream context shape; authorization
// of those headers remains the responsibility of the trusted gateway/account service.
func requireHolderContext(c *gin.Context) {
	context, ok := resolveHolderContext(c)
	if !ok {
		c.Abort()
		return
	}
	c.Set("holderContext", context)
	c.Next()
}
func getHolderContext(c *gin.Context) holderContext {
	return c.MustGet("holderContext").(holderContext)
}

func registerHolderRoutes(g *gin.RouterGroup, auth *holder.AuthorizationHandler, cfg *model.Config) {
	h := g.Group("/presentations")
	h.Use(requireHolderContext)
	h.POST("", func(c *gin.Context) {
		var input struct {
			URL         string `json:"url"`
			ConsentMode string `json:"consentMode"`
			TTL         int    `json:"ttl"`
		}
		if c.ShouldBindJSON(&input) != nil || input.ConsentMode != model.ConsentManual {
			c.JSON(400, gin.H{"error": "manual consent mode required"})
			return
		}
		if input.TTL == 0 {
			input.TTL = 3600
		}
		id := make([]byte, 16)
		if _, err := rand.Read(id); err != nil {
			c.JSON(500, gin.H{"error": "id generation failed"})
			return
		}
		processed, err := auth.IntakeLink(c.Request.Context(), input.URL, getHolderContext(c).TenantID, getHolderContext(c).GroupID, hex.EncodeToString(id), input.ConsentMode, input.TTL, cfg)
		if err != nil {
			c.JSON(400, gin.H{"error": err.Error()})
			return
		}
		c.JSON(201, gin.H{"presentationId": processed.State, "status": model.StatusPending})
	})
	h.GET("", func(c *gin.Context) {
		rows, err := svc.GetEntriesFromDb(c.Request.Context(), getHolderContext(c).TenantID, getHolderContext(c).GroupID)
		if err != nil {
			c.JSON(500, gin.H{"error": err.Error()})
			return
		}
		out := []gin.H{}
		for _, r := range rows {
			if r.ConsentMode == model.ConsentManual && r.State == model.StatusPending {
				state, err := svc.EncodeVerificationState(r.GroupId, r.RequestId)
				if err == nil {
					out = append(out, gin.H{"presentationId": state, "clientId": r.ClientId, "status": model.StatusPending})
				}
			}
		}
		c.JSON(200, gin.H{"presentations": out})
	})
	load := func(c *gin.Context) *model.VerificationEntry {
		row, err := svc.GetEntryFromDb(c.Request.Context(), getHolderContext(c).TenantID, c.Param("id"))
		if err != nil || row.GroupId != getHolderContext(c).GroupID || row.ConsentMode != model.ConsentManual {
			c.JSON(404, gin.H{"error": "presentation not found"})
			return nil
		}
		return row
	}
	h.GET("/:id", func(c *gin.Context) {
		row := load(c)
		if row != nil {
			c.JSON(200, row)
		}
	})
	h.GET("/:id/candidates", func(c *gin.Context) {
		row := load(c)
		if row == nil {
			return
		}
		if row.State != model.StatusPending {
			c.JSON(409, gin.H{"error": "request not pending"})
			return
		}
		groups, err := holder.GetCredentialCandidates(c.Request.Context(), cfg, row)
		if err != nil {
			c.JSON(422, gin.H{"error": err.Error()})
			return
		}
		c.JSON(200, gin.H{"dcqlQuery": row.DCQLQuery, "candidates": groups})
	})
	h.POST("/:id/reject", func(c *gin.Context) {
		row := load(c)
		if row == nil {
			return
		}
		ok, err := svc.TransitionPresentation(c.Request.Context(), row, model.StatusPending, model.StatusRejected)
		if err != nil {
			c.JSON(500, gin.H{"error": err.Error()})
			return
		}
		if !ok {
			c.JSON(409, gin.H{"error": "request no longer pending"})
			return
		}
		c.Status(204)
	})
	h.POST("/:id/approve", func(c *gin.Context) {
		row := load(c)
		if row == nil {
			return
		}
		var input struct {
			holder.PresentationSelection
			model.FulfillPresentationRequest
		}
		if err := c.ShouldBindJSON(&input); err != nil {
			c.JSON(400, gin.H{"error": err.Error()})
			return
		}
		// Key routing is fixed by the trusted gateway context, never by JSON payload.
		input.SignNamespace = getHolderContext(c).Namespace
		input.SignGroup = getHolderContext(c).Group
		if err := holder.FulfillSelected(c.Request.Context(), cfg, row, input.FulfillPresentationRequest, input.PresentationSelection); err != nil {
			c.JSON(422, gin.H{"error": err.Error()})
			return
		}
		c.JSON(200, gin.H{"status": model.StatusCompleted})
	})
	b := g.Group("/blocked-verifiers")
	b.Use(requireHolderContext)
	b.GET("", func(c *gin.Context) {
		ids, err := svc.ListBlockedVerifiers(c.Request.Context(), getHolderContext(c).TenantID, getHolderContext(c).GroupID)
		if err != nil {
			c.JSON(500, gin.H{"error": err.Error()})
			return
		}
		c.JSON(200, gin.H{"clientIds": ids})
	})
	b.POST("", func(c *gin.Context) {
		var input struct {
			ClientID string `json:"clientId"`
		}
		if c.ShouldBindJSON(&input) != nil || strings.TrimSpace(input.ClientID) == "" {
			c.Status(400)
			return
		}
		if err := svc.SetVerifierBlocked(c.Request.Context(), getHolderContext(c).TenantID, getHolderContext(c).GroupID, input.ClientID, true); err != nil {
			c.JSON(500, gin.H{"error": err.Error()})
			return
		}
		// Close existing pending manual requests from the newly blocked verifier.
		rows, err := svc.GetEntriesFromDb(c.Request.Context(), getHolderContext(c).TenantID, getHolderContext(c).GroupID)
		if err != nil {
			c.JSON(500, gin.H{"error": err.Error()})
			return
		}
		for i := range rows {
			row := &rows[i]
			if row.ClientId == input.ClientID && row.State == model.StatusPending {
				if _, err := svc.TransitionPresentation(c.Request.Context(), row, model.StatusPending, model.StatusBlocked); err != nil {
					c.JSON(500, gin.H{"error": err.Error()})
					return
				}
			}
		}
		c.Status(204)
	})
	b.DELETE("", func(c *gin.Context) {
		id := c.Query("clientId")
		if id == "" {
			c.Status(400)
			return
		}
		if err := svc.SetVerifierBlocked(c.Request.Context(), getHolderContext(c).TenantID, getHolderContext(c).GroupID, id, false); err != nil {
			c.JSON(500, gin.H{"error": err.Error()})
			return
		}
		c.Status(204)
	})
}
