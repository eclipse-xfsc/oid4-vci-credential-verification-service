package middleware

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"os"
	"strings"
 "sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/lestrrat-go/jwx/v2/jwk"
)

// ProfileAdminJWT protects only the profile management routes.
// Without a JWKS URL the middleware is disabled; restrict network access in that mode.
// Claims tenant_id and group_id must exactly match the request context.
func ProfileAdminJWT() gin.HandlerFunc {
	jwksURL := strings.TrimSpace(os.Getenv("CREDENTIALVERIFICATION_PROFILE_ADMIN_JWKS_URL"))
	issuer := strings.TrimSpace(os.Getenv("CREDENTIALVERIFICATION_PROFILE_ADMIN_ISSUER"))
	audience := strings.TrimSpace(os.Getenv("CREDENTIALVERIFICATION_PROFILE_ADMIN_AUDIENCE"))
	if jwksURL == "" {
		return func(c *gin.Context) { c.Next() }
	}
	u, err := url.Parse(jwksURL)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.Fragment != "" {
		panic("PROFILE_ADMIN_JWKS_URL must be a valid HTTPS URL")
	}
	client := &http.Client{Timeout: 4 * time.Second}
 var mu sync.Mutex
 var cached jwk.Set
 var expires time.Time
 requiredScope := strings.TrimSpace(os.Getenv("CREDENTIALVERIFICATION_PROFILE_ADMIN_SCOPE"))
 if requiredScope == "" { requiredScope = "presentation-profiles:write" }
	return func(c *gin.Context) {
		header := c.GetHeader("Authorization")
		if !strings.HasPrefix(header, "Bearer ") || strings.TrimSpace(strings.TrimPrefix(header, "Bearer ")) == "" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "bearer token required"})
			return
		}
		raw := strings.TrimSpace(strings.TrimPrefix(header, "Bearer "))
		ctx, cancel := context.WithTimeout(c.Request.Context(), 4*time.Second)
		defer cancel()
		mu.Lock()
 keys := cached
 var err error
 if keys == nil || time.Now().After(expires) {
   keys, err = jwk.Fetch(ctx, jwksURL, jwk.WithHTTPClient(client))
   if err == nil { cached = keys; expires = time.Now().Add(5 * time.Minute) }
 }
 mu.Unlock()
		if err != nil {
			c.AbortWithStatusJSON(http.StatusServiceUnavailable, gin.H{"error": "JWKS unavailable"})
			return
		}
		options := []jwt.ParserOption{jwt.WithValidMethods([]string{"RS256", "RS384", "RS512", "ES256", "ES384", "ES512", "EdDSA"}), jwt.WithExpirationRequired(), jwt.WithIssuedAt()}
		if issuer != "" {
			options = append(options, jwt.WithIssuer(issuer))
		}
		if audience != "" {
			options = append(options, jwt.WithAudience(audience))
		}
		claims := jwt.MapClaims{}
		token, err := jwt.NewParser(options...).ParseWithClaims(raw, claims, func(t *jwt.Token) (interface{}, error) {
			kid, ok := t.Header["kid"].(string)
			if !ok || kid == "" {
				return nil, errors.New("kid required")
			}
			key, ok := keys.LookupKeyID(kid)
			if !ok {
				return nil, errors.New("unknown kid")
			}
			var publicKey interface{}
			if err := key.Raw(&publicKey); err != nil {
				return nil, err
			}
			return publicKey, nil
		})
		if err != nil || token == nil || !token.Valid {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "invalid access token"})
			return
		}
		tenant := c.Param("tenantId")
		group := c.GetHeader("x-groupid")
		tokenTenant, okTenant := claims["tenant_id"].(string)
		tokenGroup, okGroup := claims["group_id"].(string)
		if tenant == "" || group == "" || !okTenant || !okGroup || tokenTenant != tenant || tokenGroup != group {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "tenant or group mismatch"})
			return
		}
		if !hasProfileAdminScope(claims, requiredScope) {
 c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error":"required profile administration scope missing"})
 return
 }
		c.Next()
	}
}

// hasProfileAdminScope accepts OAuth scope strings or scp arrays.
func hasProfileAdminScope(claims jwt.MapClaims, required string) bool {
 if required == "" { return false }
 if scope, ok := claims["scope"].(string); ok {
  for _, value := range strings.Fields(scope) { if value == required { return true } }
 }
 if scopes, ok := claims["scp"].([]interface{}); ok {
  for _, value := range scopes { if value == required { return true } }
 }
 if scopes, ok := claims["scp"].([]string); ok {
  for _, value := range scopes { if value == required { return true } }
 }
 return false
}
