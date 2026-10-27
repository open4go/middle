package middle

import (
	"context"
	"fmt"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/open4go/log"
	"github.com/open4go/model"
	"net/http"
	"strings"
)

// JWTAuthMiddleware 是一个 Gin 中间件，用于验证 JWT token
// 用户于客户端app/api验证
func JWTAuthMiddleware(jwtSecret []byte) gin.HandlerFunc {
	return func(c *gin.Context) {
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			log.Log(c.Request.Context()).Debug("authorization header is required")
			c.JSON(http.StatusUnauthorized, gin.H{"error": "authorization header is required"})
			c.Abort()
			return
		}

		parts := strings.SplitN(authHeader, " ", 2)
		if len(parts) != 2 || parts[0] != "Bearer" {
			log.Log(c.Request.Context()).Warn("authorization header is not a Bearer token")
			c.JSON(http.StatusUnauthorized, gin.H{"error": "authorization header format must be Bearer {token}"})
			c.Abort()
			return
		}

		tokenString := parts[1]

		token, claims, err := parseToken(tokenString, jwtSecret)
		if err != nil || !token.Valid {
			// invalid token
			log.Log(c.Request.Context()).WithError(err).Warn("invalid bearer token")
			c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid token"})
			c.Abort()
			return
		}

		// 将 claims 保存到上下文
		//c.Set("claims", claims)

		accountId, ok := claims["sub"].(string)
		if !ok || accountId == "" {
			log.Log(c.Request.Context()).Warn("accountId not found in bearer token")
			c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid token subject"})
			c.Abort()
			return
		}
		c.Set("accountId", accountId)

		iss, ok := claims["iss"].(string)
		if !ok {
			log.Log(c.Request.Context()).Warn("iss not found in bearer token")
			c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid token subject"})
			c.Abort()
			return
		}
		c.Set("iss", iss)

		aud, ok := claims["aud"].(string)
		if !ok {
			log.Log(c.Request.Context()).Warn("aud not found in bearer token")
			c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid token subject"})
			c.Abort()
			return
		}
		c.Set("aud", aud)

		jti, ok := claims["jti"].(string)
		if !ok {
			log.Log(c.Request.Context()).Warn("jti not found in bearer token")
			c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid token subject"})
			c.Abort()
			return
		}
		c.Set("jti", jti)
		tenantId := ""
		if mid, ok := claims["mid"].(string); ok {
			tenantId = strings.TrimSpace(mid)
		}
		if tenantId == "*" {
			tenantId = ""
		}
		headerMid := strings.TrimSpace(c.Request.Header.Get("X-Tenant-ID"))
		if headerMid == "*" {
			headerMid = ""
		}
		if tenantId != "" && headerMid != "" && tenantId != headerMid {
			c.JSON(http.StatusForbidden, gin.H{"error": "tenant mismatch"})
			c.Abort()
			return
		}
		if tenantId == "" && headerMid != "" {
			if trustTenantHeader(c) {
				tenantId = headerMid
			} else {
				log.Log(c.Request.Context()).Warn("tenant header ignored: request not from gateway")
				c.Request.Header.Del("X-Tenant-ID")
			}
		}
		if tenantId != "" {
			c.Request.Header.Set("X-Tenant-ID", tenantId)
		}
		c.Request.Header.Del("X-Merchant-ID")
		ctx := context.WithValue(c.Request.Context(), model.MerchantKey, tenantId) //nolint:staticcheck // SA1029: key type is fixed by open4go/model
		ctx = context.WithValue(ctx, model.AccountKey, accountId)                  //nolint:staticcheck // SA1029: key type is fixed by open4go/model
		c.Request = c.Request.WithContext(ctx)
		c.Next()
	}
}

// 解析 JWT token
func parseToken(tokenString string, jwtSecret []byte) (*jwt.Token, jwt.MapClaims, error) {
	claims := jwt.MapClaims{}

	token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return jwtSecret, nil
	}, jwt.WithValidMethods(hmacMethods))

	return token, claims, err
}
