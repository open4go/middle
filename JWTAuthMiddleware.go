package middle

import (
	"fmt"
	"github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/gin"
	"github.com/open4go/log"
	"net/http"
	"strings"
)

// JWTAuthMiddleware 是一个 Gin 中间件，用于验证 JWT token
// 用户于客户端app/api验证
func JWTAuthMiddleware(jwtSecret []byte) gin.HandlerFunc {
	return func(c *gin.Context) {
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			log.Log(c.Request.Context()).Error("authorization header is required")
			c.JSON(http.StatusUnauthorized, gin.H{"error": "authorization header is required"})
			c.Abort()
			return
		}

		parts := strings.SplitN(authHeader, " ", 2)
		if len(parts) != 2 || parts[0] != "Bearer" {
			log.Log(c.Request.Context()).WithField("authHeader", authHeader).
				Error("authorization header is required")
			c.JSON(http.StatusUnauthorized, gin.H{"error": "authorization header format must be Bearer {token}"})
			c.Abort()
			return
		}

		tokenString := parts[1]

		token, claims, err := parseToken(tokenString, jwtSecret)
		if err != nil || !token.Valid {
			// invalid token
			log.Log(c.Request.Context()).WithField("authHeader", authHeader).
				Error("invalid token")
			c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid token"})
			c.Abort()
			return
		}

		// 将 claims 保存到上下文
		c.Set("claims", claims)

		accountId, ok := claims["sub"].(string)
		if !ok || accountId == "" {
			log.Log(c.Request.Context()).Error("accountId not found")
			c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid token subject"})
			c.Abort()
			return
		}
		c.Set("accountId", accountId)

		iss, ok := claims["iss"].(string)
		if !ok {
			log.Log(c.Request.Context()).Error("iss not found")
			c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid token subject"})
			c.Abort()
			return
		}
		c.Set("iss", iss)

		aud, ok := claims["aud"].(string)
		if !ok {
			log.Log(c.Request.Context()).Error("aud not found")
			c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid token subject"})
			c.Abort()
			return
		}
		c.Set("aud", aud)

		jti, ok := claims["jti"].(string)
		if !ok {
			log.Log(c.Request.Context()).Error("jti not found")
			c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid token subject"})
			c.Abort()
			return
		}
		c.Set("jti", jti)

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
	})

	return token, claims, err
}
