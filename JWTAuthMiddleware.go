package middle

import (
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
			log.Log().Error("authorization header is required")
			c.JSON(http.StatusUnauthorized, gin.H{"error": "authorization header is required"})
			c.Abort()
			return
		}

		parts := strings.SplitN(authHeader, " ", 2)
		if len(parts) != 2 || parts[0] != "Bearer" {
			log.Log().WithField("authHeader", authHeader).
				Error("authorization header is required")
			c.JSON(http.StatusUnauthorized, gin.H{"error": "authorization header format must be Bearer {token}"})
			c.Abort()
			return
		}

		tokenString := parts[1]

		token, claims, err := parseToken(tokenString, jwtSecret)
		if err != nil || !token.Valid {
			log.Log().WithField("authHeader", authHeader).
				WithField("token", token).
				Error("authorization header is required")
			c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid token"})
			c.Abort()
			return
		}

		// 将 claims 保存到上下文
		c.Set("claims", claims)
		c.Next()
	}
}

// 解析 JWT token
func parseToken(tokenString string, jwtSecret []byte) (*jwt.Token, *jwt.StandardClaims, error) {
	claims := &jwt.StandardClaims{}

	token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
		return jwtSecret, nil
	})
	return token, claims, err
}
