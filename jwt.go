package middle

import (
	"errors"
	"fmt"
	"github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/gin"
	"github.com/open4go/log"
	"github.com/pquerna/otp/totp"
	"net/http"
)

const (
	SignOutPath = "v1/system/auth/signout"
)

// JWTMiddleware 验证cookie并且将解析出来的账号
// 通过账号获取角色
// 通过角色判断其是否具有该api的访问权限
// 用户登陆完成后会将权限配置信息写入 redis 数据库完成
// 通过hget api/path/ role boolean
func JWTMiddleware(key []byte) gin.HandlerFunc {
	return func(c *gin.Context) {
		reqPath := c.FullPath()
		if reqPath == SignOutPath {
			if checkAuth(c, key) != http.StatusOK {
				c.AbortWithStatus(http.StatusForbidden)
				return
			}
		} else {
			if checkAuth(c, key) != http.StatusOK {
				c.AbortWithStatus(http.StatusForbidden)
				return
			}
		}
		c.Next()
	}
}

func checkAuth(c *gin.Context, key []byte) int {
	// Retrieve JWT token from the "jwt" cookie
	cookie, err := c.Cookie("jwt")
	if err != nil || cookie == "" {
		log.Log(c.Request.Context()).
			WithError(err).Error("Failed to retrieve JWT token from cookie")
		c.AbortWithStatus(http.StatusUnauthorized)
		return http.StatusUnauthorized
	}

	// Parse JWT token with claims
	token, err := parseJWTToken(cookie, key)
	if err != nil {
		log.Log(c.Request.Context()).WithError(err).Error("Failed to parse JWT token")
		c.AbortWithStatus(http.StatusUnauthorized)
		return http.StatusUnauthorized
	}

	// Extract claims and load them into LoginInfo struct
	loginInfo, err := extractClaims(token)
	if err != nil {
		log.Log(c.Request.Context()).WithError(err).Error("Failed to extract claims")
		c.AbortWithStatus(http.StatusUnauthorized)
		return http.StatusUnauthorized
	}

	// Write parsed data into the header
	loginInfo.WriteIntoHeader(c)

	return http.StatusOK
}

func parseJWTToken(cookie string, key []byte) (*jwt.Token, error) {
	return jwt.ParseWithClaims(cookie, &jwt.StandardClaims{}, func(token *jwt.Token) (interface{}, error) {
		return key, nil
	})
}

func extractClaims(token *jwt.Token) (*LoginInfo, error) {
	claims, ok := token.Claims.(*jwt.StandardClaims)
	if !ok {
		return nil, errors.New("invalid token claims")
	}

	// Load claims into LoginInfo struct
	loginInfo := &LoginInfo{}
	if err := loginInfo.Load(claims.Issuer); err != nil {
		return nil, fmt.Errorf("failed to load claims into LoginInfo: %w", err)
	}

	return loginInfo, nil
}

// MerchantBindMiddleware 仅绑定商户信息，不校验登陆权限信息
func MerchantBindMiddleware(key []byte) gin.HandlerFunc {
	return func(c *gin.Context) {
		bindMerchant(c)
		c.Next()
	}
}

func bindMerchant(c *gin.Context) int {
	// Extract claims and load them into LoginInfo struct
	loginInfo := LoadFromHeader(c)
	// Write parsed data into the header
	loginInfo.WriteIntoHeader(c)
	return http.StatusOK
}

func SecondValidateMiddleware(key []byte) gin.HandlerFunc {
	return func(c *gin.Context) {

		// 1. 获取 TOTP code（支持 Body + Header）
		code := getTOTPCode(c)

		if code == "" {
			c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{
				"error": "缺少 TOTP 验证码 (code)",
			})
			return
		}

		// Retrieve JWT token from the "jwt" cookie
		cookie, err := c.Cookie("jwt")
		if err != nil || cookie == "" {
			log.Log(c.Request.Context()).
				WithError(err).Error("Failed to retrieve JWT token from cookie")
			c.AbortWithStatus(http.StatusUnauthorized)
			return
		}

		// Parse JWT token with claims
		token, err := parseJWTToken(cookie, key)
		if err != nil {
			log.Log(c.Request.Context()).WithError(err).Error("Failed to parse JWT token")
			c.AbortWithStatus(http.StatusUnauthorized)
			return
		}

		// Extract claims and load them into LoginInfo struct
		loginInfo, err := extractClaims(token)
		if err != nil {
			log.Log(c.Request.Context()).WithError(err).Error("Failed to extract claims")
			c.AbortWithStatus(http.StatusUnauthorized)
			return
		}

		// 二次验证
		totp.Validate(code, loginInfo.OPTSecret)

		c.Next()

	}
}

// 辅助函数：支持从 Body 和 Header 获取 code
func getTOTPCode(c *gin.Context) string {
	// 优先从 Header 获取
	if code := c.GetHeader("X-TOTP-Code"); code != "" {
		return code
	}

	// 最后尝试 Query 参数
	return c.Query("code")
}
