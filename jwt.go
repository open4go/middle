package middle

import (
	"context"
	"errors"
	"fmt"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/open4go/log"
	"github.com/pquerna/otp/totp"
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
		if checkAuth(c, key) != http.StatusOK {
			// checkAuth 已经 Abort 并写入 401，这里不再重复写状态码
			return
		}
		c.Next()
	}
}

// VerifiedUserIDKey 是 JWTMiddleware 校验 token 成功后写入 gin.Context（c.Set）与
// request context 的键，值为 token 中的 UserID。下游（如 open4go/auth）应以此作为调用者身份，
// 而不是读取可被客户端伪造的请求头。
const VerifiedUserIDKey = "OPEN4GO_VERIFIED_USER_ID"

// VerifiedUserID 返回 JWTMiddleware 校验后的 UserID；未经校验时返回 ""。
func VerifiedUserID(c *gin.Context) string {
	if c == nil {
		return ""
	}
	if v, ok := c.Get(VerifiedUserIDKey); ok {
		if s, ok := v.(string); ok {
			return s
		}
	}
	if c.Request != nil {
		if s, ok := c.Request.Context().Value(VerifiedUserIDKey).(string); ok {
			return s
		}
	}
	return ""
}

func setVerifiedUserID(c *gin.Context, uid string) {
	c.Set(VerifiedUserIDKey, uid)
	//nolint:staticcheck // 与 open4go/model 的字符串 context key 约定保持一致
	c.Request = c.Request.WithContext(context.WithValue(c.Request.Context(), VerifiedUserIDKey, uid))
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
	setVerifiedUserID(c, loginInfo.UserID)

	return http.StatusOK
}

var hmacMethods = []string{
	jwt.SigningMethodHS256.Alg(),
	jwt.SigningMethodHS384.Alg(),
	jwt.SigningMethodHS512.Alg(),
}

func parseJWTToken(cookie string, key []byte) (*jwt.Token, error) {
	if len(key) == 0 {
		return nil, errors.New("jwt: empty signing key")
	}
	return jwt.ParseWithClaims(cookie, &jwt.RegisteredClaims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return key, nil
	}, jwt.WithValidMethods(hmacMethods))
}

func extractClaims(token *jwt.Token) (*LoginInfo, error) {
	if token == nil || !token.Valid {
		return nil, errors.New("invalid token")
	}
	claims, ok := token.Claims.(*jwt.RegisteredClaims)
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

		// 二次验证：密钥从服务端获取，不再信任 token 内容
		issuer := ""
		if rc, ok := token.Claims.(*jwt.RegisteredClaims); ok {
			issuer = rc.Issuer
		}
		secret, err := resolveOTPSecret(c.Request.Context(), loginInfo, issuer)
		if err != nil || secret == "" {
			log.Log(c.Request.Context()).WithError(err).Error("otp secret unavailable")
			c.AbortWithStatus(http.StatusForbidden)
			return
		}
		if !totp.Validate(code, secret) {
			log.Log(c.Request.Context()).Error("failed to validate totp code")
			c.AbortWithStatus(http.StatusForbidden)
			return
		}
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
