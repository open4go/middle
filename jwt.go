package middle

import (
	"github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/gin"
	log "github.com/sirupsen/logrus"
	"net/http"
)

const (
	SignOutPath = "v1/auth/user/signout"
)

// JWTMiddleware 验证cookie并且将解析出来的账号
// 通过账号获取角色
// 通过角色判断其是否具有该api的访问权限
// 用户登陆完成后会将权限配置信息写入 redis 数据库完成
// 通过hget api/path/ role boolean
func JWTMiddleware(key []byte) gin.HandlerFunc {
	return func(c *gin.Context) {
		reqPath := c.FullPath()
		if SignOutPath == reqPath {
			if isLogin(c, key) {
				c.Next()
			} else {
				c.AbortWithStatus(http.StatusAlreadyReported)
			}
		} else {
			if isLogin(c, key) {
				c.Next()
			} else {
				c.AbortWithStatus(http.StatusForbidden)
			}
		}
	}
}

func isLogin(c *gin.Context, key []byte) bool {
	cookie, err := c.Cookie("jwt")
	if cookie == "" {
		log.Error("cookie name as jwt no found")
		return false
	}

	token, err := jwt.ParseWithClaims(cookie, &jwt.StandardClaims{}, func(token *jwt.Token) (interface{}, error) {
		return key, nil
	})

	if err != nil {
		log.WithField("message", "parse claims failed").Error(err)
		return false
	}

	claims := token.Claims.(*jwt.StandardClaims)
	l := &LoginInfo{}
	err = l.Load(claims.Issuer)
	if err != nil {
		log.WithField("message", "LoadLoginInfo failed").Error(err)
		return false
	}
	// 写入解析客户的jwt token后得到的数据
	l.WriteIntoHeader(c)
	return true
}
