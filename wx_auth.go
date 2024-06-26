package middle

import (
	"github.com/gin-gonic/gin"
	"github.com/open4go/log"
	"net/http"
)

// WxLoginSessionTokenKeyPrefix 微信登陆token
const (
	WxLoginSessionTokenKeyPrefix = "wx_tokens_"
)

var (
	WxLoginFields = []string{
		"OPEN_ID",
		"ACCOUNT_ID",
		"UNION_ID",
		"SESSION_KEY",
	}
)

// VerifyTokenMiddleware 微信登陆token校验
func VerifyTokenMiddleware(key []byte) gin.HandlerFunc {
	return func(c *gin.Context) {
		token := c.Request.Header.Get("token")
		hashParentKey := WxLoginSessionTokenKeyPrefix + token
		for _, subKey := range WxLoginFields {
			err := readCacheByToken(c, hashParentKey, subKey)
			if err != nil {
				log.Log(c.Request.Context()).WithField("subKey", subKey).Error(err)
				c.AbortWithStatus(http.StatusForbidden)
				return
			}
		}
		c.Next()
	}
}

func readCacheByToken(c *gin.Context, tokenKeyName string, subKey string) error {
	value, err := GetRedisMiddleHandler(c.Request.Context()).HGet(c.Request.Context(), tokenKeyName, subKey).Result()
	if err != nil {
		log.Log(c.Request.Context()).WithField("subKey", subKey).Error(err)
		return err
	}
	if value == "" {
		log.Log(c.Request.Context()).WithField("subKey", subKey).
			WithField("value", value).Error(err)
		return err
	}
	c.Request.Header.Set(subKey, value)
	return nil
}
