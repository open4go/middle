package middle

import (
	"github.com/gin-gonic/gin"
	"github.com/open4go/auth"
	"net/http"
)

// AccessMiddleware 验证cookie并且将解析出来的账号
// 通过账号获取角色
// 通过角色判断其是否具有该api的访问权限
// 用户登陆完成后会将权限配置信息写入 redis 数据库完成
// 通过hget api/path/ role boolean
func AccessMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		accountId := c.GetHeader("AccountID")
		sa := auth.NewRBAM()
		sa.BindKey(accountId)
		statusCode := sa.Verify(c.Request.Context(), c.FullPath(), c.Request.Method)
		if statusCode != http.StatusOK {
			c.AbortWithStatus(statusCode)
			return
		}
		c.Next()
	}
}
