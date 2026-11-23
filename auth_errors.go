package middle

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

// 统一的鉴权失败响应。前端约定：
//   - 401 code=session_expired：登录态失效（未登录、token 无效/过期、身份缺失），清本地登录态并回登录页；
//   - 403 code=permission_denied：已登录但没有该接口权限，只提示，不登出、不离开站点；
//   - 503 code=permission_unavailable：权限数据暂时读不到，可重试，不登出。
const (
	CodeSessionExpired        = "session_expired"
	CodePermissionDenied      = "permission_denied"
	CodePermissionUnavailable = "permission_unavailable"

	MsgSessionExpired        = "登录已过期，请重新登录"
	MsgPermissionDenied      = "没有访问该功能的权限"
	MsgPermissionUnavailable = "权限服务暂不可用，请稍后重试"
)

// AbortSessionExpired 返回 401 {code:"session_expired"}。
func AbortSessionExpired(c *gin.Context) {
	c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
		"code":    CodeSessionExpired,
		"message": MsgSessionExpired,
	})
}

// AbortPermissionDenied 返回 403 {code:"permission_denied"}。
func AbortPermissionDenied(c *gin.Context) {
	c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
		"code":    CodePermissionDenied,
		"message": MsgPermissionDenied,
	})
}

// AbortPermissionUnavailable 返回 503 {code:"permission_unavailable"}。
func AbortPermissionUnavailable(c *gin.Context) {
	c.AbortWithStatusJSON(http.StatusServiceUnavailable, gin.H{
		"code":    CodePermissionUnavailable,
		"message": MsgPermissionUnavailable,
	})
}
