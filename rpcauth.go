package middle

import (
	"context"
	"crypto/subtle"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/open4go/log"
	"github.com/spf13/viper"
)

// 服务间（/rpc）调用鉴权。
//
// 配置项：
//
//	rpc.auth_token                    服务间共享令牌（所有服务配置同一个值）；兼容旧配置 rpc.token
//	middle.rpc.allowUnauthenticated   true 时缺少或错误令牌的请求仍放行（只记告警），仅用于灰度切换窗口，默认 false
//
// 调用方在请求头 X-Internal-Token 中携带令牌（gRPC 使用 metadata x-internal-token）。
// open4go/util9s 的 Get / Post 对 /rpc/ 路径会自动携带；自行构造请求时请调用 SetInternalToken。
const (
	InternalTokenHeader   = "X-Internal-Token"
	InternalTokenMetadata = "x-internal-token"

	cfgRPCAuthToken   = "rpc.auth_token"
	cfgRPCLegacyToken = "rpc.token"
	cfgRPCAllowUnauth = "middle.rpc.allowUnauthenticated"
)

// InternalToken 返回本服务配置的服务间令牌（rpc.auth_token，未配置时回退 rpc.token）。
func InternalToken() string {
	if t := strings.TrimSpace(viper.GetString(cfgRPCAuthToken)); t != "" {
		return t
	}
	return strings.TrimSpace(viper.GetString(cfgRPCLegacyToken))
}

// ValidInternalToken 用常量时间比较校验令牌；本服务未配置令牌时一律返回 false。
func ValidInternalToken(got string) bool {
	want := InternalToken()
	got = strings.TrimSpace(got)
	if want == "" || got == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(want), []byte(got)) == 1
}

// SetInternalToken 为发往其他服务 /rpc 接口的请求加上令牌头（未配置令牌时不做任何事）。
func SetInternalToken(req *http.Request) {
	if req == nil {
		return
	}
	if t := InternalToken(); t != "" {
		req.Header.Set(InternalTokenHeader, t)
	}
}

func rpcAllowUnauthenticated() bool {
	return viper.GetBool(cfgRPCAllowUnauth)
}

// RPCAuthMiddleware 校验服务间令牌，失败返回 401。默认安全：未配置令牌时拒绝所有请求。
// 兼容旧调用方：令牌也可以放在 Token 请求头中。
func RPCAuthMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		got := c.GetHeader(InternalTokenHeader)
		if got == "" {
			got = c.GetHeader("Token")
		}
		if ValidInternalToken(got) {
			c.Next()
			return
		}
		if rpcAllowUnauthenticated() {
			log.Log(c.Request.Context()).
				WithField("path", c.FullPath()).
				Warning("rpc request without valid internal token allowed by middle.rpc.allowUnauthenticated")
			c.Next()
			return
		}
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
	}
}

// RPCAuthConfigured 启动时调用：未配置令牌时返回 false（同时记录错误日志），便于服务决定是否退出。
func RPCAuthConfigured() bool {
	if InternalToken() != "" {
		return true
	}
	if rpcAllowUnauthenticated() {
		log.Log(context.Background()).Warning("rpc.auth_token is empty and middle.rpc.allowUnauthenticated=true: /rpc accepts every caller")
	} else {
		log.Log(context.Background()).Error("rpc.auth_token is empty: every /rpc request will be rejected")
	}
	return false
}
