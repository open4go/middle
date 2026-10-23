package middle

import (
	"crypto/subtle"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/spf13/viper"
)

// 网关来源校验。
//
// 当登录令牌中没有商户号时，才会采用请求头 X-Tenant-ID 作为商户；
// 该请求头只有在请求证明自己来自网关（携带正确的 X-Gateway-Token）时才被采信。
//
// 配置项：
//
//	middle.gateway.token                    网关与后端共享的令牌（由网关在转发时注入 X-Gateway-Token）
//	middle.gateway.allowUnverifiedTenant    true 时未携带/未配置令牌也采信 X-Tenant-ID（旧行为），
//	                                        仅用于灰度切换窗口，默认 false
//
// 令牌只做常量时间比较，绝不写入日志。
const (
	GatewayTokenHeader = "X-Gateway-Token"

	cfgGatewayToken           = "middle.gateway.token"
	cfgGatewayAllowUnverified = "middle.gateway.allowUnverifiedTenant"
)

// GatewayToken 返回本服务配置的网关令牌（未配置时为空）。
func GatewayToken() string {
	return strings.TrimSpace(viper.GetString(cfgGatewayToken))
}

// ValidGatewayToken 用常量时间比较校验网关令牌；未配置令牌时一律返回 false。
func ValidGatewayToken(got string) bool {
	want := GatewayToken()
	got = strings.TrimSpace(got)
	if want == "" || got == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(want), []byte(got)) == 1
}

// FromGateway 报告当前请求是否携带了正确的网关令牌。
func FromGateway(c *gin.Context) bool {
	if c == nil || c.Request == nil {
		return false
	}
	return ValidGatewayToken(c.Request.Header.Get(GatewayTokenHeader))
}

// trustTenantHeader 报告在登录令牌没有商户号时，是否可以采信请求头中的 X-Tenant-ID。
func trustTenantHeader(c *gin.Context) bool {
	if FromGateway(c) {
		return true
	}
	return viper.GetBool(cfgGatewayAllowUnverified)
}

// SetGatewayToken 为服务间直连请求加上网关令牌头（未配置令牌时不做任何事）。
func SetGatewayToken(req *http.Request) {
	if req == nil {
		return
	}
	if t := GatewayToken(); t != "" {
		req.Header.Set(GatewayTokenHeader, t)
	}
}
