package middle

import (
	"net"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/spf13/viper"
)

// 配置项（均默认关闭 / 为空，即默认最安全）：
//
//	super.domain             超管控制台域名（精确匹配，忽略端口与大小写）
//	super.allowLocalhost     true 时额外把 super.localhost 视为超管域名，仅用于本地开发
//	super.merchants          允许在超管域名下切换商户（X-Merchant-ID）的登录商户号列表
//	super.merchant           同上，单个商户号（兼容现有配置）
//	middle.trustedProxies    受信任的反向代理 IP / CIDR 列表；只有直连对端在列表内时才采用 X-Forwarded-Host
const (
	cfgSuperDomain         = "super.domain"
	cfgSuperAllowLocalhost = "super.allowLocalhost"
	cfgSuperMerchants      = "super.merchants"
	cfgSuperMerchant       = "super.merchant"
	cfgTrustedProxies      = "middle.trustedProxies"

	localSuperHost = "super.localhost"
)

// hostnameOnly strips a trailing :port (including [ipv6]:port) and lowercases.
func hostnameOnly(host string) string {
	host = strings.TrimSpace(host)
	if host == "" {
		return ""
	}
	h, _, err := net.SplitHostPort(host)
	if err != nil {
		return strings.ToLower(host)
	}
	return strings.ToLower(h)
}

// isTrustedProxy reports whether the direct peer of this request is listed in
// middle.trustedProxies (plain IPs or CIDRs).
func isTrustedProxy(c *gin.Context) bool {
	if c == nil || c.Request == nil {
		return false
	}
	entries := viper.GetStringSlice(cfgTrustedProxies)
	if len(entries) == 0 {
		return false
	}
	host, _, err := net.SplitHostPort(strings.TrimSpace(c.Request.RemoteAddr))
	if err != nil {
		host = strings.TrimSpace(c.Request.RemoteAddr)
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}
	for _, e := range entries {
		e = strings.TrimSpace(e)
		if e == "" {
			continue
		}
		if strings.Contains(e, "/") {
			if _, n, err := net.ParseCIDR(e); err == nil && n.Contains(ip) {
				return true
			}
			continue
		}
		if p := net.ParseIP(e); p != nil && p.Equal(ip) {
			return true
		}
	}
	return false
}

// requestAdminHost returns the host used for admin-console detection.
// X-Forwarded-Host is only honoured when the request comes from a configured
// trusted proxy (middle.trustedProxies); otherwise Request.Host is used.
// The Origin header is never used.
func requestAdminHost(c *gin.Context) string {
	if c == nil || c.Request == nil {
		return ""
	}
	if isTrustedProxy(c) {
		if v := strings.TrimSpace(c.GetHeader("X-Forwarded-Host")); v != "" {
			return strings.TrimSpace(strings.Split(v, ",")[0])
		}
	}
	return c.Request.Host
}

// isSuperAdminHost reports whether host is the super-admin console.
// An empty super.domain never matches. super.localhost only matches when
// super.allowLocalhost is explicitly enabled (local development).
func isSuperAdminHost(host string) bool {
	h := hostnameOnly(host)
	if h == "" {
		return false
	}
	super := hostnameOnly(viper.GetString(cfgSuperDomain))
	if super != "" && h == super {
		return true
	}
	return viper.GetBool(cfgSuperAllowLocalhost) && h == localSuperHost
}

// canSwitchMerchant reports whether this login may switch merchant on the
// super-admin host: the token must be marked SuperAdmin, or its merchant must
// be listed in super.merchants.
func canSwitchMerchant(l *LoginInfo) bool {
	if l == nil {
		return false
	}
	if l.SuperAdmin {
		return true
	}
	mid := strings.TrimSpace(l.MerchantID)
	if mid == "" {
		return false
	}
	if m := strings.TrimSpace(viper.GetString(cfgSuperMerchant)); m != "" && m == mid {
		return true
	}
	for _, m := range viper.GetStringSlice(cfgSuperMerchants) {
		if strings.TrimSpace(m) == mid {
			return true
		}
	}
	return false
}

func switchedMerchantID(c *gin.Context) string {
	if c == nil {
		return ""
	}
	return strings.TrimSpace(c.GetHeader("X-Merchant-ID"))
}

// skipTenantFallback is true only on the super-admin host when the caller
// explicitly switches merchant via X-Merchant-ID (including "*").
// Unswitched super-admin and every tenant host keep JWT merchant isolation.
// Callers must additionally check canSwitchMerchant for the verified login.
func skipTenantFallback(c *gin.Context) bool {
	if c == nil || c.Request == nil {
		return false
	}
	if !isSuperAdminHost(requestAdminHost(c)) {
		return false
	}
	return switchedMerchantID(c) != ""
}
