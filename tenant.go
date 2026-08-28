package middle

import (
	"net"
	"net/url"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/spf13/viper"
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

// requestAdminHost prefers the original browser host. APISIX / docker often
// overwrite Request.Host with the upstream name, which would hide super mode.
func requestAdminHost(c *gin.Context) string {
	if c == nil || c.Request == nil {
		return ""
	}
	if v := strings.TrimSpace(c.GetHeader("X-Forwarded-Host")); v != "" {
		return strings.TrimSpace(strings.Split(v, ",")[0])
	}
	if origin := strings.TrimSpace(c.GetHeader("Origin")); origin != "" {
		if u, err := url.Parse(origin); err == nil && u.Host != "" {
			return u.Host
		}
	}
	return c.Request.Host
}

// isSuperAdminHost reports whether host is the super-admin console.
// An empty super.domain never matches ordinary hosts (product-api, admin.localhost).
// super.localhost is the local default even when a service omits super.domain.
func isSuperAdminHost(host string) bool {
	h := hostnameOnly(host)
	if h == "" {
		return false
	}
	super := hostnameOnly(viper.GetString("super.domain"))
	if super != "" && h == super {
		return true
	}
	return h == "super.localhost"
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
func skipTenantFallback(c *gin.Context) bool {
	if c == nil || c.Request == nil {
		return false
	}
	if !isSuperAdminHost(requestAdminHost(c)) {
		return false
	}
	return switchedMerchantID(c) != ""
}
