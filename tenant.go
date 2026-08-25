package middle

import (
	"net"
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

// isSuperAdminHost reports whether host is the configured super-admin console.
// An empty super.domain is never a match: strings.HasPrefix(host, "") is true
// for every host, which previously disabled tenant isolation on services that
// do not set the key (e.g. product-api).
func isSuperAdminHost(host string) bool {
	super := strings.TrimSpace(viper.GetString("super.domain"))
	if super == "" {
		return false
	}
	return hostnameOnly(host) == hostnameOnly(super)
}

// skipTenantFallback is true only on the super-admin host when the caller
// explicitly switches merchant via X-Merchant-ID (including "*").
// Unswitched super-admin and every tenant host keep JWT merchant isolation.
func skipTenantFallback(c *gin.Context) bool {
	if c == nil || c.Request == nil {
		return false
	}
	if !isSuperAdminHost(c.Request.Host) {
		return false
	}
	return strings.TrimSpace(c.GetHeader("X-Merchant-ID")) != ""
}
