package middle

import (
	"net/netip"
	"strings"
	"sync"

	"github.com/gin-gonic/gin"
)

// 来源 IP 与中文归属地。
//
// 链路是 Cloudflare → nginx → APISIX → 服务。nginx 已按 Cloudflare 网段还原真实 IP 并写入 X-Real-IP；
// 这里再加一层兜底：如果 X-Real-IP 本身是 Cloudflare 边缘节点（例如 IPv6 访客没被 nginx 还原），
// 且带了 CF-Connecting-IP，就用 CF-Connecting-IP。只有对端确实是 Cloudflare 网段时才信这个头，
// 直连源站的请求伪造 CF-Connecting-IP 不会生效。

var cloudflareCIDRs = mustPrefixes(
	// https://www.cloudflare.com/ips/ （IPv4）
	"173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22",
	"141.101.64.0/18", "108.162.192.0/18", "190.93.240.0/20", "188.114.96.0/20",
	"197.234.240.0/22", "198.41.128.0/17", "162.158.0.0/15", "104.16.0.0/13",
	"104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22",
	// IPv6
	"2400:cb00::/32", "2606:4700::/32", "2803:f800::/32", "2405:b500::/32",
	"2405:8100::/32", "2a06:98c0::/29", "2c0f:f248::/32",
)

func mustPrefixes(cidrs ...string) []netip.Prefix {
	out := make([]netip.Prefix, 0, len(cidrs))
	for _, c := range cidrs {
		out = append(out, netip.MustParsePrefix(c))
	}
	return out
}

func isCloudflareIP(ip string) bool {
	addr, err := netip.ParseAddr(strings.TrimSpace(ip))
	if err != nil {
		return false
	}
	addr = addr.Unmap()
	for _, p := range cloudflareCIDRs {
		if p.Contains(addr) {
			return true
		}
	}
	return false
}

func validIP(s string) string {
	addr, err := netip.ParseAddr(strings.TrimSpace(s))
	if err != nil {
		return ""
	}
	return addr.Unmap().String()
}

// clientRemoteIP 返回访客真实 IP（只返回合法 IP 文本）。
func clientRemoteIP(c *gin.Context) string {
	peer := ""
	if v := c.Request.Header.Get("X-Real-IP"); v != "" {
		peer = validIP(strings.Split(v, ",")[0])
	}
	if peer == "" {
		if v := c.Request.Header.Get("X-Forwarded-For"); v != "" {
			peer = validIP(strings.Split(v, ",")[0])
		}
	}
	if peer == "" {
		peer = validIP(c.ClientIP())
	}
	if peer != "" && isCloudflareIP(peer) {
		if cf := validIP(c.Request.Header.Get("CF-Connecting-IP")); cf != "" {
			return cf
		}
	}
	if peer == "" {
		return c.ClientIP()
	}
	return peer
}

// IPLocator 把 IP 查成中文归属地（例如「广西南宁 电信」）。必须是本地/离线查询，禁止在这里访问外部服务。
type IPLocator func(ip string) string

var (
	locatorMu sync.RWMutex
	locator   IPLocator
)

// SetIPLocator 注册归属地查询。不注册时 ip_location 只会对内网地址写「内网地址」，其余留空，
// 由展示端（auth-api）按本地库回填。
func SetIPLocator(l IPLocator) {
	locatorMu.Lock()
	locator = l
	locatorMu.Unlock()
}

// LocateIPZH 返回 IP 的中文归属地；内网/回环地址直接返回「内网地址」。
func LocateIPZH(ip string) string {
	ip = validIP(ip)
	if ip == "" {
		return ""
	}
	addr := netip.MustParseAddr(ip)
	if addr.IsLoopback() || addr.IsPrivate() || addr.IsLinkLocalUnicast() || addr.IsUnspecified() {
		return "内网地址"
	}
	locatorMu.RLock()
	l := locator
	locatorMu.RUnlock()
	if l == nil {
		return ""
	}
	return l(ip)
}
