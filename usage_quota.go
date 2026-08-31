package middle

import (
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/open4go/log"
	"github.com/spf13/viper"
)

var (
	quotaHTTPOnce   sync.Once
	quotaHTTPClient *http.Client
)

func quotaClient() *http.Client {
	quotaHTTPOnce.Do(func() {
		quotaHTTPClient = &http.Client{Timeout: 400 * time.Millisecond}
	})
	return quotaHTTPClient
}

func usageCheckURL() string {
	if u := strings.TrimSpace(viper.GetString("usage.check_url")); u != "" {
		return u
	}
	base := strings.TrimSpace(viper.GetString("usage.auth_base"))
	if base == "" {
		return ""
	}
	return strings.TrimRight(base, "/") + "/v1/system/auth/user/usage/check"
}

const (
	// StatusQuotaExceeded is the HTTP status returned when a create is blocked by plan quota.
	// 402 is used so clients can tell this apart from 401/403 auth failures.
	StatusQuotaExceeded = http.StatusPaymentRequired
)

type quotaCheckBody struct {
	Allowed bool   `json:"allowed"`
	Message string `json:"message"`
}

// allowQuotaOrAbort blocks successful-create paths when the tenant is over plan quota.
// Network errors fail open so a down auth-api does not freeze the shop.
func allowQuotaOrAbort(c *gin.Context) bool {
	if c.Request.Method != http.MethodPost {
		return true
	}
	fullPath := c.FullPath()
	if fullPath == "" {
		fullPath = c.Request.URL.Path
	}
	if skipOperatePath(fullPath, c.Request.URL.Path) {
		return true
	}
	resource, _ := ClassifyResource(fullPath)
	kind := usageKindOf(resource)
	if kind == "" {
		return true
	}
	if ActionFromRequest(c.Request.Method, fullPath, c.Request.URL.RawQuery) != "create" {
		return true
	}
	l := LoadFromHeader(c)
	merchantID := firstNonEmpty(
		l.MerchantID,
		c.GetHeader("X-Tenant-ID"),
		c.GetHeader("X-Merchant-ID"),
		c.GetHeader("MerchantID"),
	)
	if skipUsageMerchant(merchantID) {
		return true
	}
	ok, msg := checkQuotaRemote(c, merchantID, kind, c.Request.ContentLength)
	if ok {
		return true
	}
	c.AbortWithStatusJSON(StatusQuotaExceeded, gin.H{
		"title":   "超出套餐额度",
		"message": msg,
		"status":  "fail",
		"error":   "quota_exceeded",
		"code":    StatusQuotaExceeded,
	})
	return false
}

func checkQuotaRemote(c *gin.Context, merchantID, kind string, extraBytes int64) (allowed bool, message string) {
	endpoint := usageCheckURL()
	if endpoint == "" {
		return true, ""
	}
	u, err := url.Parse(endpoint)
	if err != nil {
		return true, ""
	}
	q := u.Query()
	q.Set("kind", kind)
	if extraBytes > 0 {
		q.Set("bytes", strconv.FormatInt(extraBytes, 10))
	}
	u.RawQuery = q.Encode()

	req, err := http.NewRequestWithContext(c.Request.Context(), http.MethodGet, u.String(), nil)
	if err != nil {
		return true, ""
	}
	req.Header.Set("X-Merchant-ID", merchantID)
	req.Header.Set("X-Tenant-ID", merchantID)
	if v := c.GetHeader("Authorization"); v != "" {
		req.Header.Set("Authorization", v)
	}
	if v := c.GetHeader("jwt"); v != "" {
		req.Header.Set("jwt", v)
	}
	if cookie, err := c.Request.Cookie("jwt"); err == nil && cookie != nil {
		req.AddCookie(cookie)
	}

	res, err := quotaClient().Do(req)
	if err != nil {
		log.Log(c.Request.Context()).WithError(err).Warning("quota check skipped")
		return true, ""
	}
	defer res.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(res.Body, 4096))
	if res.StatusCode >= 400 {
		log.Log(c.Request.Context()).WithField("status", res.StatusCode).Warning("quota check http")
		return true, ""
	}
	var body quotaCheckBody
	if err := json.Unmarshal(raw, &body); err != nil {
		return true, ""
	}
	if body.Allowed {
		return true, ""
	}
	msg := strings.TrimSpace(body.Message)
	if msg == "" {
		msg = "已超出套餐额度"
	}
	return false, msg
}
