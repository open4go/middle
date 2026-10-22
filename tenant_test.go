package middle

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/spf13/viper"
)

func setSuperDomain(t *testing.T, domain string) {
	t.Helper()
	prev := viper.GetString("super.domain")
	viper.Set("super.domain", domain)
	t.Cleanup(func() {
		viper.Set("super.domain", prev)
	})
}

func setViper(t *testing.T, key string, val interface{}) {
	t.Helper()
	prev := viper.Get(key)
	viper.Set(key, val)
	t.Cleanup(func() {
		viper.Set(key, prev)
	})
}

func TestHostnameOnly(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{"", ""},
		{"super.localhost", "super.localhost"},
		{"Super.Localhost", "super.localhost"},
		{"super.localhost:8812", "super.localhost"},
		{"admin.localhost:8988", "admin.localhost"},
		{"[::1]:8812", "::1"},
	}
	for _, tc := range cases {
		if got := hostnameOnly(tc.in); got != tc.want {
			t.Errorf("hostnameOnly(%q)=%q want %q", tc.in, got, tc.want)
		}
	}
}

func TestIsSuperAdminHostEmptyConfigNeverMatches(t *testing.T) {
	setSuperDomain(t, "")
	hosts := []string{
		"localhost:8812",
		"admin.localhost:8988",
		"product-api:8812",
		"super.localhost",
		"",
	}
	for _, h := range hosts {
		if isSuperAdminHost(h) {
			t.Errorf("empty super.domain must not match host %q", h)
		}
	}
}

func TestIsSuperAdminHostLocalhostRequiresOptIn(t *testing.T) {
	setSuperDomain(t, "")
	setViper(t, cfgSuperAllowLocalhost, false)
	if isSuperAdminHost("super.localhost:8812") {
		t.Fatal("super.localhost must not match unless super.allowLocalhost is enabled")
	}
	setViper(t, cfgSuperAllowLocalhost, true)
	if !isSuperAdminHost("super.localhost:8812") {
		t.Fatal("super.localhost should match when super.allowLocalhost=true")
	}
	if isSuperAdminHost("admin.localhost") {
		t.Fatal("allowLocalhost must only enable super.localhost")
	}
}

func TestRequestAdminHostForwardedHostNeedsTrustedProxy(t *testing.T) {
	gin.SetMode(gin.TestMode)
	newCtx := func(remote string) *gin.Context {
		c, _ := gin.CreateTestContext(httptest.NewRecorder())
		req := httptest.NewRequest(http.MethodGet, "http://store-center:9801/x", nil)
		req.RemoteAddr = remote
		req.Header.Set("X-Forwarded-Host", "super.example.com")
		req.Header.Set("Origin", "https://super.example.com")
		c.Request = req
		return c
	}

	setViper(t, cfgTrustedProxies, []string{})
	if got := requestAdminHost(newCtx("203.0.113.9:5555")); got != "store-center:9801" {
		t.Fatalf("no trusted proxies configured: got %q want Request.Host", got)
	}

	setViper(t, cfgTrustedProxies, []string{"10.0.0.0/8", "192.168.1.10"})
	if got := requestAdminHost(newCtx("203.0.113.9:5555")); got != "store-center:9801" {
		t.Fatalf("untrusted peer: got %q want Request.Host", got)
	}
	if got := requestAdminHost(newCtx("10.1.2.3:5555")); got != "super.example.com" {
		t.Fatalf("trusted CIDR peer: got %q want forwarded host", got)
	}
	if got := requestAdminHost(newCtx("192.168.1.10:5555")); got != "super.example.com" {
		t.Fatalf("trusted IP peer: got %q want forwarded host", got)
	}
}

func TestCanSwitchMerchant(t *testing.T) {
	setViper(t, cfgSuperMerchants, []string{"st"})
	if !canSwitchMerchant(&LoginInfo{MerchantID: "st"}) {
		t.Fatal("listed merchant should be allowed")
	}
	if !canSwitchMerchant(&LoginInfo{MerchantID: "x", SuperAdmin: true}) {
		t.Fatal("SuperAdmin flag should be allowed")
	}
	if canSwitchMerchant(&LoginInfo{MerchantID: "tenant-a"}) {
		t.Fatal("ordinary tenant must not switch")
	}
	if canSwitchMerchant(&LoginInfo{}) || canSwitchMerchant(nil) {
		t.Fatal("empty login must not switch")
	}
	setViper(t, cfgSuperMerchants, []string{})
	setViper(t, cfgSuperMerchant, "")
	if canSwitchMerchant(&LoginInfo{MerchantID: "st"}) {
		t.Fatal("default config must not allow switching")
	}
	setViper(t, cfgSuperMerchant, "st")
	if !canSwitchMerchant(&LoginInfo{MerchantID: "st"}) {
		t.Fatal("legacy single super.merchant should be honoured")
	}
	if canSwitchMerchant(&LoginInfo{MerchantID: "tenant-a"}) {
		t.Fatal("other merchants still denied")
	}
}

func TestIsSuperAdminHostExactMatch(t *testing.T) {
	setSuperDomain(t, "super.localhost")
	if !isSuperAdminHost("super.localhost") {
		t.Fatal("exact host should match")
	}
	if !isSuperAdminHost("super.localhost:8812") {
		t.Fatal("host with port should match")
	}
	if !isSuperAdminHost("Super.Localhost:443") {
		t.Fatal("case-insensitive match")
	}
	if isSuperAdminHost("admin.localhost:8988") {
		t.Fatal("tenant admin host must not match")
	}
	if isSuperAdminHost("super.localhost.evil.com") {
		t.Fatal("prefix / suffix impersonation must not match")
	}
	if isSuperAdminHost("notsuper.localhost") {
		t.Fatal("partial prefix must not match")
	}
}

func TestSkipTenantFallback(t *testing.T) {
	gin.SetMode(gin.TestMode)
	setSuperDomain(t, "super.localhost")

	mk := func(host, merchantID string) *gin.Context {
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		req := httptest.NewRequest(http.MethodGet, "http://"+host+"/v1/hlj/products", nil)
		if merchantID != "" {
			req.Header.Set("X-Merchant-ID", merchantID)
		}
		c.Request = req
		return c
	}

	if skipTenantFallback(mk("admin.localhost:8988", "*")) {
		t.Fatal("tenant host must never skip JWT merchant fallback")
	}
	if skipTenantFallback(mk("super.localhost:8812", "")) {
		t.Fatal("unswitched super-admin must keep JWT merchant isolation")
	}
	if !skipTenantFallback(mk("super.localhost:8812", "*")) {
		t.Fatal("super-admin with X-Merchant-ID=* should skip fallback")
	}
	if !skipTenantFallback(mk("super.localhost:8812", "abc123")) {
		t.Fatal("super-admin switching merchant should skip fallback")
	}
}
