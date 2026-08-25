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
