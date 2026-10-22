package middle

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/open4go/model"
)

func newWriteCtx(host string, headers map[string]string) *gin.Context {
	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	req := httptest.NewRequest(http.MethodGet, "http://"+host+"/v1/hlj/products", nil)
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	c.Request = req
	return c
}

func TestWriteIntoHeaderFallsBackWhenSuperDomainUnset(t *testing.T) {
	setSuperDomain(t, "")
	c := newWriteCtx("localhost:8812", nil)
	login := LoginInfo{MerchantID: "tenant-a", Namespace: "hlj", AccountID: "acc-1", UserID: "u-1"}
	login.WriteIntoHeader(c)

	if got := c.GetHeader("X-Tenant-ID"); got != "tenant-a" {
		t.Fatalf("X-Tenant-ID=%q want tenant-a", got)
	}
	if got := model.GetValueFromCtx(c.Request.Context(), model.MerchantKey); got != "tenant-a" {
		t.Fatalf("MerchantKey=%q want tenant-a", got)
	}
	if got := model.GetValueFromCtx(c.Request.Context(), model.NamespaceKey); got != "hlj" {
		t.Fatalf("NamespaceKey=%q want hlj, not wildcard", got)
	}
}

func TestWriteIntoHeaderIsolatesTenantHostEvenIfLooksLikePrefix(t *testing.T) {
	setSuperDomain(t, "super.localhost")
	c := newWriteCtx("admin.localhost:8988", nil)
	login := LoginInfo{MerchantID: "tenant-b", Namespace: "hlj"}
	login.WriteIntoHeader(c)

	if got := c.GetHeader("X-Tenant-ID"); got != "tenant-b" {
		t.Fatalf("X-Tenant-ID=%q want tenant-b", got)
	}
	if got := model.GetValueFromCtx(c.Request.Context(), model.MerchantKey); got != "tenant-b" {
		t.Fatalf("MerchantKey=%q want tenant-b", got)
	}
}

func TestWriteIntoHeaderUnswitchedSuperAdminKeepsJWTMerchant(t *testing.T) {
	setSuperDomain(t, "super.localhost")
	c := newWriteCtx("super.localhost:8812", nil)
	login := LoginInfo{MerchantID: "st", Namespace: "hlj"}
	login.WriteIntoHeader(c)

	if got := c.GetHeader("X-Tenant-ID"); got != "st" {
		t.Fatalf("unswitched super-admin X-Tenant-ID=%q want st", got)
	}
	if got := model.GetValueFromCtx(c.Request.Context(), model.NamespaceKey); got != "hlj" {
		t.Fatalf("unswitched super-admin must not get namespace=*, got %q", got)
	}
}

func TestWriteIntoHeaderSuperAdminStarSeesAll(t *testing.T) {
	setSuperDomain(t, "super.localhost")
	setViper(t, cfgSuperMerchants, []string{"st"})
	c := newWriteCtx("super.localhost:8812", map[string]string{"X-Merchant-ID": "*"})
	login := LoginInfo{MerchantID: "st", Namespace: "hlj"}
	login.WriteIntoHeader(c)

	if got := c.GetHeader("X-Tenant-ID"); got != "" {
		t.Fatalf("X-Tenant-ID=%q want empty for view-all", got)
	}
	if got := model.GetValueFromCtx(c.Request.Context(), model.MerchantKey); got != "" {
		t.Fatalf("MerchantKey=%q want empty for view-all", got)
	}
	if got := model.GetValueFromCtx(c.Request.Context(), model.NamespaceKey); got != "*" {
		t.Fatalf("NamespaceKey=%q want *", got)
	}
}

func TestWriteIntoHeaderSuperAdminSwitchUsesMerchantHeader(t *testing.T) {
	setSuperDomain(t, "super.localhost")
	setViper(t, cfgSuperMerchants, []string{"st"})
	c := newWriteCtx("super.localhost:8812", map[string]string{"X-Merchant-ID": "tenant-b"})
	login := LoginInfo{MerchantID: "st", Namespace: "hlj"}
	login.WriteIntoHeader(c)

	if got := c.GetHeader("X-Tenant-ID"); got != "tenant-b" {
		t.Fatalf("X-Tenant-ID=%q want tenant-b", got)
	}
	if got := model.GetValueFromCtx(c.Request.Context(), model.MerchantKey); got != "tenant-b" {
		t.Fatalf("MerchantKey=%q want tenant-b", got)
	}
}

func TestWriteIntoHeaderForwardedHostSeesSuper(t *testing.T) {
	setSuperDomain(t, "super.localhost")
	setViper(t, cfgSuperMerchants, []string{"st"})
	// httptest requests come from 192.0.2.1
	setViper(t, cfgTrustedProxies, []string{"192.0.2.0/24"})
	c := newWriteCtx("store-center:9801", map[string]string{
		"X-Forwarded-Host": "super.localhost:8988",
		"X-Merchant-ID":    "*",
	})
	login := LoginInfo{MerchantID: "st", Namespace: "hlj"}
	login.WriteIntoHeader(c)

	if got := c.GetHeader("X-Tenant-ID"); got != "" {
		t.Fatalf("forwarded super view-all X-Tenant-ID=%q want empty", got)
	}
	if got := model.GetValueFromCtx(c.Request.Context(), model.NamespaceKey); got != "*" {
		t.Fatalf("NamespaceKey=%q want *", got)
	}
}

func TestWriteIntoHeaderGatewayTenantMatchingJWT(t *testing.T) {
	setSuperDomain(t, "")
	c := newWriteCtx("localhost:8812", map[string]string{"X-Tenant-ID": "tenant-a"})
	login := LoginInfo{MerchantID: "tenant-a", Namespace: "hlj"}
	login.WriteIntoHeader(c)

	if got := c.GetHeader("X-Tenant-ID"); got != "tenant-a" {
		t.Fatalf("X-Tenant-ID=%q want tenant-a", got)
	}
	if IsSuperAdmin(c) {
		t.Fatal("tenant login must not be super admin")
	}
}

// 已校验的非超管登录：请求头中的 X-Tenant-ID 与 token 商户不一致时以 token 为准。
func TestWriteIntoHeaderTenantHeaderCannotOverrideJWT(t *testing.T) {
	setSuperDomain(t, "")
	c := newWriteCtx("localhost:8812", map[string]string{"X-Tenant-ID": "other-tenant"})
	login := LoginInfo{MerchantID: "from-jwt", Namespace: "hlj"}
	login.WriteIntoHeader(c)

	if got := c.GetHeader("X-Tenant-ID"); got != "from-jwt" {
		t.Fatalf("X-Tenant-ID=%q want from-jwt", got)
	}
	if got := c.GetHeader("MerchantID"); got != "from-jwt" {
		t.Fatalf("MerchantID=%q want from-jwt", got)
	}
	if got := model.GetValueFromCtx(c.Request.Context(), model.MerchantKey); got != "from-jwt" {
		t.Fatalf("MerchantKey=%q want from-jwt", got)
	}
}

// 超管域名上，非超管 token 伪造 X-Merchant-ID / X-Tenant-ID 也不能切换商户。
func TestWriteIntoHeaderSpoofedSwitchOnSuperHost(t *testing.T) {
	setSuperDomain(t, "super.localhost")
	setViper(t, cfgSuperMerchants, []string{"st"})
	c := newWriteCtx("super.localhost:8812", map[string]string{"X-Merchant-ID": "*", "X-Tenant-ID": "victim"})
	login := LoginInfo{MerchantID: "tenant-a", Namespace: "hlj"}
	login.WriteIntoHeader(c)

	if IsSuperAdmin(c) {
		t.Fatal("must not be super admin")
	}
	if got := c.GetHeader("X-Tenant-ID"); got != "tenant-a" {
		t.Fatalf("X-Tenant-ID=%q want tenant-a", got)
	}
}

func TestIsSuperAdminOnlyFromVerifiedLogin(t *testing.T) {
	setSuperDomain(t, "super.localhost")
	setViper(t, cfgSuperMerchants, []string{"st"})

	c := newWriteCtx("super.localhost:8812", map[string]string{"X-Merchant-ID": "*"})
	(&LoginInfo{MerchantID: "st", Namespace: "hlj"}).WriteIntoHeader(c)
	if !IsSuperAdmin(c) {
		t.Fatal("verified super login should be super admin")
	}

	// MerchantBindMiddleware 路径：登录信息来自请求头，不能获得超管。
	c = newWriteCtx("super.localhost:8812", map[string]string{"X-Merchant-ID": "*", "MerchantID": "st"})
	bindMerchant(c)
	if IsSuperAdmin(c) {
		t.Fatal("header-only login must not be super admin")
	}
	if c.GetHeader("X-Merchant-ID") != "*" {
		t.Fatal("bind must leave X-Merchant-ID for the verifying middleware")
	}
	if IsSuperAdmin(nil) {
		t.Fatal("nil ctx")
	}
}

func TestWriteIntoHeaderForwardedHostIgnoredFromUntrustedPeer(t *testing.T) {
	setSuperDomain(t, "super.localhost")
	setViper(t, cfgSuperMerchants, []string{"st"})
	setViper(t, cfgTrustedProxies, []string{})
	c := newWriteCtx("store-center:9801", map[string]string{
		"X-Forwarded-Host": "super.localhost:8988",
		"X-Merchant-ID":    "*",
	})
	login := LoginInfo{MerchantID: "st", Namespace: "hlj"}
	login.WriteIntoHeader(c)

	if got := c.GetHeader("X-Tenant-ID"); got != "st" {
		t.Fatalf("X-Tenant-ID=%q want st (forwarded host not trusted)", got)
	}
	if got := model.GetValueFromCtx(c.Request.Context(), model.NamespaceKey); got != "hlj" {
		t.Fatalf("NamespaceKey=%q want hlj", got)
	}
}

func TestWriteIntoHeaderTenantLoginCannotSwitchOnSuperHost(t *testing.T) {
	setSuperDomain(t, "super.localhost")
	setViper(t, cfgSuperMerchants, []string{"st"})
	for _, sw := range []string{"*", "tenant-b"} {
		c := newWriteCtx("super.localhost:8812", map[string]string{"X-Merchant-ID": sw})
		login := LoginInfo{MerchantID: "tenant-a", Namespace: "hlj"}
		login.WriteIntoHeader(c)

		if got := c.GetHeader("X-Tenant-ID"); got != "tenant-a" {
			t.Fatalf("switch %q: X-Tenant-ID=%q want tenant-a", sw, got)
		}
		if got := model.GetValueFromCtx(c.Request.Context(), model.MerchantKey); got != "tenant-a" {
			t.Fatalf("switch %q: MerchantKey=%q want tenant-a", sw, got)
		}
		if got := model.GetValueFromCtx(c.Request.Context(), model.NamespaceKey); got != "hlj" {
			t.Fatalf("switch %q: NamespaceKey=%q want hlj", sw, got)
		}
		if got := c.GetHeader("X-Merchant-ID"); got != "" {
			t.Fatalf("switch %q: X-Merchant-ID should be stripped, got %q", sw, got)
		}
	}
}

func TestWriteIntoHeaderSuperAdminFlagCanSwitch(t *testing.T) {
	setSuperDomain(t, "super.localhost")
	setViper(t, cfgSuperMerchants, []string{})
	c := newWriteCtx("super.localhost", map[string]string{"X-Merchant-ID": "tenant-b"})
	login := LoginInfo{MerchantID: "ops", Namespace: "hlj", SuperAdmin: true}
	login.WriteIntoHeader(c)
	if got := c.GetHeader("X-Tenant-ID"); got != "tenant-b" {
		t.Fatalf("X-Tenant-ID=%q want tenant-b", got)
	}
}
