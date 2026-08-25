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

func TestWriteIntoHeaderGatewayTenantWins(t *testing.T) {
	setSuperDomain(t, "")
	c := newWriteCtx("localhost:8812", map[string]string{"X-Tenant-ID": "from-gateway"})
	login := LoginInfo{MerchantID: "from-jwt", Namespace: "hlj"}
	login.WriteIntoHeader(c)

	if got := c.GetHeader("X-Tenant-ID"); got != "from-gateway" {
		t.Fatalf("X-Tenant-ID=%q want from-gateway", got)
	}
	if got := c.GetHeader("MerchantID"); got != "from-gateway" {
		t.Fatalf("MerchantID=%q want from-gateway", got)
	}
}
