package tenantguard

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/open4go/middle"
)

func ctxWith(headers map[string]string, super bool) *gin.Context {
	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	c.Request = req
	if super {
		c.Set(middle.SuperAdminContextKey, true)
	}
	return c
}

func TestMerchantStrictNoSwitcherFallback(t *testing.T) {
	c := ctxWith(map[string]string{"X-Merchant-ID": "attacker"}, false)
	if got := Merchant(c); got != "" {
		t.Fatalf("Merchant=%q want empty", got)
	}
	c = ctxWith(map[string]string{"X-Tenant-ID": "st", "X-Merchant-ID": "attacker"}, false)
	if got := Merchant(c); got != "st" {
		t.Fatalf("Merchant=%q want st", got)
	}
	c = ctxWith(map[string]string{"X-Tenant-ID": "*"}, true)
	if got := Merchant(c); got != "" {
		t.Fatalf("Merchant=* → %q want empty", got)
	}
}

func TestOwnsAndAllow(t *testing.T) {
	c := ctxWith(map[string]string{"X-Tenant-ID": "a"}, false)
	if !Owns(c, "a") || Owns(c, "b") {
		t.Fatal("owns mismatch")
	}
	// view-all without super → deny
	c = ctxWith(map[string]string{"X-Tenant-ID": "*"}, false)
	if Owns(c, "a") {
		t.Fatal("view-all without super must deny")
	}
	c = ctxWith(map[string]string{"X-Tenant-ID": "*"}, true)
	if !Owns(c, "a") {
		t.Fatal("super view-all must allow")
	}
	c2 := ctxWith(map[string]string{"X-Tenant-ID": "a"}, false)
	if Allow(c2, "b") {
		t.Fatal("allow should fail")
	}
	if !c2.IsAborted() {
		t.Fatal("expected abort")
	}
}

func TestRequireSuperOrMerchant(t *testing.T) {
	gin.SetMode(gin.TestMode)
	h := Require()
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodGet, "/", nil)
	h(c)
	if w.Code != http.StatusForbidden {
		t.Fatalf("code=%d", w.Code)
	}

	w2 := httptest.NewRecorder()
	c2, eng := gin.CreateTestContext(w2)
	c2.Request = httptest.NewRequest(http.MethodGet, "/", nil)
	c2.Request.Header.Set("X-Tenant-ID", "m1")
	passed := false
	eng.Use(h)
	// call handler directly
	c2, _ = gin.CreateTestContext(w2)
	c2.Request = httptest.NewRequest(http.MethodGet, "/", nil)
	c2.Request.Header.Set("X-Tenant-ID", "m1")
	h(c2)
	if c2.IsAborted() {
		t.Fatal("merchant context should pass require")
	}
	_ = passed
}

func TestSuperOnly(t *testing.T) {
	c := ctxWith(nil, false)
	if SuperOnly(c) {
		t.Fatal("non-super")
	}
	c = ctxWith(nil, true)
	if !SuperOnly(c) {
		t.Fatal("super")
	}
}
