package middle

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/open4go/log"
	"github.com/open4go/model"
)

const testGatewayToken = "unit-test-gateway-token"

func signBearer(t *testing.T, mid string) string {
	t.Helper()
	claims := jwt.MapClaims{
		"sub": "acc-1", "iss": "test", "aud": "mini", "jti": "j1",
		"exp": time.Now().Add(time.Hour).Unix(),
	}
	if mid != "" {
		claims["mid"] = mid
	}
	s, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString(testKey)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func runBearer(t *testing.T, mid string, hdr map[string]string) (int, string, string) {
	t.Helper()
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.GET("/x", JWTAuthMiddleware(testKey), func(c *gin.Context) {
		c.String(http.StatusOK, "%s|%s", c.GetHeader("X-Tenant-ID"),
			model.GetValueFromCtx(c.Request.Context(), model.MerchantKey))
	})
	req := httptest.NewRequest(http.MethodGet, "/x", nil)
	req.Header.Set("Authorization", "Bearer "+signBearer(t, mid))
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	parts := strings.SplitN(w.Body.String(), "|", 2)
	if len(parts) != 2 {
		return w.Code, "", ""
	}
	return w.Code, parts[0], parts[1]
}

func TestValidGatewayToken(t *testing.T) {
	setViper(t, cfgGatewayToken, "")
	if ValidGatewayToken("anything") || ValidGatewayToken("") {
		t.Fatal("未配置令牌时必须拒绝")
	}
	setViper(t, cfgGatewayToken, testGatewayToken)
	if !ValidGatewayToken(testGatewayToken) || !ValidGatewayToken(" "+testGatewayToken+" ") {
		t.Fatal("正确令牌应通过")
	}
	if ValidGatewayToken("") || ValidGatewayToken("wrong") || ValidGatewayToken(testGatewayToken+"x") {
		t.Fatal("错误令牌应拒绝")
	}
}

func TestBearerTenantHeaderNeedsGateway(t *testing.T) {
	setViper(t, cfgGatewayToken, testGatewayToken)
	setViper(t, cfgGatewayAllowUnverified, false)

	// 无网关令牌：忽略客户端 X-Tenant-ID
	code, hdr, ctx := runBearer(t, "", map[string]string{"X-Tenant-ID": "t-forged"})
	if code != http.StatusOK || hdr != "" || ctx != "" {
		t.Fatalf("未经网关的租户头应被忽略: code=%d hdr=%q ctx=%q", code, hdr, ctx)
	}
	// 错误网关令牌
	_, hdr, ctx = runBearer(t, "", map[string]string{"X-Tenant-ID": "t-forged", GatewayTokenHeader: "wrong"})
	if hdr != "" || ctx != "" {
		t.Fatalf("错误令牌不应采信租户头: hdr=%q ctx=%q", hdr, ctx)
	}
	// 正确网关令牌
	_, hdr, ctx = runBearer(t, "", map[string]string{"X-Tenant-ID": "t-1", GatewayTokenHeader: testGatewayToken})
	if hdr != "t-1" || ctx != "t-1" {
		t.Fatalf("网关注入的租户头应被采信: hdr=%q ctx=%q", hdr, ctx)
	}
	// JWT 自带商户：不依赖网关令牌，且不匹配时 403
	_, hdr, ctx = runBearer(t, "m-1", nil)
	if hdr != "m-1" || ctx != "m-1" {
		t.Fatalf("JWT 商户应生效: hdr=%q ctx=%q", hdr, ctx)
	}
	if code, _, _ := runBearer(t, "m-1", map[string]string{"X-Tenant-ID": "m-2", GatewayTokenHeader: testGatewayToken}); code != http.StatusForbidden {
		t.Fatalf("商户不一致应 403, got %d", code)
	}
}

func TestBearerTenantHeaderTransitionFlag(t *testing.T) {
	setViper(t, cfgGatewayToken, "")
	setViper(t, cfgGatewayAllowUnverified, false)
	if _, hdr, _ := runBearer(t, "", map[string]string{"X-Tenant-ID": "t-1"}); hdr != "" {
		t.Fatalf("默认安全：未配置令牌时不采信租户头, got %q", hdr)
	}
	setViper(t, cfgGatewayAllowUnverified, true)
	if _, hdr, ctx := runBearer(t, "", map[string]string{"X-Tenant-ID": "t-1"}); hdr != "t-1" || ctx != "t-1" {
		t.Fatalf("过渡开关打开时保持旧行为: hdr=%q ctx=%q", hdr, ctx)
	}
}

func TestWriteIntoHeaderTenantHeaderNeedsGateway(t *testing.T) {
	setSuperDomain(t, "super.example.test")
	setViper(t, cfgGatewayToken, testGatewayToken)
	setViper(t, cfgGatewayAllowUnverified, false)
	login := LoginInfo{Namespace: "hlj", AccountID: "acc-1", UserID: "u-1"}

	c := newWriteCtx("mini.example.test", map[string]string{"X-Tenant-ID": "t-forged"})
	login.WriteIntoHeader(c)
	if got := c.GetHeader("X-Tenant-ID"); got != "" {
		t.Fatalf("未经网关的租户头应被删除, got %q", got)
	}
	if got := model.GetValueFromCtx(c.Request.Context(), model.MerchantKey); got != "" {
		t.Fatalf("MerchantKey=%q want empty", got)
	}

	c = newWriteCtx("mini.example.test", map[string]string{"X-Tenant-ID": "t-1", GatewayTokenHeader: testGatewayToken})
	login.WriteIntoHeader(c)
	if got := model.GetValueFromCtx(c.Request.Context(), model.MerchantKey); got != "t-1" {
		t.Fatalf("网关注入的租户头应生效, got %q", got)
	}

	// JWT 带商户时与网关令牌无关
	withMerchant := LoginInfo{MerchantID: "m-1", Namespace: "hlj", AccountID: "acc-1"}
	c = newWriteCtx("admin.example.test", map[string]string{"X-Tenant-ID": "t-forged"})
	withMerchant.WriteIntoHeader(c)
	if got := c.GetHeader("X-Tenant-ID"); got != "m-1" {
		t.Fatalf("JWT 商户优先, got %q", got)
	}
}

func TestSetGatewayTokenAndNoLogLeak(t *testing.T) {
	setViper(t, cfgGatewayToken, "")
	req := httptest.NewRequest(http.MethodGet, "/x", nil)
	SetGatewayToken(req)
	if req.Header.Get(GatewayTokenHeader) != "" {
		t.Fatal("未配置时不应设置令牌头")
	}
	setViper(t, cfgGatewayToken, testGatewayToken)
	SetGatewayToken(req)
	if req.Header.Get(GatewayTokenHeader) != testGatewayToken {
		t.Fatal("应设置令牌头")
	}

	var buf bytes.Buffer
	log.Init("debug", &buf)
	t.Cleanup(func() { log.Init("info", nil) })
	runBearer(t, "", map[string]string{"X-Tenant-ID": "t-1", GatewayTokenHeader: "wrong-" + testGatewayToken})
	runBearer(t, "", map[string]string{"X-Tenant-ID": "t-1", GatewayTokenHeader: testGatewayToken})
	if !strings.Contains(buf.String(), "request not from gateway") {
		t.Fatalf("应记录忽略租户头的告警: %s", buf.String())
	}
	if strings.Contains(buf.String(), testGatewayToken) {
		t.Fatal("日志中不得出现网关令牌")
	}
}
