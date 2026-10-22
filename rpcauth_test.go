package middle

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
)

func rpcRouter() *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.POST("/rpc/x", RPCAuthMiddleware(), func(c *gin.Context) { c.Status(http.StatusOK) })
	return r
}

func doRPC(r *gin.Engine, headers map[string]string) int {
	req := httptest.NewRequest(http.MethodPost, "/rpc/x", nil)
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w.Code
}

func TestRPCAuthMiddleware(t *testing.T) {
	setViper(t, cfgRPCAuthToken, "")
	setViper(t, cfgRPCLegacyToken, "")
	setViper(t, cfgRPCAllowUnauth, false)
	r := rpcRouter()

	// 未配置令牌：默认拒绝
	if got := doRPC(r, nil); got != http.StatusUnauthorized {
		t.Fatalf("no config: %d", got)
	}
	if got := doRPC(r, map[string]string{InternalTokenHeader: "anything"}); got != http.StatusUnauthorized {
		t.Fatalf("no config with header: %d", got)
	}

	setViper(t, cfgRPCAuthToken, "s3cret")
	cases := []struct {
		name    string
		headers map[string]string
		want    int
	}{
		{"missing", nil, http.StatusUnauthorized},
		{"wrong", map[string]string{InternalTokenHeader: "nope"}, http.StatusUnauthorized},
		{"prefix", map[string]string{InternalTokenHeader: "s3cre"}, http.StatusUnauthorized},
		{"ok", map[string]string{InternalTokenHeader: "s3cret"}, http.StatusOK},
		{"legacy header", map[string]string{"Token": "s3cret"}, http.StatusOK},
	}
	for _, tc := range cases {
		if got := doRPC(r, tc.headers); got != tc.want {
			t.Fatalf("%s: got %d want %d", tc.name, got, tc.want)
		}
	}
}

func TestRPCAuthLegacyConfigKey(t *testing.T) {
	setViper(t, cfgRPCAuthToken, "")
	setViper(t, cfgRPCLegacyToken, "old")
	setViper(t, cfgRPCAllowUnauth, false)
	if !ValidInternalToken("old") || ValidInternalToken("new") {
		t.Fatal("legacy rpc.token not honoured")
	}
	if got := doRPC(rpcRouter(), map[string]string{InternalTokenHeader: "old"}); got != http.StatusOK {
		t.Fatalf("legacy: %d", got)
	}
}

func TestRPCAuthAllowUnauthenticatedFlag(t *testing.T) {
	setViper(t, cfgRPCAuthToken, "s3cret")
	setViper(t, cfgRPCAllowUnauth, true)
	if got := doRPC(rpcRouter(), nil); got != http.StatusOK {
		t.Fatalf("opt-out flag: %d", got)
	}
}

func TestSetInternalToken(t *testing.T) {
	setViper(t, cfgRPCAuthToken, "")
	setViper(t, cfgRPCLegacyToken, "")
	req := httptest.NewRequest(http.MethodGet, "/rpc/x", nil)
	SetInternalToken(req)
	if req.Header.Get(InternalTokenHeader) != "" {
		t.Fatal("must not set empty token")
	}
	setViper(t, cfgRPCAuthToken, "s3cret")
	SetInternalToken(req)
	if req.Header.Get(InternalTokenHeader) != "s3cret" {
		t.Fatal("token not set")
	}
	SetInternalToken(nil)
}
