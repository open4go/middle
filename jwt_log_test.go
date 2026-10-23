package middle

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/open4go/log"
)

// 未登录（缺少 cookie）是正常的 401 路径，不应在 info 级别产生 error 日志和堆栈。
func TestMissingJWTCookieIsNotAnErrorLog(t *testing.T) {
	var buf bytes.Buffer
	log.Init("info", &buf)
	t.Cleanup(func() { log.Init("info", nil) })

	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(TraceMiddleware(), log.RequestLogger())
	r.GET("/v1/x", JWTMiddleware(testKey), func(c *gin.Context) { c.Status(http.StatusOK) })
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/v1/x", nil))

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("code=%d", w.Code)
	}
	out := buf.String()
	if strings.Contains(out, `"level":"error"`) || strings.Contains(out, "stacktrace") {
		t.Fatalf("noisy log for missing cookie: %s", out)
	}
	if !strings.Contains(out, `"msg":"api-start"`) || !strings.Contains(out, `"msg":"api-end"`) || !strings.Contains(out, `"status":401`) {
		t.Fatalf("access log pair missing: %s", out)
	}
}
