package middle

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/open4go/model"
)

func TestCORSMiddlewareDoesNotMarkTenantHostAsSuper(t *testing.T) {
	setSuperDomain(t, "")
	gin.SetMode(gin.TestMode)

	var gotNS string
	r := gin.New()
	r.Use(CORSMiddleware("http://localhost:8100"))
	r.GET("/ping", func(c *gin.Context) {
		gotNS = model.GetValueFromCtx(c.Request.Context(), model.NamespaceKey)
		c.Status(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodGet, "http://localhost:8812/ping", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if gotNS != "" {
		t.Fatalf("namespace=%q want empty when super.domain is unset", gotNS)
	}
}

func TestCORSMiddlewareWritesSuperNamespaceOnSuperHost(t *testing.T) {
	setSuperDomain(t, "super.localhost")
	gin.SetMode(gin.TestMode)

	var gotNS, gotTrace string
	r := gin.New()
	r.Use(CORSMiddleware("http://localhost:8100"))
	r.GET("/ping", func(c *gin.Context) {
		gotNS = model.GetValueFromCtx(c.Request.Context(), model.NamespaceKey)
		if v := c.Request.Context().Value("traceid"); v != nil {
			gotTrace, _ = v.(string)
		}
		c.Status(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodGet, "http://super.localhost:8812/ping", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if gotNS != "*" {
		t.Fatalf("namespace=%q want * on super host", gotNS)
	}
	if gotTrace == "" {
		t.Fatal("traceid should be written back onto the request context")
	}
}
