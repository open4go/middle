package middle

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
)

func TestAuthErrorBodies(t *testing.T) {
	gin.SetMode(gin.TestMode)
	cases := []struct {
		abort func(*gin.Context)
		code  int
		want  string
	}{
		{AbortSessionExpired, http.StatusUnauthorized, CodeSessionExpired},
		{AbortPermissionDenied, http.StatusForbidden, CodePermissionDenied},
		{AbortPermissionUnavailable, http.StatusServiceUnavailable, CodePermissionUnavailable},
	}
	for _, tc := range cases {
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		tc.abort(c)
		if w.Code != tc.code || !c.IsAborted() {
			t.Fatalf("%s: code=%d aborted=%v", tc.want, w.Code, c.IsAborted())
		}
		var body map[string]string
		if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil || body["code"] != tc.want || body["message"] == "" {
			t.Fatalf("%s: body=%q", tc.want, w.Body.String())
		}
	}
}
