package middle

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/spf13/viper"
)

func testGinCtx() *gin.Context {
	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodPost, "/v1/system/fs/client/image", nil)
	return c
}

func TestCheckQuotaRemoteDeny(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(quotaCheckBody{Allowed: false, Message: "已超出套餐额度：图片"})
	}))
	defer srv.Close()
	viper.Set("usage.check_url", srv.URL)
	defer viper.Set("usage.check_url", "")

	ok, msg := checkQuotaRemote(testGinCtx(), "m1", KindImage, 10)
	if ok || msg == "" {
		t.Fatalf("want deny, got ok=%v msg=%s", ok, msg)
	}
}

func TestCheckQuotaRemoteFailOpen(t *testing.T) {
	viper.Set("usage.check_url", "http://127.0.0.1:1/nope")
	defer viper.Set("usage.check_url", "")
	ok, _ := checkQuotaRemote(testGinCtx(), "m1", KindImage, 10)
	if !ok {
		t.Fatal("network error should fail open")
	}
}

func TestAllowQuotaOrAbortHTTPStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(quotaCheckBody{Allowed: false, Message: "已超出套餐额度：图片"})
	}))
	defer srv.Close()
	viper.Set("usage.check_url", srv.URL)
	defer viper.Set("usage.check_url", "")

	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodPost, "/v1/system/fs/client/image", nil)
	c.Request.Header.Set("X-Merchant-ID", "m1")

	if allowQuotaOrAbort(c) {
		t.Fatal("quota exceeded should abort")
	}
	if w.Code != StatusQuotaExceeded {
		t.Fatalf("want HTTP %d, got %d body=%s", StatusQuotaExceeded, w.Code, w.Body.String())
	}
	var body map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body["error"] != "quota_exceeded" {
		t.Fatalf("error field: %v", body["error"])
	}
	if int(body["code"].(float64)) != StatusQuotaExceeded {
		t.Fatalf("json code: %v", body["code"])
	}
}
