package middle

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
)

func TestUUMD5SignVector(t *testing.T) {
	params := map[string]string{
		"origin_id": "o1",
		"state":     "10",
		"sign":      "ignore",
	}
	payload := CanonicalSortedKV(params, "sign")
	sig := UUMD5Sign(payload, "sys-key")
	params["sign"] = sig
	if !VerifyUUMD5(params, "sys-key") {
		t.Fatal("expected ok")
	}
	if VerifyUUMD5(params, "wrong") {
		t.Fatal("wrong key")
	}
	delete(params, "sign")
	if VerifyUUMD5(params, "sys-key") {
		t.Fatal("missing sign")
	}
}

func TestCallbackAuthRejectsBadSign(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.POST("/cb", CallbackAuth(StaticUUMD5Verifier{Keys: []string{"sys-key"}}, WithCallbackReject(UURejectWriter)), func(c *gin.Context) {
		c.JSON(200, gin.H{"return_code": "ok"})
	})

	// unsigned
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/cb", strings.NewReader("origin_id=o1&state=10"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("unsigned code=%d body=%s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "invalid sign") {
		t.Fatalf("body=%s", w.Body.String())
	}

	// valid
	params := map[string]string{"origin_id": "o1", "state": "10"}
	payload := CanonicalSortedKV(params, "sign")
	sig := UUMD5Sign(payload, "sys-key")
	form := url.Values{"origin_id": {"o1"}, "state": {"10"}, "sign": {sig}}
	w2 := httptest.NewRecorder()
	req2 := httptest.NewRequest(http.MethodPost, "/cb", strings.NewReader(form.Encode()))
	req2.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.ServeHTTP(w2, req2)
	if w2.Code != 200 {
		t.Fatalf("signed code=%d body=%s", w2.Code, w2.Body.String())
	}
}

func TestFuncVerifier(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.POST("/x", CallbackAuth(FuncVerifier{Provider: "lakala", Fn: func(c *gin.Context) error {
		return ErrInvalidCallbackSign
	}}), func(c *gin.Context) { c.Status(200) })
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/x", nil))
	if w.Code != 401 {
		t.Fatalf("code=%d", w.Code)
	}
}
