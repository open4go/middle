package middle

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/pquerna/otp/totp"
)

var testKey = []byte("unit-test-signing-key")

func signLogin(t *testing.T, key []byte, method jwt.SigningMethod, issuer string) string {
	t.Helper()
	claims := jwt.RegisteredClaims{
		Issuer:    issuer,
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
	}
	tok := jwt.NewWithClaims(method, claims)
	s, err := tok.SignedString(key)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func newJWTEngine(mw ...gin.HandlerFunc) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.GET("/x", append(mw, func(c *gin.Context) {
		c.String(http.StatusOK, VerifiedUserID(c))
	})...)
	return r
}

func doCookie(r http.Handler, cookie string, hdr map[string]string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, "/x", nil)
	if cookie != "" {
		req.AddCookie(&http.Cookie{Name: "jwt", Value: cookie})
	}
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w
}

func TestDumpDoesNotEmbedOTPSecret(t *testing.T) {
	l := LoginInfo{AccountID: "a1", UserID: "u1", OPTSecret: "JBSWY3DPEHPK3PXP"}
	for _, enc := range []string{
		DumpLoginInfo(l),
		func() string { s, _ := l.Dump("m", "u1", "", "", "", "", "a1", "", "JBSWY3DPEHPK3PXP"); return s }(),
	} {
		raw, err := base64.StdEncoding.DecodeString(enc)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(raw), "JBSWY3DPEHPK3PXP") {
			t.Fatalf("otp secret leaked into token payload: %s", raw)
		}
		var m map[string]interface{}
		_ = json.Unmarshal(raw, &m)
		if _, ok := m["os"]; ok {
			t.Fatalf("payload still carries os field: %s", raw)
		}
	}
}

func TestLoadIgnoresLegacyOTPSecret(t *testing.T) {
	payload := base64.StdEncoding.EncodeToString([]byte(`{"uid":"u1","os":"LEGACY"}`))
	var l LoginInfo
	if err := l.Load(payload); err != nil {
		t.Fatal(err)
	}
	if l.OPTSecret != "" {
		t.Fatalf("Load must not take OTP secret from token, got %q", l.OPTSecret)
	}
}

func TestJWTMiddlewareValidToken(t *testing.T) {
	setSuperDomain(t, "")
	r := newJWTEngine(JWTMiddleware(testKey))
	tok := signLogin(t, testKey, jwt.SigningMethodHS256, DumpLoginInfo(LoginInfo{UserID: "u-42", MerchantID: "m1"}))
	w := doCookie(r, tok, map[string]string{"UserID": "spoofed"})
	if w.Code != http.StatusOK {
		t.Fatalf("code=%d", w.Code)
	}
	if w.Body.String() != "u-42" {
		t.Fatalf("verified user id=%q want u-42", w.Body.String())
	}
}

func TestJWTMiddlewareRejects(t *testing.T) {
	r := newJWTEngine(JWTMiddleware(testKey))
	issuer := DumpLoginInfo(LoginInfo{UserID: "u-1"})

	none, err := jwt.NewWithClaims(jwt.SigningMethodNone, jwt.RegisteredClaims{Issuer: issuer}).
		SignedString(jwt.UnsafeAllowNoneSignatureType)
	if err != nil {
		t.Fatal(err)
	}
	expired, _ := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.RegisteredClaims{
		Issuer: issuer, ExpiresAt: jwt.NewNumericDate(time.Now().Add(-time.Hour)),
	}).SignedString(testKey)

	cases := map[string]string{
		"missing":   "",
		"wrong key": signLogin(t, []byte("other"), jwt.SigningMethodHS256, issuer),
		"alg none":  none,
		"expired":   expired,
		"garbage":   "abc.def.ghi",
	}
	for name, tok := range cases {
		w := doCookie(r, tok, nil)
		if w.Code != http.StatusUnauthorized {
			t.Errorf("%s: code=%d want 401", name, w.Code)
		}
	}
}

func TestVerifiedUserIDEmptyWithoutJWT(t *testing.T) {
	r := newJWTEngine(MerchantBindMiddleware(testKey))
	w := doCookie(r, "", map[string]string{"UserID": "spoofed"})
	if w.Body.String() != "" {
		t.Fatalf("MerchantBindMiddleware must not mark identity verified, got %q", w.Body.String())
	}
}

func TestSecondValidateUsesServerSideSecret(t *testing.T) {
	const secret = "JBSWY3DPEHPK3PXP"
	SetOTPSecretResolver(func(ctx context.Context, l *LoginInfo) (string, error) {
		if l.AccountID == "acc-1" {
			return secret, nil
		}
		return "", ErrOTPSecretNotFound
	})
	t.Cleanup(func() { SetOTPSecretResolver(nil) })
	setViper(t, cfgOTPAllowLegacyJWT, false)

	r := newJWTEngine(SecondValidateMiddleware(testKey))
	code, err := totp.GenerateCode(secret, time.Now())
	if err != nil {
		t.Fatal(err)
	}

	ok := signLogin(t, testKey, jwt.SigningMethodHS256, DumpLoginInfo(LoginInfo{AccountID: "acc-1", UserID: "u1"}))
	if w := doCookie(r, ok, map[string]string{"X-TOTP-Code": code}); w.Code != http.StatusOK {
		t.Fatalf("valid code: %d", w.Code)
	}
	if w := doCookie(r, ok, map[string]string{"X-TOTP-Code": "000000"}); w.Code != http.StatusForbidden && code != "000000" {
		t.Fatalf("wrong code: %d", w.Code)
	}

	// A token for another account carrying its own (attacker-chosen) secret must fail.
	attackerSecret := "KRSXG5CTMVRXEZLU"
	legacy := base64.StdEncoding.EncodeToString([]byte(`{"aid":"acc-2","uid":"u2","os":"` + attackerSecret + `"}`))
	tok := signLogin(t, testKey, jwt.SigningMethodHS256, legacy)
	acode, _ := totp.GenerateCode(attackerSecret, time.Now())
	if w := doCookie(r, tok, map[string]string{"X-TOTP-Code": acode}); w.Code != http.StatusForbidden {
		t.Fatalf("token-carried secret must not be accepted by default: %d", w.Code)
	}

	// Migration switch re-enables the legacy field explicitly.
	setViper(t, cfgOTPAllowLegacyJWT, true)
	if w := doCookie(r, tok, map[string]string{"X-TOTP-Code": acode}); w.Code != http.StatusOK {
		t.Fatalf("legacy switch on: %d", w.Code)
	}
}
