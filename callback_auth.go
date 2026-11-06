package middle

import (
	"crypto/md5"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/open4go/log"
)

// CallbackVerifier verifies a platform callback (UU / WeChat / Lakala / custom).
// Return nil to allow the request; non-nil rejects with 401 unless a custom
// Reject writer is configured via CallbackAuthOption.
type CallbackVerifier interface {
	// Name is a short provider id for logs (uu, wechat, lakala, …).
	Name() string
	// Verify inspects the request (headers/body/form). Must not consume the
	// body unless it restores c.Request.Body for downstream handlers.
	Verify(c *gin.Context) error
}

// CallbackRejectWriter customises the 401 response body (UU returns return_code etc.).
type CallbackRejectWriter func(c *gin.Context, provider string, err error)

// CallbackAuthOption configures CallbackAuth.
type CallbackAuthOption func(*callbackAuthCfg)

type callbackAuthCfg struct {
	reject CallbackRejectWriter
}

// WithCallbackReject sets a custom reject response writer.
func WithCallbackReject(w CallbackRejectWriter) CallbackAuthOption {
	return func(cfg *callbackAuthCfg) { cfg.reject = w }
}

// ErrInvalidCallbackSign is the sentinel for bad/missing signatures.
var ErrInvalidCallbackSign = errors.New("invalid sign")

// CallbackAuth runs verifier before the handler. On failure it logs
// callback.verify and aborts with HTTP 401 (preserving P0/P1 behaviour).
func CallbackAuth(v CallbackVerifier, opts ...CallbackAuthOption) gin.HandlerFunc {
	cfg := &callbackAuthCfg{
		reject: defaultCallbackReject,
	}
	for _, o := range opts {
		if o != nil {
			o(cfg)
		}
	}
	name := "callback"
	if v != nil {
		name = v.Name()
	}
	return func(c *gin.Context) {
		if v == nil {
			log.Log(c.Request.Context()).WithField("provider", name).
				WithField("event", "callback.verify").Warning("nil verifier")
			cfg.reject(c, name, ErrInvalidCallbackSign)
			return
		}
		if err := v.Verify(c); err != nil {
			log.Log(c.Request.Context()).WithField("provider", name).
				WithField("event", "callback.verify").WithField("ok", false).
				WithField("reason", err.Error()).Warning("callback sign rejected")
			cfg.reject(c, name, err)
			return
		}
		log.Log(c.Request.Context()).WithField("provider", name).
			WithField("event", "callback.verify").WithField("ok", true).Debug("callback verified")
		c.Next()
	}
}

func defaultCallbackReject(c *gin.Context, provider string, err error) {
	msg := "unauthorized"
	if err != nil {
		msg = err.Error()
	}
	c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
		"error":    msg,
		"provider": provider,
	})
}

// UURejectWriter matches transport-api UU callback JSON (return_code / return_msg).
func UURejectWriter(c *gin.Context, _ string, _ error) {
	c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
		"return_code": "fail",
		"return_msg":  "invalid sign",
	})
}

// ----- UU-style sorted MD5 sign helpers (plugin building block) -----

// CanonicalSortedKV builds k=v&k=v… from params, skipping empty values and skipKeys.
func CanonicalSortedKV(params map[string]string, skipKeys ...string) string {
	skip := map[string]struct{}{}
	for _, k := range skipKeys {
		skip[strings.ToLower(k)] = struct{}{}
	}
	keys := make([]string, 0, len(params))
	for k, v := range params {
		if _, ok := skip[strings.ToLower(k)]; ok {
			continue
		}
		if strings.TrimSpace(v) == "" {
			continue
		}
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, fmt.Sprintf("%s=%s", k, params[k]))
	}
	return strings.Join(parts, "&")
}

// UUMD5Sign implements UU open-platform sign: MD5(upper(payload + "&key=" + key)).upper.
func UUMD5Sign(payload, key string) string {
	raw := strings.ToUpper(payload + "&key=" + key)
	sum := md5.Sum([]byte(raw))
	return strings.ToUpper(hex.EncodeToString(sum[:]))
}

// SignEqualConstantTime compares hex/sign strings case-insensitively.
func SignEqualConstantTime(got, want string) bool {
	got = strings.ToUpper(strings.TrimSpace(got))
	want = strings.ToUpper(strings.TrimSpace(want))
	if got == "" || want == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(got), []byte(want)) == 1
}

// VerifyUUMD5 checks params["sign"] against candidate keys using UU MD5 rules.
func VerifyUUMD5(params map[string]string, keys ...string) bool {
	got, ok := params["sign"]
	if !ok || strings.TrimSpace(got) == "" {
		return false
	}
	payload := CanonicalSortedKV(params, "sign")
	if payload == "" {
		return false
	}
	seen := map[string]struct{}{}
	for _, key := range keys {
		key = strings.TrimSpace(key)
		if key == "" {
			continue
		}
		if _, dup := seen[key]; dup {
			continue
		}
		seen[key] = struct{}{}
		if SignEqualConstantTime(got, UUMD5Sign(payload, key)) {
			return true
		}
	}
	return false
}

// FuncVerifier adapts a function to CallbackVerifier.
type FuncVerifier struct {
	Provider string
	Fn       func(c *gin.Context) error
}

// Name implements CallbackVerifier.
func (f FuncVerifier) Name() string {
	if f.Provider == "" {
		return "func"
	}
	return f.Provider
}

// Verify implements CallbackVerifier.
func (f FuncVerifier) Verify(c *gin.Context) error {
	if f.Fn == nil {
		return ErrInvalidCallbackSign
	}
	return f.Fn(c)
}

// StaticUUMD5Verifier verifies UU form/json params with fixed candidate keys.
// Params are taken from c.Request.Form (ParseForm) plus query "sign".
type StaticUUMD5Verifier struct {
	Keys []string
}

// Name implements CallbackVerifier.
func (StaticUUMD5Verifier) Name() string { return "uu" }

// Verify implements CallbackVerifier.
func (v StaticUUMD5Verifier) Verify(c *gin.Context) error {
	_ = c.Request.ParseForm()
	params := map[string]string{}
	for k, vs := range c.Request.Form {
		if len(vs) == 0 {
			continue
		}
		if val := strings.TrimSpace(vs[0]); val != "" {
			params[k] = val
		}
	}
	if _, ok := params["sign"]; !ok {
		if s := strings.TrimSpace(c.Query("sign")); s != "" {
			params["sign"] = s
		}
	}
	if !VerifyUUMD5(params, v.Keys...) {
		return ErrInvalidCallbackSign
	}
	return nil
}
