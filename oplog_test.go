package middle

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
)

func TestClassifyResourceMemberFirst(t *testing.T) {
	res, name := ClassifyResource("/v1/hlj/member/account/:_id")
	if res != "member" || name != "会员中心 · 会员账户" {
		t.Fatalf("got %s %s", res, name)
	}
	res, name = ClassifyResource("/v1/system/auth/account")
	if res != "admin_account" || name != "权限管理 · 账号" {
		t.Fatalf("got %s %s", res, name)
	}
	res, name = ClassifyResource("/v1/system/password/:_id")
	if res != "password" || name != "权限管理 · 密码" {
		t.Fatalf("got %s %s", res, name)
	}
}

func TestActionFromMethod(t *testing.T) {
	if ActionFromMethod(http.MethodPost) != "create" {
		t.Fatal("post")
	}
	if ActionFromMethod(http.MethodPut) != "update" {
		t.Fatal("put")
	}
	if ActionFromMethod(http.MethodDelete) != "delete" {
		t.Fatal("delete")
	}
}

func TestMerchantFromBefore(t *testing.T) {
	got := merchantFromBefore(`{"_":{"merchant_id":"tenant-a","namespace":"hlj"},"name":"demo"}`)
	if got != "tenant-a" {
		t.Fatalf("got %s", got)
	}
	if merchantFromBefore(`{"_":{"merchant_id":"*"}}`) != "" {
		t.Fatal("skip *")
	}
	if merchantFromBefore("") != "" {
		t.Fatal("empty")
	}
}

func TestClassifyResourceStoreInfo(t *testing.T) {
	res, name := ClassifyResource("/v1/hlj/store/info")
	if res != "store" || name != "门店管理 · 门店信息" {
		t.Fatalf("got %s %s", res, name)
	}
}

func TestClassifyPathServiceAndModule(t *testing.T) {
	cases := []struct {
		path     string
		service  string
		module   string
		resource string
	}{
		{"/v1/hlj/client/launch", "client", "launch", "client"},
		{"/v1/hlj/client/launch/:_id", "client", "launch", "client"},
		{"/v1/hlj/client/theme/asset/generate", "client", "theme", "client"},
		{"/v1/hlj/client/notify", "client", "notification", "client"},
		{"/v1/hlj/client/mp-dist", "client", "mp", "client"},
		{"/v1/hlj/member/account/:_id", "member", "account", "member"},
		{"/v1/hlj/member/addresses", "member", "addresses", "member_address"},
		{"/v1/hlj/member/address", "member", "addresses", "member_address"},
		{"/v1/hlj/member/level", "member", "level", "member_level"},
		{"/v1/system/auth/account", "auth", "account", "admin_account"},
		{"/v1/system/auth/plan", "auth", "plan", "plan"},
		{"/v1/system/auth/billing", "auth", "billing", "billing"},
		{"/v1/system/auth/partner", "auth", "partner", "partner"},
		{"/v1/system/auth/role", "auth", "role", "role"},
		{"/v1/system/password/:_id", "auth", "password", "password"},
		{"/v1/hlj/store/info", "store", "info", "store"},
		{"/v1/hlj/product/categories", "product", "categories", "product"},
		{"/v1/hlj/product/menu", "product", "menu", "product"},
		{"/v1/hlj/scm/material", "scm", "material", "scm"},
		{"/v1/hlj/scm/categories", "scm", "categories", "scm"},
		{"/v1/hlj/active/campaign", "active", "campaign", "campaign"},
		{"/v1/hlj/active/ticket", "active", "ticket", "campaign"},
		{"/v1/hlj/order/commands", "order", "commands", "order"},
		{"/v1/hlj/order/place", "order", "place", "order"},
		{"/v1/hlj/finance/keys", "finance", "keys", "finance"},
		{"/v1/hlj/finance/shift", "finance", "shift", "finance"},
		{"/v1/hlj/device/printer", "device", "printer", "device"},
		{"/v1/hlj/device/pos/printer", "device", "printer", "device"},
		{"/v1/hlj/feedback/reviews", "feedback", "reviews", "feedback"},
		{"/v1/hlj/feedback/bounty", "feedback", "bounty", "feedback"},
		{"/v1/hlj/transport/orders", "transport", "orders", "transport"},
		{"/v1/hlj/transport/addresses", "transport", "addresses", "transport"},
		{"/v1/system/fs/client/image", "fs", "image", "image"},
		{"/v1/system/fs/image", "fs", "image", "image"},
		{"/v1/pay/scan", "pay", "scan", "pay"},
		{"/v1/pay/cash", "pay", "cash", "pay"},
		{"/v1/hlj/merchant/info", "merchant", "info", "merchant"},
	}
	for _, tc := range cases {
		got := ClassifyPath(tc.path)
		if got.Service != tc.service || got.Module != tc.module || got.Resource != tc.resource {
			t.Fatalf("%s: got service=%s module=%s resource=%s label=%s", tc.path, got.Service, got.Module, got.Resource, got.Label)
		}
		if got.Resource == "other" || got.Label == "其他" {
			t.Fatalf("%s classified as other", tc.path)
		}
	}
	launch := ClassifyPath("/v1/hlj/client/launch")
	if launch.Label != "终端管理 · 启动配置" {
		t.Fatalf("label %s", launch.Label)
	}
	if other := ClassifyPath("/not/a/route"); other.Resource != "other" {
		t.Fatalf("unknown %s", other.Resource)
	}
}

func TestActionFromRequest(t *testing.T) {
	if ActionFromRequest(http.MethodPost, "/v1/hlj/member/account/send/:_id", "") != "notify" {
		t.Fatal("send")
	}
	if ActionFromRequest(http.MethodPut, "/v1/hlj/member/account/:_id", "ts=1") != "transfer" {
		t.Fatal("transfer")
	}
	if ActionFromRequest(http.MethodPost, "/v1/hlj/member/account", "") != "create" {
		t.Fatal("create")
	}
}

func TestBuildOperationSummary(t *testing.T) {
	got := BuildOperationSummary("张三", "update", "会员", "66abcdef0123456789", "")
	if got != "张三 更新了 会员 66abcdef…" {
		t.Fatalf("got %q", got)
	}
	got = BuildOperationSummary("张三", "update", "会员", "66abcdef0123456789", "李四")
	if got != "张三 更新了 会员 李四" {
		t.Fatalf("got %q", got)
	}
}

func TestRedactJSON(t *testing.T) {
	raw := []byte(`{"name":"李四","password":"secret","nested":{"token":"abc"},"sms_code":"123456"}`)
	out := RedactJSON(raw)
	var m map[string]interface{}
	if err := json.Unmarshal([]byte(out), &m); err != nil {
		t.Fatal(err)
	}
	if m["name"] != "李四" || m["password"] != "***" || m["sms_code"] != "***" {
		t.Fatalf("got %v", m)
	}
	nested := m["nested"].(map[string]interface{})
	if nested["token"] != "***" {
		t.Fatalf("nested %v", nested)
	}
}

func TestSkipRequestBodyCaptureMultipart(t *testing.T) {
	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	body := strings.Repeat("x", 64)
	c.Request = httptest.NewRequest(http.MethodPost, "/v1/system/fs/client/image", strings.NewReader(body))
	c.Request.Header.Set("Content-Type", "multipart/form-data; boundary=----x")
	c.Request.ContentLength = int64(len(body))
	if !skipRequestBodyCapture(c) {
		t.Fatal("multipart must not be captured")
	}
	if got := readRequestBody(c); got != nil {
		t.Fatalf("must not consume upload body, got %d bytes", len(got))
	}
	rest, err := io.ReadAll(c.Request.Body)
	if err != nil {
		t.Fatal(err)
	}
	if string(rest) != body {
		t.Fatal("upload body was drained")
	}
}

func TestExtractBodyFields(t *testing.T) {
	got := extractBodyFields([]byte(`{"name":"李四","phone":"13800138000","password":"x"}`))
	if got.Name != "李四" || got.Phone != "13800138000" {
		t.Fatalf("got %+v", got)
	}

	got = extractBodyFields([]byte(`{"identity":{"nickname":"王五","phone":"13900139000"},"id":"66ab"}`))
	if got.Name != "王五" || got.Phone != "13900139000" || got.ID != "66ab" {
		t.Fatalf("nested %+v", got)
	}

	got = extractBodyFields([]byte(`name=赵六&phone=13700137000&account_id=acc1`))
	if got.Name != "赵六" || got.Phone != "13700137000" || got.AccountID != "acc1" {
		t.Fatalf("form %+v", got)
	}
}

func TestResolveTarget(t *testing.T) {
	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodPut, "/v1/hlj/member/account/abc?id=from-query", nil)
	c.Params = gin.Params{{Key: "_id", Value: "path-id"}}
	c.Writer.Header().Set("TargetId", "header-id")

	id, name := resolveTarget(c, bodyFields{ID: "body-id", Name: "李四"})
	if id != "path-id" {
		t.Fatalf("path id preferred, got %q", id)
	}
	if name != "李四" {
		t.Fatalf("name %q", name)
	}

	w = httptest.NewRecorder()
	c, _ = gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodPost, "/v1/hlj/member/account", nil)
	id, name = resolveTarget(c, bodyFields{ID: "body-id", Name: "李四", Phone: "13800138000"})
	if id != "body-id" || name != "李四" {
		t.Fatalf("body fallback id=%q name=%q", id, name)
	}
}

func TestLoginLogType(t *testing.T) {
	if loginLogType("/v1/system/auth/signin", "/v1/system/auth/signin") != "signin" {
		t.Fatal("signin")
	}
	if loginLogType("/v1/system/auth/signout", "") != "signout" {
		t.Fatal("signout")
	}
	if loginLogType("/v1/system/auth/otp/verify", "") != "otp" {
		t.Fatal("otp")
	}
}

func TestParseAccessLevel(t *testing.T) {
	if parseAccessLevel("3") != 3 {
		t.Fatal("3")
	}
	if parseAccessLevel("") != 0 {
		t.Fatal("empty")
	}
}
