package middle

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
)

func TestClassifyResourceMemberFirst(t *testing.T) {
	res, name := ClassifyResource("/v1/hlj/member/account/:_id")
	if res != "member" || name != "会员" {
		t.Fatalf("got %s %s", res, name)
	}
	res, name = ClassifyResource("/v1/system/auth/account")
	if res != "admin_account" || name != "管理账号" {
		t.Fatalf("got %s %s", res, name)
	}
	res, name = ClassifyResource("/v1/system/password/:_id")
	if res != "password" || name != "密码" {
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
