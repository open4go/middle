package middle

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
)

func TestUsageFromOperation(t *testing.T) {
	_, ok := UsageFromOperation("image", "create", 500, 100)
	if ok {
		t.Fatal("failed request should skip")
	}
	_, ok = UsageFromOperation("image", "update", 200, 100)
	if ok {
		t.Fatal("update should skip")
	}
	ev, ok := UsageFromOperation("image", "create", 200, 2048)
	if !ok || ev.Kind != KindImage || ev.Delta != 1 || ev.Bytes != 2048 {
		t.Fatalf("%+v", ev)
	}
	ev, ok = UsageFromOperation("image", "delete", 200, 4096)
	if !ok || ev.Kind != KindImage || ev.Delta != -1 || ev.Bytes != 4096 {
		t.Fatalf("image delete %+v", ev)
	}
	ev, ok = UsageFromOperation("image", "delete", 200, 0)
	if !ok || ev.Delta != -1 || ev.Bytes != 0 {
		t.Fatalf("image delete without size %+v", ev)
	}
	ev, ok = UsageFromOperation("product", "delete", 200, 0)
	if !ok || ev.Kind != KindProduct || ev.Delta != -1 {
		t.Fatalf("%+v", ev)
	}
	_, ok = UsageFromOperation("role", "create", 200, 0)
	if ok {
		t.Fatal("role is not occupancy")
	}
	ev, ok = UsageFromOperation("scm", "create", 200, 0)
	if !ok || ev.Kind != KindScm || ev.Delta != 1 {
		t.Fatalf("scm %+v", ev)
	}
}

func TestClassifyResourceImage(t *testing.T) {
	res, name := ClassifyResource("/v1/system/fs/client/image")
	if res != "image" || name != "图片" {
		t.Fatalf("%s %s", res, name)
	}
	res, _ = ClassifyResource("/v1/system/fs/image")
	if res != "image" {
		t.Fatalf("admin image %s", res)
	}
	res, name = ClassifyResource("/v1/hlj/scm/material")
	if res != "scm" || name != "供应链" {
		t.Fatalf("scm %s %s", res, name)
	}
	res, _ = ClassifyResource("/v1/hlj/active/campaign")
	if res != "campaign" {
		t.Fatalf("campaign %s", res)
	}
	res, _ = ClassifyResource("/v1/hlj/device/printer")
	if res != "device" {
		t.Fatalf("device %s", res)
	}
	res, _ = ClassifyResource("/v1/hlj/client/launch")
	if res != "client" {
		t.Fatalf("client %s", res)
	}
}

func TestSizeFromJSON(t *testing.T) {
	if got := sizeFromJSON(`{"name":"a.png","size":4096}`); got != 4096 {
		t.Fatalf("size %d", got)
	}
	if got := sizeFromJSON(`{"Size":2048}`); got != 2048 {
		t.Fatalf("Size %d", got)
	}
	if got := sizeFromJSON(""); got != 0 {
		t.Fatalf("empty %d", got)
	}
}

func TestUsageBytesPrefersContext(t *testing.T) {
	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodDelete, "/v1/system/fs/image/1", nil)
	SetUsageBytes(c, 8192)
	if got := usageBytes(c, `{"size":4096}`, 100); got != 8192 {
		t.Fatalf("context %d", got)
	}
	c2, _ := gin.CreateTestContext(w)
	c2.Request = httptest.NewRequest(http.MethodDelete, "/v1/system/fs/image/1", nil)
	if got := usageBytes(c2, `{"size":4096}`, 0); got != 4096 {
		t.Fatalf("before %d", got)
	}
}

func TestEnqueueUsageDropsWhenUninitialized(t *testing.T) {
	EnqueueUsage(UsageEvent{MerchantID: "m1", Kind: KindImage, Delta: 1})
}

func TestSkipUsageMerchant(t *testing.T) {
	if !skipUsageMerchant("") || !skipUsageMerchant("*") || !skipUsageMerchant("share") {
		t.Fatal("should skip")
	}
	if skipUsageMerchant("abc") {
		t.Fatal("tenant should count")
	}
}
