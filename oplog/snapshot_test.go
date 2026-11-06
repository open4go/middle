package oplog

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
)

func TestRegistryCollectionFor(t *testing.T) {
	r := NewRegistry().
		Register("/products", "product_detail_config").
		Register("/categories", "product_categories_config")
	if got := r.collectionFor("/v1/hlj/products/:_id", "/v1/hlj/products/abc"); got != "product_detail_config" {
		t.Fatalf("got %q", got)
	}
	if got := r.collectionFor("/v1/hlj/categories/:_id", "/v1/hlj/categories/x"); got != "product_categories_config" {
		t.Fatalf("got %q", got)
	}
	if got := r.collectionFor("/other", "/other"); got != "" {
		t.Fatalf("got %q", got)
	}
}

func TestSnapshotNilSafe(t *testing.T) {
	gin.SetMode(gin.TestMode)
	h := Snapshot(nil, NewRegistry())
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodPut, "/x", nil)
	h(c)
}
