package middle

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestCompressAuditBodiesUpdateStoresDiff(t *testing.T) {
	before := `{"name":"a","level":1,"password":"secret"}`
	after := `{"name":"b","level":1,"password":"secret2"}`
	b, a := CompressAuditBodies("update", before, after)
	if b != "" {
		t.Fatalf("before should be empty, got %q", b)
	}
	changes, ok := ParseAuditDiffAfter(a)
	if !ok {
		t.Fatalf("expected diff envelope: %s", a)
	}
	found := false
	for _, c := range changes {
		if c.Path == "name" && c.Kind == "changed" {
			found = true
		}
		if strings.Contains(strings.ToLower(c.Path), "password") {
			t.Fatalf("password should be skipped: %+v", c)
		}
	}
	if !found {
		t.Fatalf("name change missing: %+v", changes)
	}
}

func TestCompressAuditBodiesCreateSummary(t *testing.T) {
	after := `{"name":"张三","nickname":"z","password":"x","extra":{"deep":true}}`
	b, a := CompressAuditBodies("create", "", after)
	if b != "" {
		t.Fatal("before")
	}
	var m map[string]interface{}
	if err := json.Unmarshal([]byte(a), &m); err != nil {
		t.Fatal(err)
	}
	if m["name"] != "张三" {
		t.Fatalf("name: %v", m["name"])
	}
	if _, ok := m["extra"]; ok {
		t.Fatal("extra should be dropped from summary")
	}
	if m["password"] != nil && m["password"] != "***" {
		t.Fatalf("password leaked: %v", m["password"])
	}
}

func TestCompressAuditBodiesDeleteSummary(t *testing.T) {
	before := `{"id":"abc","name":"gone"}`
	b, a := CompressAuditBodies("delete", before, "")
	if a != "" {
		t.Fatal("after")
	}
	if !strings.Contains(b, "gone") {
		t.Fatalf("summary: %s", b)
	}
}

func TestIsCriticalAudit(t *testing.T) {
	if !IsCriticalAudit("member", "update") {
		t.Fatal("member")
	}
	if !IsCriticalAudit("product", "delete") {
		t.Fatal("delete")
	}
	if IsCriticalAudit("product", "update") {
		t.Fatal("product update not critical")
	}
}
