// Package oplog provides a shared before-write Snapshot middleware.
// Each API registers path-substring → collection mappings; the load/sanitize
// logic lives here once.
package oplog

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"sync"

	"github.com/gin-gonic/gin"
	"github.com/open4go/log"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
)

const maxSnapshotBytes = 24 * 1024

// Registry maps a lowercase path substring to a mongo collection name.
// First matching substring wins (registration order).
type Registry struct {
	mu   sync.RWMutex
	pairs []pair
}

type pair struct {
	substr string
	coll   string
}

// NewRegistry returns an empty registry.
func NewRegistry() *Registry { return &Registry{} }

// Register adds path-substring → collection. substr is matched with strings.Contains
// against lowercased (FullPath + " " + URL.Path). Empty substr/coll are ignored.
func (r *Registry) Register(substr, coll string) *Registry {
	substr = strings.ToLower(strings.TrimSpace(substr))
	coll = strings.TrimSpace(coll)
	if r == nil || substr == "" || coll == "" {
		return r
	}
	r.mu.Lock()
	r.pairs = append(r.pairs, pair{substr: substr, coll: coll})
	r.mu.Unlock()
	return r
}

// RegisterMap registers many mappings. Map iteration order is random; prefer
// Register in priority order when path substrings may overlap.
func (r *Registry) RegisterMap(m map[string]string) *Registry {
	for k, v := range m {
		r.Register(k, v)
	}
	return r
}

func (r *Registry) collectionFor(fullPath, rawPath string) string {
	if r == nil {
		return ""
	}
	p := strings.ToLower(fullPath + " " + rawPath)
	r.mu.RLock()
	defer r.mu.RUnlock()
	for _, e := range r.pairs {
		if strings.Contains(p, e.substr) {
			return e.coll
		}
	}
	return ""
}

// Snapshot returns middleware that loads the prior document into gin keys
// "Before" / "OldData" for OperateLogMiddleware. db may be nil (no-op).
func Snapshot(db *mongo.Database, reg *Registry) gin.HandlerFunc {
	if db == nil || reg == nil {
		return func(c *gin.Context) { c.Next() }
	}
	return func(c *gin.Context) {
		method := c.Request.Method
		if method == http.MethodPut || method == http.MethodPatch || method == http.MethodDelete {
			if raw := loadBefore(c, db, reg); raw != "" {
				c.Set("Before", raw)
				c.Set("OldData", raw)
			}
		}
		c.Next()
	}
}

func loadBefore(c *gin.Context, db *mongo.Database, reg *Registry) string {
	if db == nil || c == nil || reg == nil {
		return ""
	}
	id := strings.TrimSpace(c.Param("_id"))
	if id == "" {
		id = strings.TrimSpace(c.Param("id"))
	}
	if id == "" {
		return ""
	}
	if _, err := primitive.ObjectIDFromHex(id); err != nil {
		return ""
	}
	collName := reg.collectionFor(c.FullPath(), c.Request.URL.Path)
	if collName == "" {
		return ""
	}
	oid, err := primitive.ObjectIDFromHex(id)
	if err != nil {
		return ""
	}
	ctx := c.Request.Context()
	if ctx == nil {
		ctx = context.Background()
	}
	var doc bson.M
	err = db.Collection(collName).FindOne(ctx, bson.M{"_id": oid}).Decode(&doc)
	if err != nil {
		if !errors.Is(err, mongo.ErrNoDocuments) {
			log.Log(ctx).WithError(err).WithField("collection", collName).WithField("id", id).
				Debug("oplog snapshot skipped")
		}
		return ""
	}
	raw, err := json.Marshal(sanitizeDoc(doc))
	if err != nil {
		return ""
	}
	if len(raw) > maxSnapshotBytes {
		raw = raw[:maxSnapshotBytes]
	}
	return string(raw)
}

func sanitizeDoc(doc bson.M) bson.M {
	if doc == nil {
		return doc
	}
	out := bson.M{}
	for k, v := range doc {
		lk := strings.ToLower(k)
		if lk == "context" || lk == "password" || lk == "passwd" {
			continue
		}
		if nested, ok := v.(bson.M); ok {
			out[k] = sanitizeDoc(nested)
			continue
		}
		if nested, ok := v.(map[string]interface{}); ok {
			out[k] = sanitizeDoc(bson.M(nested))
			continue
		}
		out[k] = v
	}
	return out
}
