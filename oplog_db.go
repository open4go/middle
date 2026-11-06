package middle

import (
	"context"

	"github.com/gin-gonic/gin"
	r2mongo "github.com/open4go/db/mongo"
	"github.com/open4go/log"
	"go.mongodb.org/mongo-driver/mongo"
)

// MustOplogDB returns the named mongo database from the shared pool, or nil
// when the pool is unavailable. Callers typically pass "sys_auth" for operate-log
// and "f9z" (or the service DB name) for Snapshot. Replaces duplicated
// route/oplog.go authLogDB helpers across API repos.
func MustOplogDB(name string) *mongo.Database {
	if r2mongo.DBPool == nil {
		return nil
	}
	h, err := r2mongo.DBPool.GetHandler(name)
	if err != nil {
		log.Log(context.Background()).WithError(err).WithField("db", name).
			Error("operate-log mongo unavailable")
		return nil
	}
	return h
}

// OperateLogOrNoop returns OperateLogMiddleware when MustOplogDB(dbName) succeeds,
// otherwise a pass-through handler (same behaviour as the old route/oplog.go boilerplate).
func OperateLogOrNoop(dbName string) gin.HandlerFunc {
	db := MustOplogDB(dbName)
	if db == nil {
		return func(c *gin.Context) { c.Next() }
	}
	return OperateLogMiddleware(db)
}
