package middle

import (
	"github.com/gin-gonic/gin"
	"github.com/open4go/log"
)

// TraceMiddleware assigns a request id and writes it into the request
// context so log.Log(ctx) can attach a `trace` field. Prefer inbound
// X-Request-ID / X-Trace-ID when the caller already has one.
//
// Kept as a thin wrapper so existing services that import middle.TraceMiddleware
// pick up the context injection without changing call sites.
func TraceMiddleware() gin.HandlerFunc {
	return log.TraceMiddleware()
}
