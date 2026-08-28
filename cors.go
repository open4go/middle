package middle

import (
	"context"
	"encoding/hex"
	"math/rand"

	"github.com/gin-gonic/gin"
	"github.com/open4go/model"
)

// CORSMiddleware 跨站请求
func CORSMiddleware(host string) gin.HandlerFunc {
	return func(c *gin.Context) {
		// 跨站请求必要的header
		c.Writer.Header().Set("Access-Control-Allow-Origin", host)
		c.Writer.Header().Set("Access-Control-Allow-Credentials", "true")
		c.Writer.Header().Set("Access-Control-Allow-Headers", "Content-Type, Content-Length, Accept-Encoding, X-CSRF-Token, Authorization, accept, origin, Cache-Control, X-Requested-With, Merchant-Id, X-Merchant-ID, X-Tenant-ID, jwt, User-Id, Content-Range, X-Total-Count, Token")
		c.Writer.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS, GET, PUT, DELETE")
		c.Writer.Header().Set("Access-Control-Expose-Headers", "Content-Range,X-Total-Count")

		// Reuse TraceMiddleware RequestID when present so logs and error bodies share one id.
		traceID := generateTraceID()
		if existing, ok := c.Get("RequestID"); ok {
			if s, ok := existing.(string); ok && s != "" {
				traceID = s
			}
		}
		ctx := context.WithValue(c.Request.Context(), "traceid", traceID)
		ip := c.ClientIP()
		ctx = context.WithValue(ctx, "ip", ip)

		if c.Request.Method != "OPTIONS" && isSuperAdminHost(requestAdminHost(c)) {
			ctx = context.WithValue(ctx, model.NamespaceKey, "*")
		}

		c.Request = c.Request.WithContext(ctx)

		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(204)
			return
		}

		c.Next()
	}
}

func generateTraceID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return ""
	}
	return hex.EncodeToString(b)
}
