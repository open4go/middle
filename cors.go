package middle

import (
	"context"
	"encoding/hex"
	"github.com/gin-gonic/gin"
	"math/rand"
)

// CORSMiddleware 跨站请求
func CORSMiddleware(host string) gin.HandlerFunc {
	return func(c *gin.Context) {
		// 跨站请求必要的header
		c.Writer.Header().Set("Access-Control-Allow-Origin", host)
		c.Writer.Header().Set("Access-Control-Allow-Credentials", "true")
		c.Writer.Header().Set("Access-Control-Allow-Headers", "Content-Type, Content-Length, Accept-Encoding, X-CSRF-Token, Authorization, accept, origin, Cache-Control, X-Requested-With, Merchant-Id, jwt, User-Id, Content-Range, X-Total-Count, Token")
		c.Writer.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS, GET, PUT, DELETE")
		c.Writer.Header().Set("Access-Control-Expose-Headers", "Content-Range,X-Total-Count")

		// 添加必要的信息便于日志追踪
		traceID := generateTraceID()
		ctx := context.WithValue(c.Request.Context(), "traceid", traceID)
		ip := c.ClientIP()
		ctx = context.WithValue(ctx, "ip", ip)

		// 更新请求上下文
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
