package middle

import (
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/open4go/log"
	"github.com/sirupsen/logrus"
)

// TraceMiddleware 日志追踪
func TraceMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {

		// Generate a UUID for the request ID
		requestID := uuid.New().String()

		// Set the request ID in the request context for later use
		c.Set("RequestID", requestID)

		// Pass the request ID in the response headers
		c.Header("X-Request-ID", requestID)

		// Set the request ID in the Logrus logger's fields
		logger := log.Log(c.Request.Context()).WithFields(
			logrus.Fields{"request_id": requestID})
		c.Set("log", logger)

		c.Next()
	}
}
