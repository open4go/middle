package middle

import (
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
	"os"
)

// Initialize Logrus logger
var logger = logrus.New()

func InitLogger(logLevel string) {
	// 输出到终端
	logger.SetOutput(os.Stdout)
	// Add this line for logging filename and line number!
	logger.SetReportCaller(true)
	// 日志格式
	logger.SetFormatter(&logrus.JSONFormatter{})
	// 设置日志级别
	switch logLevel {
	case "debug":
		logger.SetLevel(logrus.DebugLevel)
	case "test":
	case "info":
		logger.SetLevel(logrus.InfoLevel)
	case "warn":
		logger.SetLevel(logrus.WarnLevel)
	case "error":
		logger.SetLevel(logrus.ErrorLevel)
	default:
		logger.SetLevel(logrus.InfoLevel)
	}
}

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
		log := logger.WithFields(
			logrus.Fields{"request_id": requestID})
		c.Set("log", log)

		c.Next()
	}
}
