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
	// 中间件打印文件及函数位置毫无意义
	// {"account_id":"AC1739403045495640064",
	// "file":"/Users/frank/code/go-workspace/pkg/mod/github.com/open4go/rest@v0.1.5/render.go:21",
	// "func":"github.com/open4go/rest.MakeResponse",
	// "id":"","level":"error","message":"参数错误",
	// "msg":"Key: 'CreateRequest.Desc' Error:Field validation for 'Desc' failed on the 'required' tag",
	// "request_id":"2b42540f-9ab9-4a37-8d2d-6ef7c1a52229",
	// "result":{"name":"a","phone":"1766612","password":"12345678","desc":""},
	// "time":"2023-12-30T05:28:31+08:00"}
	//logger.SetReportCaller(true)
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
