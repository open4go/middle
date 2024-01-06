package middle

import (
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/gin-gonic/gin/binding"
	"github.com/open4go/log/model/login"
	"github.com/open4go/log/model/operation"
	rtime "github.com/r2day/base/time"
	"github.com/r2day/body"
	"github.com/sirupsen/logrus"

	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
)

// LoginLogMiddleware 登陆日志
func LoginLogMiddleware(db *mongo.Database, skipViewLog bool) gin.HandlerFunc {

	return func(c *gin.Context) {
		// Retrieve the Logrus logger from the context
		logger, _ := c.Get("log")
		log := logger.(*logrus.Entry)

		// 先执行登陆操作
		c.Next()
		// 获取用户登陆信息
		//clientIP := c.ClientIP()
		remoteIP := c.RemoteIP()
		fullPath := c.FullPath()
		// Retrieve remote IP from trusted headers
		clientIP := c.Request.Header.Get("X-Real-IP") // For Nginx proxy setups
		if clientIP == "" {
			clientIP = c.Request.Header.Get("X-Forwarded-For") // For other proxy setups
		}
		if clientIP == "" {
			clientIP = c.ClientIP() // If all else fails, fallback to c.ClientIP()
		}

		respCode := c.Writer.Status()

		logCtx := log.WithField("client_id", clientIP).
			WithField("remote_ip", remoteIP).
			WithField("full_path", fullPath).
			WithField("resp_status", respCode)

		if c.Request.Method == http.MethodGet && skipViewLog {
			logCtx.Debug("it is get method, we don't record it on database")
			return
		}
		l := LoadFromHeader(c)
		m := &login.Model{}
		var jsonInstance body.SimpleSignInRequest
		if err := c.ShouldBindBodyWith(&jsonInstance, binding.JSON); err != nil {
			logCtx.Error(err)
			return
		}

		m.ID = primitive.NewObjectID()
		accessLevelInt, _ := strconv.Atoi(l.LoginLevel)
		m.Meta.AccessLevel = uint(accessLevelInt)

		// 基本查询条件

		m.Meta.MerchantID = l.Namespace
		m.Meta.AccountID = l.AccountId
		// 插入身份信息
		createdAt := rtime.FomratTimeAsReader(time.Now().Unix())

		m.Meta.CreatedAt = createdAt
		m.Meta.UpdatedAt = createdAt

		m.ClientIP = clientIP
		m.RemoteIP = remoteIP
		m.FullPath = fullPath
		m.RespCode = respCode
		m.UserID = l.UserId
		m.AccountID = l.AccountId
		// 写入数据库
		// 插入记录
		handler := m.Init(c.Request.Context(), db, m.CollectionName())
		_, err := handler.Create(m)
		if err != nil {
			logCtx.Error(err)
			return
		}
	}
}

// OperateLogMiddleware 操作日志(记录增、删、改）
func OperateLogMiddleware(db *mongo.Database) gin.HandlerFunc {

	return func(c *gin.Context) {
		// Retrieve the Logrus logger from the context
		logger, _ := c.Get("log")
		log := logger.(*logrus.Entry)

		method := c.Request.Method
		if c.Request.Method == http.MethodGet {
			log.Info("it is get method ,no data change so don't need to record it by default")
			c.Next()
			return
		}

		if c.Request.Method == http.MethodPut || c.Request.Method == http.MethodDelete {
			l := LoadFromHeader(c)

			clientIP := c.ClientIP()
			remoteIP := c.RemoteIP()
			fullPath := c.FullPath()
			targetId := c.Param("_id")
			saveLog(c, l, clientIP,
				remoteIP, fullPath, method, targetId, db)
		}

		c.Next()

		// 创建对象需要执行完成后再记录操作日志
		// TODO 其实应该都在执行完毕后记录才是合理的
		if c.Request.Method == http.MethodPost {
			l := LoadFromHeader(c)

			clientIP := c.ClientIP()
			remoteIP := c.RemoteIP()
			fullPath := c.FullPath()
			// Accessing response headers set by the handler
			headers := c.Writer.Header()

			// Example: Get the value of a specific header
			targetId := headers.Get("TargetId")
			// TODO 如果是新增/需要在新增后拿到targetId
			log.WithField("id", targetId).
				Debug("after call done")

			saveLog(c, l, clientIP,
				remoteIP, fullPath, method, targetId, db)
		}
	}
}

func saveLog(c *gin.Context, l LoginInfo, clientIP string,
	remoteIP string, fullPath string, method string, targetId string, db *mongo.Database) {
	// Retrieve the Logrus logger from the context
	logger, _ := c.Get("log")
	log := logger.(*logrus.Entry)

	// 声明表
	m := &operation.Model{}
	// 基本查询条件
	m.ID = primitive.NewObjectID()
	// 基本查询条件

	m.Meta.MerchantID = l.Namespace
	m.Meta.AccountID = l.AccountId
	// 插入身份信息
	createdAt := rtime.FomratTimeAsReader(time.Now().Unix())

	m.Meta.CreatedAt = createdAt
	m.Meta.UpdatedAt = createdAt
	m.ClientIP = clientIP
	m.RemoteIP = remoteIP
	m.FullPath = fullPath
	m.Method = method // 对应的 新增/修改/删除
	m.TargetID = targetId
	m.Operator = l.UserName
	m.AccountID = l.AccountId
	m.Timestamp = uint64(time.Now().Unix())

	// 写入数据库
	// 插入记录
	handler := m.Init(c.Request.Context(), db, m.CollectionName())
	_, err := handler.Create(m)
	if err != nil {
		log.WithField("operation", m).
			Error(err)
	}
}
