package middle

import (
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/gin-gonic/gin/binding"
	"github.com/open4go/log/model/login"
	"github.com/r2day/auth"
	rtime "github.com/r2day/base/time"
	"github.com/r2day/body"
	log "github.com/sirupsen/logrus"

	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
)

// LoginLogMiddleware 登陆日志
func LoginLogMiddleware(db *mongo.Database, skipViewLog bool) gin.HandlerFunc {

	return func(c *gin.Context) {

		// 先执行登陆操作
		c.Next()
		// 获取用户登陆信息
		clientIP := c.ClientIP()
		remoteIP := c.RemoteIP()
		fullPath := c.FullPath()
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
			// c.JSON(http.StatusBadRequest, gin.H{"error": err.Error(), "message": "login params no right"})
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

		// 写入数据库
		// 插入记录
		handler := m.Init(c.Request.Context(), auth.MDB, m.CollectionName())
		_, err := handler.Create(m)
		if err != nil {
			logCtx.Error(err)
			return
		}

	}
}

// CallLogMiddleware 调用日志
// func CallLogMiddleware(db *mongo.Database) gin.HandlerFunc {

// 	return func(c *gin.Context) {
// 		method := c.Request.Method
// 		if c.Request.Method == http.MethodGet {
// 			fmt.Println("it is get method ,no data change so don't need to record it by default")
// 			c.Next()
// 			return
// 		}

// 		if customOperationLogColl == "" {
// 			customOperationLogColl = defaultOperationLogColl
// 		}

// 		clientIP := c.ClientIP()
// 		remoteIP := c.RemoteIP()
// 		fullPath := c.FullPath()

// 		// 声明表
// 		m := &clog.Model{}
// 		// 基本查询条件
// 		m.MerchantID = c.GetHeader("MerchantId")
// 		m.ID = primitive.NewObjectID()

// 		// 插入身份信息
// 		createdAt := rtime.FomratTimeAsReader(time.Now().Unix())

// 		m.CreatedAt = createdAt
// 		m.UpdatedAt = createdAt
// 		m.ClientIP = clientIP
// 		m.RemoteIP = remoteIP
// 		m.FullPath = fullPath
// 		m.Method = method
// 		m.TargetID = c.Param("_id")

// 		// 写入数据库
// 		// 插入记录
// 		_, err := m.Create(c.Request.Context())
// 		if err != nil {
// 			c.JSON(http.StatusBadRequest, gin.H{"message": "failed to insert one", "error": err.Error()})
// 			return
// 		}
// 		c.Next()
// 	}
// }
