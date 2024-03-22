package middle

import (
	"github.com/gin-gonic/gin/binding"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/open4go/log"
	"github.com/open4go/log/model/login"
	"github.com/open4go/log/model/operation"
	rtime "github.com/r2day/base/time"
	"github.com/r2day/body"

	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
)

// LoginLogMiddleware handles login-related logging
func LoginLogMiddleware(db *mongo.Database, skipViewLog bool) gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Next()

		remoteIP := c.Request.Header.Get("X-Real-IP")
		if remoteIP == "" {
			remoteIP = c.Request.Header.Get("X-Forwarded-For")
		}
		if remoteIP == "" {
			remoteIP = c.ClientIP()
		}

		if c.Request.Method == http.MethodGet && skipViewLog {
			log.Log().Debug("GET method, not logged to database")
			return
		}

		l := LoadFromHeader(c)
		m := &login.Model{}
		var jsonInstance body.SimpleSignInRequest
		if err := c.ShouldBindBodyWith(&jsonInstance, binding.JSON); err != nil {
			log.Log().Error(err)
			return
		}

		m.ID = primitive.NewObjectID()
		accessLevelInt, _ := strconv.Atoi(l.LoginLevel)
		m.Meta.AccessLevel = uint(accessLevelInt)

		m.Meta.MerchantID = l.Namespace
		m.Meta.AccountID = l.AccountID

		createdAt := rtime.FomratTimeAsReader(time.Now().Unix())
		m.Meta.CreatedAt = createdAt
		m.Meta.UpdatedAt = createdAt

		m.ClientIP = c.ClientIP()
		m.RemoteIP = remoteIP
		m.FullPath = c.FullPath()
		m.RespCode = c.Writer.Status()
		m.UserID = l.UserID
		m.AccountID = l.AccountID

		handler := m.Init(c.Request.Context(), db, m.CollectionName())
		_, err := handler.Create(m)
		if err != nil {
			log.Log().Error(err)
			return
		}
	}
}

// OperateLogMiddleware handles operation-related logging
func OperateLogMiddleware(db *mongo.Database) gin.HandlerFunc {
	return func(c *gin.Context) {
		method := c.Request.Method

		if method == http.MethodGet {
			log.Log().WithField("method", method).
				Debug("GET method, not logged to database by default")
			c.Next()
			return
		}

		c.Next()

		if method == http.MethodPut || method == http.MethodDelete {
			l := LoadFromHeader(c)

			clientIP := c.ClientIP()
			remoteIP := c.Request.Header.Get("X-Real-IP")
			if remoteIP == "" {
				remoteIP = c.Request.Header.Get("X-Forwarded-For")
			}
			if remoteIP == "" {
				remoteIP = c.ClientIP()
			}

			fullPath := c.FullPath()
			// 移除 "/:_id"
			fullPath = strings.Replace(fullPath, "/:_id", "", -1)
			targetID := c.Param("_id")
			saveLog(c, l, clientIP, remoteIP, fullPath, method, targetID, db)
		}

		if method == http.MethodPost {
			l := LoadFromHeader(c)

			clientIP := c.ClientIP()
			remoteIP := c.Request.Header.Get("X-Real-IP")
			if remoteIP == "" {
				remoteIP = c.Request.Header.Get("X-Forwarded-For")
			}
			if remoteIP == "" {
				remoteIP = c.ClientIP()
			}

			fullPath := c.FullPath()
			headers := c.Writer.Header()
			targetID := headers.Get("TargetId")

			if targetID == "" {
				if value, ok := c.Value("TargetId").(string); ok {
					targetID = value
				} else {
					// 处理无法从上下文中获取 "TargetId" 的情况
				}
			}
			log.Log().
				WithField("clientIP", clientIP).
				WithField("remoteIP", remoteIP).
				WithField("fullPath", fullPath).
				WithField("method", method).
				WithField("targetID", targetID).
				Debug("before save")
			saveLog(c, l, clientIP, remoteIP, fullPath, method, targetID, db)
		}
	}
}

func saveLog(c *gin.Context, l LoginInfo, clientIP, remoteIP, fullPath, method string, targetID string, db *mongo.Database) {
	m := &operation.Model{}
	m.ClientIP = clientIP
	m.RemoteIP = remoteIP
	m.FullPath = fullPath
	m.Method = method
	m.TargetID = targetID
	m.Operator = l.UserName
	m.AccountID = l.AccountID
	m.Timestamp = uint64(time.Now().Unix())

	handler := m.Init(c.Request.Context(), db, m.CollectionName())
	id, err := handler.Create(m)
	if err != nil {
		log.Log().Error(err)
	}
	log.Log().WithField("id", id).Debug("after create done")
}
