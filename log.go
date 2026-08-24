package middle

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/open4go/log"
	"github.com/open4go/log/model/login"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
)

// LoginLogMiddleware handles login-related logging
func LoginLogMiddleware(db *mongo.Database, skipViewLog bool) gin.HandlerFunc {
	return func(c *gin.Context) {
		if db == nil {
			c.Next()
			return
		}
		if c.Request.Method == http.MethodGet && skipViewLog {
			log.Log(c.Request.Context()).Debug("GET method, not logged to database")
			c.Next()
			return
		}

		payload := readRequestBody(c)
		c.Next()
		saveLoginLog(c, db, payload)
	}
}

func saveLoginLog(c *gin.Context, db *mongo.Database, payload []byte) {
	l := LoadFromHeader(c)
	body := extractBodyFields(payload)
	fullPath := c.FullPath()
	if fullPath == "" {
		fullPath = c.Request.URL.Path
	}

	phone := firstNonEmpty(l.Phone, body.Phone)
	userID := firstNonEmpty(l.UserID, body.UserID)
	accountID := firstNonEmpty(l.AccountID, body.AccountID)
	merchantID := firstNonEmpty(
		l.MerchantID,
		c.GetHeader("X-Tenant-ID"),
		c.GetHeader("X-Merchant-ID"),
		body.MerchantID,
		l.Namespace,
	)
	loginType := firstNonEmpty(l.LoginType, body.LoginType, body.Type)
	userAgent := truncateRunes(c.Request.UserAgent(), 240)
	logType := loginLogType(fullPath, c.Request.URL.Path)

	m := &login.Model{}
	m.ID = primitive.NewObjectID()
	m.ClientIP = c.ClientIP()
	m.RemoteIP = clientRemoteIP(c)
	m.FullPath = fullPath
	m.Method = c.Request.Method
	m.RespCode = c.Writer.Status()
	m.TargetID = firstNonEmpty(userID, accountID, phone)
	m.Device = firstNonEmpty(c.GetHeader("X-Device-ID"), c.GetHeader("X-Device-Id"), truncateRunes(userAgent, 180))
	m.LogType = logType
	m.UserID = userID
	m.AccountID = accountID
	m.UserName = l.UserName
	m.Phone = phone
	m.LoginType = loginType
	m.MerchantID = merchantID
	m.TraceID = requestTraceID(c)
	m.UserAgent = userAgent

	ctx := withLogIdentity(c.Request.Context(), l, merchantID)
	handler := m.Init(ctx, db, m.CollectionName())
	m.Meta = completeMeta(handler.GetMeta(), parseAccessLevel(l.LoginLevel), m.RespCode < 400, merchantID, accountID, l.Namespace, firstNonEmpty(userID, accountID, phone))
	if _, err := handler.Context.Handler.Collection(handler.Context.Collection).InsertOne(ctx, m); err != nil {
		log.Log(ctx).WithError(err).
			WithField("path", fullPath).
			WithField("log_type", logType).
			Warning("write login log failed")
	}
}

func loginLogType(fullPath, rawPath string) string {
	p := strings.ToLower(fullPath + " " + rawPath)
	switch {
	case strings.Contains(p, "signout"):
		return "signout"
	case strings.Contains(p, "/otp"):
		return "otp"
	case strings.Contains(p, "/mch"):
		return "merchant_choose"
	case strings.Contains(p, "signup"), strings.Contains(p, "register"):
		return "signup"
	default:
		return "signin"
	}
}
