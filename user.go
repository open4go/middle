package middle

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"os"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/open4go/log"
	"github.com/open4go/model"
)

const (
	CacheMerchant2Tenant = "cache:merchant2tenant"
)

type LoginInfo struct {
	// 命名空间
	// 可是商户号
	Namespace string `json:"namespace"`
	// 商户号
	MerchantID string `json:"merchant-id"  bson:"merchant"`
	// 账号id
	AccountID string `json:"account_id"  bson:"account_id"`
	// 可以是手机号
	Phone string `json:"phone"  bson:"phone"`
	// mongoID
	UserID string `json:"user_id"  bson:"user_id"`
	// 用户名
	UserName string `json:"user_name"  bson:"user_name"`
	// Avatar 用户头像
	Avatar string `json:"avatar"`
	// LoginType 登陆类型
	LoginType string `json:"login_type"  bson:"login_type"`
	// LoginLevel 登陆用户等级
	LoginLevel string `json:"login_level"  bson:"login_level"`
	// 用于二次验证权限的接口，如解密手机号等
	OPTSecret string `json:"os"  bson:"os"`
}

// Dump 登陆信息
func (l *LoginInfo) Dump(merchant string,
	userId string,
	phone string,
	avatar string,
	loginType string,
	userName string,
	accountId string,
	loginLevel string,
	optSecret string,
) (string, error) {
	// step 01 转换为json
	loginInfo := LoginInfo{
		Namespace:  os.Getenv(model.NamespaceKey),
		MerchantID: merchant,
		AccountID:  accountId,
		UserID:     userId,
		Phone:      phone,
		UserName:   userName,
		Avatar:     avatar,
		LoginType:  loginType,
		LoginLevel: loginLevel,
		OPTSecret:  optSecret,
	}
	payload, err := json.Marshal(loginInfo)
	if err != nil {
		return "", err
	}
	sEnc := base64.StdEncoding.EncodeToString([]byte(payload))
	return sEnc, nil
}

func DumpLoginInfo(l LoginInfo) string {
	payload, err := json.Marshal(l)
	if err != nil {
		return ""
	}
	sEnc := base64.StdEncoding.EncodeToString([]byte(payload))
	return sEnc
}

// Load 解析登陆信息
func (l *LoginInfo) Load(payload string) error {
	// step 01 转换为bytes
	sDec, err := base64.StdEncoding.DecodeString(payload)
	if err != nil {
		return err
	}
	err = json.Unmarshal(sDec, l)
	if err != nil {
		return err
	}
	return nil
}

// LoadFromHeader 从登陆后的头部信息解析登陆信息
func LoadFromHeader(c *gin.Context) LoginInfo {
	return LoginInfo{
		Namespace:  c.GetHeader("Namespace"),
		AccountID:  c.GetHeader("AccountID"),
		UserID:     c.GetHeader("UserID"),
		Phone:      c.GetHeader("Phone"),
		MerchantID: c.GetHeader("MerchantID"),
		UserName:   c.GetHeader("UserName"),
		Avatar:     c.GetHeader("Avatar"),
		LoginType:  c.GetHeader("LoginType"),
		LoginLevel: c.GetHeader("LoginLevel"),
	}
}

// WriteIntoHeader 从登陆后的头部信息解析登陆信息
func (l *LoginInfo) WriteIntoHeader(c *gin.Context) {
	c.Request.Header.Set("Namespace", l.Namespace)

	tenantId := strings.TrimSpace(c.Request.Header.Get("X-Tenant-ID"))
	switcher := switchedMerchantID(c)
	isSuperDomain := isSuperAdminHost(requestAdminHost(c))

	log.Log(c.Request.Context()).
		WithField("tenantId ", tenantId).
		WithField("switcher", switcher).
		WithField("gateway bind domain tenantId", l.MerchantID).
		WithField("domain", c.Request.Host).
		WithField("isSuperDomain", isSuperDomain).
		Debug("before write into each response header")

	if isSuperDomain && switcher != "" {
		if switcher == "*" {
			tenantId = ""
			c.Request.Header.Del("X-Tenant-ID")
			log.Log(c.Request.Context()).Debug("super-admin view-all merchants")
		} else {
			tenantId = switcher
			c.Request.Header.Set("X-Tenant-ID", tenantId)
		}
	} else if tenantId == "" {
		tenantId = l.MerchantID
		if tenantId != "" {
			c.Request.Header.Set("X-Tenant-ID", tenantId)
		}
	}

	if tenantId != "" && tenantId != "*" {
		c.Request.Header.Set("MerchantID", tenantId)
	}

	c.Request.Header.Set("AccountID", l.AccountID)
	c.Request.Header.Set("UserID", l.UserID)
	c.Request.Header.Set("UserName", l.UserName)
	c.Request.Header.Set("Phone", l.Phone)
	c.Request.Header.Set("Avatar", l.Avatar)
	c.Request.Header.Set("LoginType", l.LoginType)
	c.Request.Header.Set("LoginLevel", l.LoginLevel)
	// 写入context
	// 在请求上下文中设置值
	ctx := context.WithValue(c.Request.Context(), model.AccountKey, l.AccountID)
	ctx = context.WithValue(ctx, model.NamespaceKey, l.Namespace)
	merchantKey := tenantId
	if merchantKey == "*" {
		merchantKey = ""
	}
	ctx = context.WithValue(ctx, model.MerchantKey, merchantKey)
	ctx = context.WithValue(ctx, model.OperatorKey, l.UserID)

	// View-all mode: super-admin host and no resolved tenant.
	if isSuperDomain && merchantKey == "" {
		ctx = context.WithValue(ctx, model.NamespaceKey, "*")
	}
	c.Request = c.Request.WithContext(ctx)
}
