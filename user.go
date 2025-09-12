package middle

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/gin-gonic/gin"
	"github.com/open4go/log"
	"github.com/open4go/model"
	"os"
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
}

// Dump 登陆信息
func (l *LoginInfo) Dump(merchant string,
	userId string,
	phone string,
	avatar string,
	loginType string,
	userName string,
	accountId string,
	loginLevel string) (string, error) {
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

	tenantId := c.Request.Header.Get("X-Tenant-ID")
	if tenantId != "" {
		// 如果存在租户id 则当前是需要传递其作为商户id 并且作为数据隔离
		c.Request.Header.Set("MerchantID", tenantId)
	} else {
		// 后续传递默认root 或者 * 标识超级管理员查看所有租户数据
		// 如果网关没有获取到，那么还需解析看看后台是否是超级super 可以查看所有商户到信息
		merchantId := c.Request.Header.Get("X-Merchant-ID")
		log.Log(c.Request.Context()).WithField("merchantId", merchantId).Debug("merchantId is received")
		// 如果id不为空
		if merchantId != "" {
			// 查询数据库解析出商户tenantId
			rs, err := GetRedisCacheHandler(c.Request.Context()).Get(c.Request.Context(), fmt.Sprintf("%s:%s", CacheMerchant2Tenant, merchantId)).Result()
			if err != nil {
				log.Log(c.Request.Context()).Error(err)
			}
			log.Log(c.Request.Context()).WithField("rs", rs).Debug("merchantId is received")
			c.Request.Header.Set("MerchantID", rs)
		}
	}

	c.Request.Header.Set("AccountID", l.AccountID)
	c.Request.Header.Set("UserID", l.UserID)
	c.Request.Header.Set("UserName", l.UserName)
	c.Request.Header.Set("Avatar", l.Avatar)
	c.Request.Header.Set("LoginType", l.LoginType)
	c.Request.Header.Set("LoginLevel", l.LoginLevel)

	// 写入context
	// 在请求上下文中设置值
	ctx := context.WithValue(c.Request.Context(), model.AccountKey, l.AccountID)
	ctx = context.WithValue(ctx, model.NamespaceKey, l.Namespace)
	ctx = context.WithValue(ctx, model.MerchantKey, tenantId)
	ctx = context.WithValue(ctx, model.OperatorKey, l.UserID)
	c.Request = c.Request.WithContext(ctx)
}
