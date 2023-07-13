package middle

import (
	"encoding/base64"
	"encoding/json"
	"github.com/gin-gonic/gin"
)

type LoginInfo struct {
	// 命名空间
	// 可是商户号
	Namespace string `json:"namespace"`
	// 账号id
	AccountId string `json:"account_id"  bson:"account_id"`
	// 可以是手机号
	UserId string `json:"user_id"  bson:"user_id"`
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
func (l *LoginInfo) Dump(namespace string, userId string, avatar string, loginType string, userName string, accountId string, loginLevel string) (string, error) {
	// step 01 转换为json
	loginInfo := LoginInfo{
		Namespace:  namespace,
		AccountId:  accountId,
		UserId:     userId,
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
		Namespace:  c.GetHeader("MerchantID"),
		AccountId:  c.GetHeader("AccountID"),
		UserId:     c.GetHeader("UserID"),
		UserName:   c.GetHeader("UserName"),
		Avatar:     c.GetHeader("Avatar"),
		LoginType:  c.GetHeader("LoginType"),
		LoginLevel: c.GetHeader("LoginLevel"),
	}
}

// WriteIntoHeader 从登陆后的头部信息解析登陆信息
func (l *LoginInfo) WriteIntoHeader(c *gin.Context) {
	c.Request.Header.Set("MerchantID", l.Namespace)
	c.Request.Header.Set("AccountID", l.AccountId)
	c.Request.Header.Set("UserID", l.UserId)
	c.Request.Header.Set("UserName", l.UserName)
	c.Request.Header.Set("Avatar", l.Avatar)
	c.Request.Header.Set("LoginType", l.LoginType)
	c.Request.Header.Set("LoginLevel", l.LoginLevel)
}
