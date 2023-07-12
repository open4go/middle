package middle

import (
	"encoding/base64"
	"encoding/json"
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
func (l *LoginInfo) Load(payload string) (*LoginInfo, error) {
	// step 01 转换为bytes
	sDec, err := base64.StdEncoding.DecodeString(payload)
	if err != nil {
		return nil, err
	}
	loginInfo := &LoginInfo{}
	err = json.Unmarshal(sDec, loginInfo)
	if err != nil {
		return nil, err
	}
	return loginInfo, nil
}
