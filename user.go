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
	// OPTSecret 二次验证（TOTP）密钥。
	// 出于安全考虑不再序列化进 JWT（json:"-"）：Dump / DumpLoginInfo 不会输出该字段，
	// SecondValidateMiddleware 通过 OTPSecretResolver 在服务端获取密钥（默认读 Redis，见 otp.go）。
	OPTSecret string `json:"-"  bson:"os"`
	// SuperAdmin 由签发方在超管登录时设置；仅当为 true（或商户号在 super.merchants 中）
	// 时才允许在超管域名下通过 X-Merchant-ID 切换商户。
	SuperAdmin bool `json:"sa,omitempty" bson:"sa,omitempty"`
}

// Dump 登陆信息。
// 注意：optSecret 参数仅为兼容旧签名而保留，不会写入输出（OPTSecret 不再序列化进 token），
// 签发方应改为调用 SaveOTPSecret 在服务端保存。
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

// SuperAdminContextKey 在 gin.Context 中标记“本次请求已通过校验的超管身份”。
// 仅由 JWTMiddleware（或签发方直接调用的 WriteIntoHeader）根据已校验的登录信息写入，
// 不读取任何客户端可控的请求头。下游请用 IsSuperAdmin 判断，不要再自行解析 X-Merchant-ID / Host。
const SuperAdminContextKey = "OPEN4GO_VERIFIED_SUPER_ADMIN"

// IsSuperAdmin 返回当前请求是否为已校验的超管：超管域名 + token 中的 SuperAdmin 标记
// （或商户号在 super.merchant / super.merchants 中）。未经 JWTMiddleware 校验时总是 false。
func IsSuperAdmin(c *gin.Context) bool {
	if c == nil {
		return false
	}
	return c.GetBool(SuperAdminContextKey)
}

// WriteIntoHeader 把已校验的登录信息写入请求头与 context。
// 调用方必须保证 l 来自已校验的 token（或签发方自己查库得到的登录信息）。
// 非超管登录时，商户以 token 中的 MerchantID 为准，客户端传入的 X-Tenant-ID 不能覆盖。
func (l *LoginInfo) WriteIntoHeader(c *gin.Context) {
	l.writeIntoHeader(c, true)
}

// writeIntoHeader verified=false 用于 MerchantBindMiddleware：登录信息来自未经校验的请求头，
// 不允许切换商户，也不会标记超管。
func (l *LoginInfo) writeIntoHeader(c *gin.Context, verified bool) {
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

	allowSwitch := verified && isSuperDomain && canSwitchMerchant(l)
	c.Set(SuperAdminContextKey, allowSwitch)
	if verified && !allowSwitch {
		if jwtMerchant := strings.TrimSpace(l.MerchantID); jwtMerchant != "" && tenantId != jwtMerchant {
			if tenantId != "" {
				log.Log(c.Request.Context()).
					WithField("domain", c.Request.Host).
					Warning("tenant header ignored: does not match login merchant")
			}
			tenantId = jwtMerchant
			c.Request.Header.Set("X-Tenant-ID", tenantId)
		}
	}
	if switcher != "" && !allowSwitch {
		log.Log(c.Request.Context()).
			WithField("domain", c.Request.Host).
			Warning("merchant switch ignored: not permitted for this login")
		switcher = ""
		if verified {
			c.Request.Header.Del("X-Merchant-ID")
		}
	}

	if allowSwitch && switcher != "" {
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
	ctx := context.WithValue(c.Request.Context(), model.AccountKey, l.AccountID) //nolint:staticcheck // SA1029: key type is fixed by open4go/model
	ctx = context.WithValue(ctx, model.NamespaceKey, l.Namespace)                //nolint:staticcheck // SA1029: key type is fixed by open4go/model
	merchantKey := tenantId
	if merchantKey == "*" {
		merchantKey = ""
	}
	ctx = context.WithValue(ctx, model.MerchantKey, merchantKey) //nolint:staticcheck // SA1029: key type is fixed by open4go/model
	ctx = context.WithValue(ctx, model.OperatorKey, l.UserID)    //nolint:staticcheck // SA1029: key type is fixed by open4go/model

	// View-all mode: super-admin host and no resolved tenant.
	if allowSwitch && merchantKey == "" {
		ctx = context.WithValue(ctx, model.NamespaceKey, "*") //nolint:staticcheck // SA1029: key type is fixed by open4go/model
	}
	c.Request = c.Request.WithContext(ctx)
}
