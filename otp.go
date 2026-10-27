package middle

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"time"

	r2redis "github.com/open4go/db/redis"
	"github.com/spf13/viper"
)

// OTPSecretKeyPrefix 默认 OTP 密钥在 Redis（handler "middle"）中的 key 前缀。
const OTPSecretKeyPrefix = "middle:otp:secret:"

// cfgOTPAllowLegacyJWT 为 true 时，若服务端查不到密钥，允许回退读取旧版 JWT 中携带的 "os" 字段。
// 仅用于迁移窗口，默认 false。
const cfgOTPAllowLegacyJWT = "middle.otp.allowLegacyJWTSecret"

// ErrOTPSecretNotFound 服务端没有该账号的 OTP 密钥。
var ErrOTPSecretNotFound = errors.New("otp secret not found")

// OTPSecretResolver 根据已验证的登录信息返回该账号的 TOTP 密钥。
type OTPSecretResolver func(ctx context.Context, l *LoginInfo) (string, error)

var (
	otpResolverMu sync.RWMutex
	otpResolver   OTPSecretResolver = redisOTPSecretResolver
)

// SetOTPSecretResolver 替换默认的密钥获取方式（例如直接查账号库）。传 nil 恢复默认。
func SetOTPSecretResolver(r OTPSecretResolver) {
	otpResolverMu.Lock()
	defer otpResolverMu.Unlock()
	if r == nil {
		r = redisOTPSecretResolver
	}
	otpResolver = r
}

func currentOTPResolver() OTPSecretResolver {
	otpResolverMu.RLock()
	defer otpResolverMu.RUnlock()
	return otpResolver
}

func otpKey(l *LoginInfo) string {
	id := strings.TrimSpace(l.AccountID)
	if id == "" {
		id = strings.TrimSpace(l.UserID)
	}
	if id == "" {
		return ""
	}
	return OTPSecretKeyPrefix + id
}

// SaveOTPSecret 在登录签发 token 时由签发服务调用，把 TOTP 密钥保存在服务端（Redis "middle"）。
// ttl 建议与登录会话时长一致；<=0 表示不过期。
func SaveOTPSecret(ctx context.Context, l LoginInfo, secret string, ttl time.Duration) error {
	key := otpKey(&l)
	if key == "" {
		return errors.New("otp: empty account id")
	}
	rdb, err := r2redis.DBPool.GetHandler("middle")
	if err != nil {
		return err
	}
	if ttl < 0 {
		ttl = 0
	}
	return rdb.Set(ctx, key, secret, ttl).Err()
}

// DeleteOTPSecret 退出登录或重置 OTP 时调用。
func DeleteOTPSecret(ctx context.Context, l LoginInfo) error {
	key := otpKey(&l)
	if key == "" {
		return nil
	}
	rdb, err := r2redis.DBPool.GetHandler("middle")
	if err != nil {
		return err
	}
	return rdb.Del(ctx, key).Err()
}

func redisOTPSecretResolver(ctx context.Context, l *LoginInfo) (string, error) {
	key := otpKey(l)
	if key == "" {
		return "", ErrOTPSecretNotFound
	}
	if r2redis.DBPool == nil {
		return "", errors.New("otp: redis pool not initialised")
	}
	rdb, err := r2redis.DBPool.GetHandler("middle")
	if err != nil {
		return "", err
	}
	v, err := rdb.Get(ctx, key).Result()
	if err != nil || strings.TrimSpace(v) == "" {
		return "", ErrOTPSecretNotFound
	}
	return v, nil
}

// legacyOTPSecret 读取旧版 token 中 base64(JSON) 携带的 "os" 字段，仅在迁移开关打开时使用。
func legacyOTPSecret(payload string) string {
	raw, err := base64.StdEncoding.DecodeString(payload)
	if err != nil {
		return ""
	}
	var v struct {
		OS string `json:"os"`
	}
	if json.Unmarshal(raw, &v) != nil {
		return ""
	}
	return v.OS
}

func resolveOTPSecret(ctx context.Context, l *LoginInfo, issuerPayload string) (string, error) {
	secret, err := currentOTPResolver()(ctx, l)
	if err == nil && secret != "" {
		return secret, nil
	}
	if viper.GetBool(cfgOTPAllowLegacyJWT) {
		if s := legacyOTPSecret(issuerPayload); s != "" {
			return s, nil
		}
	}
	if err == nil {
		err = ErrOTPSecretNotFound
	}
	return "", err
}
