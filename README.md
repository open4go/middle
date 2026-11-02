# middle — Gin 中间件集合（认证、租户、CORS、审计、用量）

> 仓库：https://github.com/open4go/middle ｜ 模块：`github.com/open4go/middle` ｜ Go 1.25.8 ｜ 最近提交：2026-10-08（最新 tag v0.3.60，180 个 tag）

## 项目简介
r2day 后端服务共用的 Gin 中间件：
- **认证**：后台用 Cookie `jwt`（`JWTMiddleware`），C 端用 `Authorization: Bearer`（`JWTAuthMiddleware`），二次验证用 TOTP（`SecondValidateMiddleware`），微信小程序 token 走 Redis 校验（`VerifyTokenMiddleware`）
- **租户/商户上下文**：把登录信息写进请求头（`AccountID`、`UserID`、`MerchantID`、`X-Tenant-ID`…）和 `context`（`model.*Key`），支持超管域名下用 `X-Merchant-ID` 切换商户
- **CORS**、**Trace**（转发 `log.TraceMiddleware`）
- **操作审计**（`OperateLogMiddleware`：非 GET 请求写 Mongo 审计日志，敏感字段脱敏，按路径归类 Service/Module）
- **用量与配额**：通过 Kafka 异步上报用量（`InitUsageFromViper`、`EnqueueUsage`），创建类请求先远程检查配额（`allowQuotaOrAbort`）

## 目录结构
```
middle/
├── jwt.go                # JWTMiddleware / MerchantBindMiddleware / SecondValidateMiddleware
├── JWTAuthMiddleware.go  # Bearer Token（sub/iss/aud/jti/mid）
├── user.go               # LoginInfo、Dump/Load、LoadFromHeader、WriteIntoHeader
├── tenant.go             # 超管域名识别、X-Merchant-ID 切换
├── cors.go  trace.go  log.go  todo.go(Redis "middle") db.go(Redis "cache")
├── wx_auth.go            # VerifyTokenMiddleware
├── oplog.go oplog_classify.go   # 审计日志
├── usage.go usage_kafka.go usage_quota.go  # 用量/配额
└── *_test.go             # cors/tenant/user/oplog/usage 测试
```

## 主要 API
| API | 说明 |
|---|---|
| `JWTMiddleware(key)` | 从 Cookie `jwt` 解析 HS* 签名的 `StandardClaims`，把 `Issuer` 当作 base64(JSON(LoginInfo)) 解析，然后 `WriteIntoHeader` |
| `JWTAuthMiddleware(secret)` | Bearer Token，要求有 `sub/iss/aud/jti`；`mid` 和请求头 `X-Tenant-ID` 不一致时返回 403 |
| `SecondValidateMiddleware(key)` | 读 `X-TOTP-Code` 或 `?code=`，用 JWT 里的 `OPTSecret` 校验 |
| `MerchantBindMiddleware(key)` | 只从请求头读取登录信息，再写回请求头和 ctx（不校验） |
| `CORSMiddleware(host)` | 固定 Allow-Origin + Credentials；OPTIONS 返回 204 |
| `OperateLogMiddleware(db)` | POST/PUT/PATCH/DELETE 审计写入 Mongo |
| `InitUsageFromViper()` / `EnqueueUsage(ev)` | Kafka 用量上报（`usage.kafka.brokers`/`topic`） |
| `(*LoginInfo).Dump(...)` / `DumpLoginInfo(l)` / `Load(payload)` | 登录信息序列化 |

## 使用示例
```go
r.Use(middle.TraceMiddleware(), middle.CORSMiddleware(viper.GetString("cors.host")))
admin := r.Group("/v1", middle.JWTMiddleware(jwtKey), middle.OperateLogMiddleware(mdb))
// rest/login.go 中签发 Cookie JWT：
claims := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.StandardClaims{
    Issuer: middle.DumpLoginInfo(lp), ExpiresAt: ...})
```

## 依赖
`gin v1.9.1`、`github.com/dgrijalva/jwt-go v3.2.0+incompatible`、`pquerna/otp`、`segmentio/kafka-go`、`go-redis/v9 v9.7.3`、`mongo-driver v1.17.3`、`open4go/{db v0.0.13, log v0.0.23, model v0.0.20, r3time}`、`r2day/base`

## 构建与测试
`go build`、`go vet`、`go test ./...` 均通过。

## 与其他仓库的关系
`rest` 依赖 `middle v0.3.25`（`LoginInfo`、`DumpLoginInfo`）；r2day/* 业务服务在路由层使用；`auth.AccessMiddleware` 依赖本库写入的 `UserID` 请求头。
