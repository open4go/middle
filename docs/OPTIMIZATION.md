# middle 优化方案

> 下面的安全问题都有一个前提：服务可以绕过网关直接访问，或者网关没有覆盖、剥离相关请求头。请结合 APISIX 的实际配置核实。

> 修复进展：表中标注“已修复 / 部分修复”的条目已在 [open4go/middle/pull/1](https://github.com/open4go/middle/pull/1) 中处理，合并后生效。

| # | 优先级 | 问题 | 位置 | 建议 | 工作量 |
|---|---|---|---|---|---|
| 1 | 高 | **已修复**（[修复 PR](https://github.com/open4go/middle/pull/1)） **TOTP 密钥放在 JWT 里**：`LoginInfo.OPTSecret`（json `os`）被序列化进 `StandardClaims.Issuer`。JWT 只签名、不加密，拿到 Cookie 的人都能 base64 解出 TOTP 种子，二次验证形同虚设 | `user.go:40`、`jwt.go` SecondValidateMiddleware、`rest/login.go` | TOTP 密钥只存服务端（DB/Redis，按 accountId 查），JWT 里不再携带；已签发的 token 让它过期，并轮换受影响账号的 TOTP | M |
| 2 | 高 | **已修复**（[修复 PR](https://github.com/open4go/middle/pull/1)） **超管识别依赖客户端可控的请求头**：`requestAdminHost` 优先取 `X-Forwarded-Host`，然后是 `Origin`；而且 `super.localhost` **在任何环境下都算超管**。任何已登录用户只要带上 `X-Forwarded-Host: super.localhost` 和 `X-Merchant-ID: <他人商户>`，`WriteIntoHeader` 就会把 ctx 的商户切过去（跨租户访问） | `tenant.go:31-54`、`user.go` WriteIntoHeader | ① 只信任网关注入的 Host（配置可信代理列表）；② 去掉硬编码的 `super.localhost`，只在 `env=dev` 时启用；③ 切换商户还要校验 JWT 里的超管角色或 LoginLevel | M |
| 3 | 高 | **已修复**（[修复 PR](https://github.com/open4go/middle/pull/1)） `dgrijalva/jwt-go` 已归档，存在 CVE-2020-26160（`aud` 校验绕过），也没人维护了 | `jwt.go`、`JWTAuthMiddleware.go`、`rest/login.go` | 迁移到 `github.com/golang-jwt/jwt/v5`，显式 `WithValidMethods([]string{"HS256"})`、`WithAudience`、`WithIssuer` | M |
| 4 | 高 | **部分修复（auth 已改用 token 校验后的身份，MerchantBindMiddleware 仍待处理）**（[修复 PR](https://github.com/open4go/middle/pull/1)） `MerchantBindMiddleware` 完全信任请求头 `AccountID/UserID/MerchantID`，不做任何校验；`auth.AccessMiddleware` 也只看 `UserID` 头 | `jwt.go` bindMerchant、`user.go` LoadFromHeader | 在入口先删除所有内部身份头（`Del("UserID")` 等），只由 JWT 解析结果写入；内部服务间调用改用签名头或 mTLS | M |
| 5 | 中 | **已修复**（[修复 PR](https://github.com/open4go/middle/pull/1)） `checkAuth` 已经 `AbortWithStatus(401)`，调用方又 `AbortWithStatus(403)`，会出现 “headers were already written” 告警，状态码也混乱；SignOut 分支和普通分支的代码完全一样 | `jwt.go:22-37` | `checkAuth` 只返回状态码，由调用方 Abort 一次；删除重复分支 | S |
| 6 | 中 | `VerifyTokenMiddleware`：`value==""` 时返回的 err 是 nil，等于放行；token 为空时会去查 `wx_tokens_` | `wx_auth.go` | 空 token 直接 401；空值返回明确错误 | S |
| 7 | 中 | 审计日志在请求链路里同步写 Mongo，会拉高写接口延迟；配额检查每次创建请求都同步发一次 HTTP，失败时一律放行（fail-open） | `oplog.go` saveOperationLog、`usage_quota.go` | 审计改成异步队列（复用 usage 的 channel 模式）；配额结果按商户本地缓存 30–60 秒；在文档里写明 fail-open 是有意为之 | M |
| 8 | 中 | 配额检查会把用户的 `Authorization` / `jwt` Cookie 原样转发给 `usageCheckURL`，配置错误时会泄露凭证 | `usage_quota.go` checkQuotaRemote | 改用服务间凭证；只允许内网 host | S |
| 9 | 低 | CORS 用 `math/rand` 生成 traceID，并写入裸字符串 ctx key `"traceid"`/`"ip"`；和 `log.TraceMiddleware` 的功能重复 | `cors.go` | 改为调用 `log.Inject` / `log.NewTraceID` | S |
| 10 | 低 | `GetRedisMiddleHandler` / `GetRedisCacheHandler` 遇错就 `Fatal`，会让请求处理过程中的进程直接退出 | `todo.go`、`db.go` | 返回 error，由中间件返回 503 | S |
| 11 | 中 | govulncheck：`golang.org/x/net v0.47.0`（4 个 HTTP/2 相关问题） | `go.mod` | 升级到 x/net v0.60.0 | S |
| 12 | 低 | 两套 JWT 方案（Cookie+StandardClaims.Issuer 和 Bearer+MapClaims）共存，claims 语义被滥用（Issuer 字段存的是用户数据） | `jwt.go`、`JWTAuthMiddleware.go` | 统一用自定义 Claims struct（`RegisteredClaims` + 业务字段） | M |
