package middle

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/gin-gonic/gin"
	"github.com/open4go/log"
	"github.com/open4go/log/model/operation"
	"github.com/open4go/model"
	rtime "github.com/r2day/base/time"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
)

const maxAuditBody = 4096

var skipOperatePathParts = []string{
	"/actions",
	"/logs",
	"/heartbeat",
	"/metrics",
	"/healthz",
	"/readyz",
	"/health",
	"/ping",
}

var sensitiveBodyKeys = map[string]struct{}{
	"password":      {},
	"passwd":        {},
	"old_password":  {},
	"new_password":  {},
	"oldpassword":   {},
	"newpassword":   {},
	"token":         {},
	"access_token":  {},
	"refresh_token": {},
	"secret":        {},
	"session_key":   {},
	"jwt":           {},
	"otp":           {},
	"otp_secret":    {},
	"opt_secret":    {},
	"sms_code":      {},
	"authorization": {},
	"cookie":        {},
}

var targetIDKeys = []string{
	"id", "_id", "account_id", "user_id", "member_id", "target_id",
}

var targetNameKeys = []string{
	"name", "nickname", "user_name", "username", "title",
}

var nestedBodyKeys = []string{
	"identity", "profile", "user", "member", "account", "data",
}

// OperateLogMiddleware 记录后台增删改：操作人、会员/资源、请求摘要、脱敏后的变更内容。
func OperateLogMiddleware(db *mongo.Database) gin.HandlerFunc {
	return func(c *gin.Context) {
		method := c.Request.Method
		if method == http.MethodGet || method == http.MethodHead || method == http.MethodOptions {
			c.Next()
			return
		}
		if db == nil || skipOperatePath(c.FullPath(), c.Request.URL.Path) {
			c.Next()
			return
		}

		start := time.Now()
		payload := readRequestBody(c)
		c.Next()

		if method != http.MethodPost && method != http.MethodPut &&
			method != http.MethodPatch && method != http.MethodDelete {
			return
		}
		saveOperationLog(c, db, payload, start)
	}
}

func skipOperatePath(fullPath, rawPath string) bool {
	p := strings.ToLower(fullPath + " " + rawPath)
	for _, part := range skipOperatePathParts {
		if strings.Contains(p, part) {
			return true
		}
	}
	return false
}

func readRequestBody(c *gin.Context) []byte {
	if c.Request.Body == nil {
		return nil
	}
	payload, err := io.ReadAll(io.LimitReader(c.Request.Body, maxAuditBody+1))
	if err != nil {
		return nil
	}
	c.Request.Body = io.NopCloser(bytes.NewBuffer(payload))
	if len(payload) > maxAuditBody {
		return payload[:maxAuditBody]
	}
	return payload
}

func saveOperationLog(c *gin.Context, db *mongo.Database, payload []byte, start time.Time) {
	l := LoadFromHeader(c)
	fields := parseOperationFields(c, l, payload, start)

	now := time.Now()
	m := &operation.Model{}
	m.ID = primitive.NewObjectID()
	m.ClientIP = fields.clientIP
	m.RemoteIP = fields.remoteIP
	m.FullPath = fields.fullPath
	m.Method = fields.method
	m.RespCode = fields.respCode
	m.TargetID = fields.targetID
	m.TargetName = fields.targetName
	m.Device = fields.device
	m.Operator = fields.operator
	m.OperatorPhone = fields.operatorPhone
	m.LoginType = fields.loginType
	m.UserID = fields.userID
	m.AccountID = fields.accountID
	m.Timestamp = uint64(now.Unix())
	m.Before = fields.before
	m.After = fields.after
	m.Summary = BuildOperationSummary(fields.operator, fields.action, fields.resourceLabel, fields.targetID, fields.targetName)
	m.Resource = fields.resource
	m.ResourceLabel = fields.resourceLabel
	m.Action = fields.action
	m.RequestURI = fields.requestURI
	m.UserAgent = fields.userAgent
	m.MerchantID = fields.merchantID
	m.LatencyMs = fields.latencyMs
	m.TraceID = fields.traceID

	ctx := withLogIdentity(c.Request.Context(), l, fields.merchantID)
	handler := m.Init(ctx, db, m.CollectionName())
	m.Meta = completeMeta(handler.GetMeta(), fields.accessLevel, fields.respCode < 400, fields.merchantID, fields.accountID, fields.namespace, firstNonEmpty(fields.userID, fields.accountID))
	if _, err := handler.Context.Handler.Collection(handler.Context.Collection).InsertOne(ctx, m); err != nil {
		log.Log(ctx).WithError(err).
			WithField("path", fields.fullPath).
			WithField("method", fields.method).
			Warning("write operation log failed")
	}
}

type operationFields struct {
	clientIP      string
	remoteIP      string
	fullPath      string
	method        string
	respCode      int
	targetID      string
	targetName    string
	device        string
	operator      string
	operatorPhone string
	loginType     string
	userID        string
	accountID     string
	before        string
	after         string
	resource      string
	resourceLabel string
	action        string
	requestURI    string
	userAgent     string
	merchantID    string
	namespace     string
	traceID       string
	latencyMs     int64
	accessLevel   uint
}

func parseOperationFields(c *gin.Context, l LoginInfo, payload []byte, start time.Time) operationFields {
	method := c.Request.Method
	fullPath := strings.ReplaceAll(c.FullPath(), "/:_id", "")
	fullPath = strings.ReplaceAll(fullPath, "/:id", "")
	if fullPath == "" {
		fullPath = c.Request.URL.Path
	}

	body := extractBodyFields(payload)
	targetID, targetName := resolveTarget(c, body)
	resource, resourceLabel := ClassifyResource(fullPath)
	action := ActionFromRequest(method, fullPath, c.Request.URL.RawQuery)
	operator := firstNonEmpty(l.UserName, l.Phone, l.AccountID, l.UserID, "unknown")
	merchantID := firstNonEmpty(
		l.MerchantID,
		c.GetHeader("X-Tenant-ID"),
		c.GetHeader("X-Merchant-ID"),
		c.GetHeader("MerchantID"),
		body.MerchantID,
		l.Namespace,
	)
	userAgent := truncateRunes(c.Request.UserAgent(), 240)

	return operationFields{
		clientIP:      c.ClientIP(),
		remoteIP:      clientRemoteIP(c),
		fullPath:      fullPath,
		method:        method,
		respCode:      c.Writer.Status(),
		targetID:      targetID,
		targetName:    targetName,
		device:        firstNonEmpty(c.GetHeader("X-Device-ID"), c.GetHeader("X-Device-Id"), truncateRunes(userAgent, 180)),
		operator:      operator,
		operatorPhone: l.Phone,
		loginType:     l.LoginType,
		userID:        l.UserID,
		accountID:     l.AccountID,
		before:        contextString(c, "Before", "OldData"),
		after:         RedactJSON(payload),
		resource:      resource,
		resourceLabel: resourceLabel,
		action:        action,
		requestURI:    sanitizeURI(c.Request.URL),
		userAgent:     userAgent,
		merchantID:    merchantID,
		namespace:     l.Namespace,
		traceID:       requestTraceID(c),
		latencyMs:     time.Since(start).Milliseconds(),
		accessLevel:   parseAccessLevel(l.LoginLevel),
	}
}

func resolveTarget(c *gin.Context, body bodyFields) (id, name string) {
	id = firstNonEmpty(
		c.Param("_id"),
		c.Param("id"),
		c.Writer.Header().Get("TargetId"),
		contextString(c, "TargetId", "TargetID"),
		paramSuffixID(c),
		body.ID,
		c.Query("_id"),
		c.Query("id"),
	)
	name = firstNonEmpty(
		contextString(c, "TargetName"),
		body.Name,
		body.Phone,
	)
	return id, name
}

func paramSuffixID(c *gin.Context) string {
	for _, p := range c.Params {
		key := strings.ToLower(p.Key)
		if p.Value != "" && (key == "id" || key == "_id" || strings.HasSuffix(key, "_id") || strings.HasSuffix(key, "id")) {
			return p.Value
		}
	}
	return ""
}

type bodyFields struct {
	ID         string
	Name       string
	Phone      string
	UserID     string
	AccountID  string
	MerchantID string
	LoginType  string
	Type       string
}

func extractBodyFields(raw []byte) bodyFields {
	var out bodyFields
	raw = bytes.TrimSpace(raw)
	if len(raw) == 0 {
		return out
	}

	var v interface{}
	if err := json.Unmarshal(raw, &v); err != nil {
		values, err := url.ParseQuery(string(raw))
		if err != nil {
			return out
		}
		out.ID = firstNonEmpty(values.Get("id"), values.Get("_id"), values.Get("account_id"), values.Get("user_id"))
		out.Name = firstNonEmpty(values.Get("name"), values.Get("nickname"), values.Get("user_name"), values.Get("title"))
		out.Phone = values.Get("phone")
		out.UserID = values.Get("user_id")
		out.AccountID = values.Get("account_id")
		out.MerchantID = values.Get("merchant_id")
		out.LoginType = values.Get("login_type")
		out.Type = values.Get("type")
		return out
	}

	maps := collectMaps(v)
	out.ID = lookupString(maps, targetIDKeys...)
	out.Name = lookupString(maps, targetNameKeys...)
	out.Phone = lookupString(maps, "phone")
	out.UserID = lookupString(maps, "user_id")
	out.AccountID = lookupString(maps, "account_id")
	out.MerchantID = lookupString(maps, "merchant_id", "merchant")
	out.LoginType = lookupString(maps, "login_type")
	out.Type = lookupString(maps, "type")
	return out
}

func collectMaps(v interface{}) []map[string]interface{} {
	root, ok := v.(map[string]interface{})
	if !ok {
		return nil
	}
	out := []map[string]interface{}{root}
	for _, key := range nestedBodyKeys {
		child, ok := root[key].(map[string]interface{})
		if ok {
			out = append(out, child)
		}
	}
	return out
}

func lookupString(maps []map[string]interface{}, keys ...string) string {
	for _, m := range maps {
		for _, key := range keys {
			for k, raw := range m {
				if !strings.EqualFold(k, key) {
					continue
				}
				if s := stringify(raw); s != "" {
					return s
				}
			}
		}
	}
	return ""
}

func stringify(v interface{}) string {
	switch t := v.(type) {
	case string:
		return strings.TrimSpace(t)
	case json.Number:
		return t.String()
	case float64:
		if t == float64(int64(t)) {
			return strconv.FormatInt(int64(t), 10)
		}
		return strconv.FormatFloat(t, 'f', -1, 64)
	case json.RawMessage:
		return strings.Trim(strings.TrimSpace(string(t)), `"`)
	default:
		return ""
	}
}

func clientRemoteIP(c *gin.Context) string {
	if v := c.Request.Header.Get("X-Real-IP"); v != "" {
		return strings.TrimSpace(strings.Split(v, ",")[0])
	}
	if v := c.Request.Header.Get("X-Forwarded-For"); v != "" {
		return strings.TrimSpace(strings.Split(v, ",")[0])
	}
	return c.ClientIP()
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

func contextString(c *gin.Context, keys ...string) string {
	if c == nil {
		return ""
	}
	for _, key := range keys {
		if v, ok := c.Get(key); ok {
			if s := stringify(v); s != "" {
				return s
			}
		}
		if s, ok := c.Value(key).(string); ok && strings.TrimSpace(s) != "" {
			return strings.TrimSpace(s)
		}
		if c.Request != nil {
			if s, ok := c.Request.Context().Value(key).(string); ok && strings.TrimSpace(s) != "" {
				return strings.TrimSpace(s)
			}
		}
	}
	return ""
}

func requestTraceID(c *gin.Context) string {
	if id := log.TraceID(c.Request.Context()); id != "" {
		return id
	}
	if v, ok := c.Get("RequestID"); ok {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return firstNonEmpty(c.GetHeader("X-Request-ID"), c.GetHeader("X-Trace-ID"))
}

func parseAccessLevel(level string) uint {
	n, err := strconv.Atoi(strings.TrimSpace(level))
	if err != nil || n < 0 {
		return 0
	}
	return uint(n)
}

func withLogIdentity(ctx context.Context, l LoginInfo, merchantID string) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	if l.AccountID != "" {
		ctx = context.WithValue(ctx, model.AccountKey, l.AccountID)
	}
	if merchantID != "" {
		ctx = context.WithValue(ctx, model.MerchantKey, merchantID)
	}
	if l.Namespace != "" {
		ctx = context.WithValue(ctx, model.NamespaceKey, l.Namespace)
	}
	if op := firstNonEmpty(l.UserID, l.AccountID); op != "" {
		ctx = context.WithValue(ctx, model.OperatorKey, op)
	}
	return ctx
}

func completeMeta(meta model.MetaModel, accessLevel uint, success bool, merchantID, accountID, namespace, operator string) model.MetaModel {
	if accessLevel != 0 {
		meta.AccessLevel = accessLevel
	}
	meta.Status = success
	if meta.MerchantID == "" {
		meta.MerchantID = merchantID
	}
	if meta.AccountID == "" {
		meta.AccountID = accountID
	}
	if meta.Namespace == "" {
		meta.Namespace = namespace
	}
	if meta.Founder == "" {
		meta.Founder = operator
	}
	if meta.Updater == "" {
		meta.Updater = operator
	}
	if meta.CreatedAt == "" {
		now := time.Now().Unix()
		meta.CreatedAt = rtime.FomratTimeAsReader(now)
		meta.UpdatedAt = meta.CreatedAt
		meta.CreatedTime = now
		meta.UpdatedTime = now
	}
	return meta
}

// ClassifyResource 从请求路径识别业务资源，会员相关路径优先匹配。
func ClassifyResource(path string) (resource, name string) {
	p := strings.ToLower(path)
	switch {
	case strings.Contains(p, "/member/account"):
		return "member", "会员"
	case strings.Contains(p, "/member/addresses"), strings.Contains(p, "/addresses"):
		return "member_address", "会员地址"
	case strings.Contains(p, "/member/level"), strings.HasSuffix(p, "/level"), strings.Contains(p, "/level/"):
		return "member_level", "会员等级"
	case strings.Contains(p, "/member"):
		return "member", "会员"
	case strings.Contains(p, "/password"):
		return "password", "密码"
	case strings.Contains(p, "/auth/account") || strings.HasSuffix(p, "/account") || strings.Contains(p, "/account/"):
		return "admin_account", "管理账号"
	case strings.Contains(p, "/role"):
		return "role", "角色"
	case strings.Contains(p, "/tenant"):
		return "tenant", "站点"
	case strings.Contains(p, "/app"):
		return "app", "应用"
	case strings.Contains(p, "/store") || strings.Contains(p, "/info"):
		return "store", "门店"
	case strings.Contains(p, "/product"):
		return "product", "商品"
	case strings.Contains(p, "/order"):
		return "order", "订单"
	case strings.Contains(p, "/scm"):
		return "scm", "供应链"
	default:
		return "other", "其他"
	}
}

// ActionFromMethod 将 HTTP 方法映射为业务动作。
func ActionFromMethod(method string) string {
	switch strings.ToUpper(method) {
	case http.MethodPost:
		return "create"
	case http.MethodPut, http.MethodPatch:
		return "update"
	case http.MethodDelete:
		return "delete"
	default:
		return strings.ToLower(method)
	}
}

// ActionFromRequest 结合路径细化动作，例如 POST /send 记为 notify。
func ActionFromRequest(method, path, rawQuery string) string {
	p := strings.ToLower(path + " " + rawQuery)
	switch {
	case strings.Contains(p, "/send"):
		return "notify"
	case strings.Contains(p, "/transfer") || strings.Contains(p, "ts="):
		return "transfer"
	case strings.Contains(p, "/reset"):
		return "reset"
	case strings.Contains(p, "/enable") || strings.Contains(p, "/disable"):
		return "update"
	default:
		return ActionFromMethod(method)
	}
}

// BuildOperationSummary 生成可读的一行摘要。
func BuildOperationSummary(operator, action, resourceName, targetID, targetName string) string {
	verb := map[string]string{
		"create":   "新增",
		"update":   "更新",
		"delete":   "删除",
		"notify":   "通知",
		"transfer": "转移",
		"reset":    "重置",
	}[action]
	if verb == "" {
		verb = action
	}
	if operator == "" {
		operator = "系统"
	}
	if resourceName == "" {
		resourceName = "资源"
	}
	target := firstNonEmpty(targetName, shortID(targetID))
	if target == "" {
		return operator + " " + verb + "了 " + resourceName
	}
	return operator + " " + verb + "了 " + resourceName + " " + target
}

func shortID(id string) string {
	if utf8.RuneCountInString(id) <= 12 {
		return id
	}
	runes := []rune(id)
	return string(runes[:8]) + "…"
}

func truncateRunes(s string, n int) string {
	if n <= 0 || s == "" {
		return s
	}
	if utf8.RuneCountInString(s) <= n {
		return s
	}
	return string([]rune(s)[:n])
}

func sanitizeURI(u *url.URL) string {
	if u == nil {
		return ""
	}
	q := u.Query()
	for _, key := range []string{"token", "jwt", "password", "secret", "access_token", "code"} {
		if q.Has(key) {
			q.Set(key, "***")
		}
	}
	out := *u
	out.RawQuery = q.Encode()
	out.User = nil
	return out.RequestURI()
}

// RedactJSON 脱敏请求体中的密码、令牌等字段，供审计详情展示。
func RedactJSON(raw []byte) string {
	if len(bytes.TrimSpace(raw)) == 0 {
		return ""
	}
	var v interface{}
	if err := json.Unmarshal(raw, &v); err != nil {
		s := strings.TrimSpace(string(raw))
		return truncateRunes(s, maxAuditBody)
	}
	redactValue(v)
	b, err := json.Marshal(v)
	if err != nil {
		return ""
	}
	s := string(b)
	if len(s) > maxAuditBody {
		return s[:maxAuditBody] + "…"
	}
	return s
}

func redactValue(v interface{}) {
	switch t := v.(type) {
	case map[string]interface{}:
		for k, child := range t {
			if _, sensitive := sensitiveBodyKeys[strings.ToLower(k)]; sensitive {
				t[k] = "***"
				continue
			}
			redactValue(child)
		}
	case []interface{}:
		for _, child := range t {
			redactValue(child)
		}
	}
}
