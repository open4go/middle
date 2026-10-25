package middle

import (
	"net/url"
	"os"
	"regexp"
	"sort"
	"strings"
	"sync"

	"github.com/gin-gonic/gin"
)

// 调用端（来源端）识别。
//
// 前端在每个请求里带两个头：
//
//	X-Client-Id       调用端编码，例如 x9 / x6 / x5 / x2
//	X-Client-Version  调用端版本号，例如 0.0.118
//
// 这两个值由客户端自己上报，只用于审计日志的展示与筛选，绝不能用于鉴权。
// 没带头时按 UA / 域名兜底；都识别不出来则为空，展示为「未知」。
//
// 新增调用端：在 defaultClientNames 里加一行，或启动时调用 RegisterClient，
// 或设置环境变量 AUDIT_CLIENTS="x7=收银台,x3=商家小程序"，无需改其它代码。

const (
	// HeaderClientID 调用端编码请求头
	HeaderClientID = "X-Client-Id"
	// HeaderClientVersion 调用端版本号请求头
	HeaderClientVersion = "X-Client-Version"
	// UnknownClientName 旧数据或识别不出时的展示名
	UnknownClientName = "未知"
)

var defaultClientNames = map[string]string{
	"x2": "大厅小程序",
	"x9": "后台管理",
	"x6": "点餐端",
	"x5": "出餐管理端",
}

// 域名兜底：取域名第一段。仅在没带 X-Client-Id 时使用，可用 AUDIT_CLIENT_HOSTS 覆盖，
// 例如 AUDIT_CLIENT_HOSTS="admin=x9,menu=x6"。
var defaultClientHostLabels = map[string]string{
	"admin": "x9",
	"super": "x9",
	"mch":   "x9",
	"menu":  "x6",
	"pad":   "x5",
	"mini":  "x2",
}

var (
	clientMu     sync.RWMutex
	clientNames  = map[string]string{}
	clientHosts  = map[string]string{}
	clientInitMu sync.Once

	clientCodeRe    = regexp.MustCompile(`^[a-z0-9][a-z0-9_.-]{0,31}$`)
	clientVersionRe = regexp.MustCompile(`^[0-9A-Za-z][0-9A-Za-z._+-]{0,31}$`)
)

func initClients() {
	clientInitMu.Do(func() {
		clientMu.Lock()
		defer clientMu.Unlock()
		for k, v := range defaultClientNames {
			clientNames[k] = v
		}
		for k, v := range defaultClientHostLabels {
			clientHosts[k] = v
		}
		for code, name := range parsePairs(os.Getenv("AUDIT_CLIENTS")) {
			if c := NormalizeClientCode(code); c != "" && name != "" {
				clientNames[c] = name
			}
		}
		for host, code := range parsePairs(os.Getenv("AUDIT_CLIENT_HOSTS")) {
			if c := NormalizeClientCode(code); c != "" {
				clientHosts[strings.ToLower(host)] = c
			}
		}
	})
}

func parsePairs(raw string) map[string]string {
	out := map[string]string{}
	for _, part := range strings.Split(raw, ",") {
		kv := strings.SplitN(part, "=", 2)
		if len(kv) != 2 {
			continue
		}
		k, v := strings.TrimSpace(kv[0]), strings.TrimSpace(kv[1])
		if k != "" && v != "" {
			out[k] = v
		}
	}
	return out
}

// RegisterClient 注册（或改名）一个调用端。线程安全。
func RegisterClient(code, name string) {
	initClients()
	code = NormalizeClientCode(code)
	name = strings.TrimSpace(name)
	if code == "" || name == "" {
		return
	}
	clientMu.Lock()
	clientNames[code] = name
	clientMu.Unlock()
}

// NormalizeClientCode 校验并规范化调用端编码：小写，只允许字母数字和 _ . -，最长 32；非法返回空。
func NormalizeClientCode(code string) string {
	code = strings.ToLower(strings.TrimSpace(code))
	if !clientCodeRe.MatchString(code) {
		return ""
	}
	return code
}

// NormalizeClientVersion 校验调用端版本号，允许前缀 v；非法返回空。
func NormalizeClientVersion(v string) string {
	v = strings.TrimSpace(v)
	if len(v) > 1 && (v[0] == 'v' || v[0] == 'V') && v[1] >= '0' && v[1] <= '9' {
		v = v[1:]
	}
	if !clientVersionRe.MatchString(v) {
		return ""
	}
	return v
}

// ClientName 返回调用端中文名。空编码返回「未知」；未登记的编码原样返回（不丢信息）。
func ClientName(code string) string {
	initClients()
	code = strings.TrimSpace(code)
	if code == "" {
		return UnknownClientName
	}
	clientMu.RLock()
	name, ok := clientNames[strings.ToLower(code)]
	clientMu.RUnlock()
	if ok {
		return name
	}
	return code
}

// ClientOption 给筛选下拉用。
type ClientOption struct {
	Code string `json:"code"`
	Name string `json:"name"`
}

// ClientOptions 返回所有已登记的调用端（按编码排序）。
func ClientOptions() []ClientOption {
	initClients()
	clientMu.RLock()
	defer clientMu.RUnlock()
	out := make([]ClientOption, 0, len(clientNames))
	for k, v := range clientNames {
		out = append(out, ClientOption{Code: k, Name: v})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Code < out[j].Code })
	return out
}

// ResolveClient 识别调用端编码与版本号。
// 顺序：X-Client-Id 头 → 微信小程序特征（x2）→ Origin / Referer / Host 的域名。识别不出返回空。
func ResolveClient(c *gin.Context) (code, version string) {
	if c == nil || c.Request == nil {
		return "", ""
	}
	initClients()
	version = NormalizeClientVersion(c.GetHeader(HeaderClientVersion))
	if code = NormalizeClientCode(c.GetHeader(HeaderClientID)); code != "" {
		return code, version
	}
	if c.GetHeader("X-WeChat-AppId") != "" || isWeChatMiniProgramUA(c.Request.UserAgent()) {
		return "x2", version
	}
	for _, h := range []string{c.GetHeader("Origin"), c.GetHeader("Referer"), c.Request.Host} {
		if code = clientFromHost(h); code != "" {
			return code, version
		}
	}
	return "", version
}

func clientFromHost(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	host := raw
	if strings.Contains(raw, "://") {
		u, err := url.Parse(raw)
		if err != nil {
			return ""
		}
		host = u.Host
	}
	if i := strings.IndexByte(host, ':'); i >= 0 {
		host = host[:i]
	}
	host = strings.ToLower(host)
	label := host
	if i := strings.IndexByte(host, '.'); i >= 0 {
		label = host[:i]
	}
	clientMu.RLock()
	defer clientMu.RUnlock()
	// *.tenant.xxx 都是后台
	if strings.Contains(host, ".tenant.") {
		return clientHosts["admin"]
	}
	return clientHosts[label]
}
