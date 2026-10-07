package middle

import "strings"

// PathClass is the service and module parsed from an API path.
// Service matches the x9 app (client, member, order, auth). Module is the
// concrete screen under that app (launch, account, commands). Labels are the
// default Chinese fallback; x9 translates service and module per locale.
type PathClass struct {
	Namespace string
	Service   string
	Module    string
	Resource  string
	Label     string
}

var pathNamespaces = map[string]struct{}{
	"hlj":    {},
	"system": {},
	"gyb":    {},
}

var pathServices = map[string]struct{}{
	"client":    {},
	"member":    {},
	"order":     {},
	"product":   {},
	"store":     {},
	"finance":   {},
	"device":    {},
	"feedback":  {},
	"active":    {},
	"scm":       {},
	"transport": {},
	"merchant":  {},
	"auth":      {},
	"fs":        {},
	"pay":       {},
	"data":      {},
	"message":   {},
}

// Platforms sit between the service and the module and are not a business module.
var pathPlatforms = map[string]struct{}{
	"mini":   {},
	"pos":    {},
	"pad":    {},
	"rpc":    {},
	"open":   {},
	"common": {},
	"admin":  {},
}

// Modules that appear without a service segment.
var orphanModules = map[string]struct{ service, module string }{
	"password":  {"auth", "password"},
	"products":  {"product", "products"},
	"property":  {"product", "property"},
	"menu":      {"product", "menu"},
	"material":  {"scm", "material"},
	"supplier":  {"scm", "supplier"},
	"recipe":    {"scm", "recipe"},
	"inventory": {"scm", "inventory"},
	"purchase":  {"scm", "purchase"},
	"inbound":   {"scm", "inbound"},
	"outbound":  {"scm", "outbound"},
	"process":   {"scm", "process"},
	"stocktake": {"scm", "stocktake"},
	"campaign":  {"active", "campaign"},
	"coupon":    {"active", "coupon"},
	"ticket":    {"active", "ticket"},
	"record":    {"active", "record"},
	"qrcode":    {"store", "qrcode"},
}

var zhService = map[string]string{
	"client":    "终端管理",
	"member":    "会员中心",
	"order":     "订单管理",
	"product":   "产品管理",
	"store":     "门店管理",
	"finance":   "财务管理",
	"device":    "设备管理",
	"feedback":  "用户反馈",
	"active":    "营销活动",
	"scm":       "供应链",
	"transport": "物流配送",
	"merchant":  "商户",
	"auth":      "权限管理",
	"fs":        "文件系统",
	"pay":       "支付",
	"data":      "数据",
	"message":   "消息",
}

var zhModule = map[string]map[string]string{
	"client": {
		"launch":       "启动配置",
		"theme":        "视觉模版",
		"notification": "通知中心",
		"mp":           "微信小程序",
		"message":      "消息",
	},
	"member": {
		"account":    "会员账户",
		"addresses":  "会员地址",
		"level":      "会员层级",
		"profile":    "会员资料",
		"login":      "会员登录",
		"attendance": "考勤",
	},
	"product": {
		"categories": "分类",
		"property":   "规格",
		"menu":       "菜谱",
		"products":   "产品",
	},
	"order": {
		"commands":  "订单",
		"data":      "数据",
		"analytics": "统计分析",
		"place":     "下单",
		"pad":       "平板点餐",
		"topup":     "充值",
	},
	"store": {
		"info":   "门店信息",
		"topup":  "充值",
		"qrcode": "桌码",
	},
	"finance": {
		"keys":     "密钥",
		"flow":     "交易流水",
		"handover": "交接记录",
		"shift":    "班次",
	},
	"device": {
		"printer": "打印机",
		"ptpl":    "模版",
	},
	"feedback": {
		"tag":     "标签",
		"reviews": "评论",
		"chat":    "聊天",
		"rating":  "评分",
		"bounty":  "有奖反馈",
		"payroll": "测试周薪",
		"service": "在线客服",
	},
	"active": {
		"campaign": "活动",
		"coupon":   "优惠券",
		"ticket":   "用户券",
		"record":   "核销记录",
	},
	"transport": {
		"orders":    "物流订单",
		"addresses": "发货地址",
		"vehicles":  "车辆",
		"matching":  "货物匹配",
		"fleets":    "车队",
		"routes":    "线路",
		"platforms": "平台管理",
		"takeout":   "外卖",
	},
	"scm": {
		"material":   "物料",
		"categories": "物料分类",
		"supplier":   "供应商",
		"recipe":     "配方",
		"inventory":  "库存",
		"purchase":   "采购单",
		"inbound":    "入库单",
		"outbound":   "出库单",
		"process":    "加工单",
		"stocktake":  "盘点单",
		"equipment":  "厨房设备",
	},
	"auth": {
		"account":  "账号",
		"role":     "角色",
		"app":      "功能",
		"tenant":   "业主站点",
		"plan":     "套餐",
		"billing":  "计费",
		"partner":  "开放账号",
		"password": "密码",
	},
	"fs": {
		"image": "图片管理",
	},
	"pay": {
		"scan":     "扫码支付",
		"cash":     "现金支付",
		"balance":  "余额支付",
		"mini":     "小程序支付",
		"callback": "支付回调",
	},
}

// ClassifyPath splits /v1/{namespace}/{service}/{module} into the x9 service and module.
// /v1/hlj/client/launch → service client, module launch.
func ClassifyPath(path string) PathClass {
	segs := pathSegments(path)
	if len(segs) == 0 {
		return otherClass()
	}
	ns := ""
	if _, ok := pathNamespaces[segs[0]]; ok {
		ns = segs[0]
		segs = segs[1:]
	}
	if len(segs) == 0 {
		return otherClass()
	}
	service := segs[0]
	rest := segs[1:]
	if _, ok := pathServices[service]; !ok {
		orphan, ok := orphanModules[service]
		if !ok {
			return otherClass()
		}
		service = orphan.service
		rest = append([]string{orphan.module}, rest...)
	}
	module := pickModule(service, rest)
	if service == "fs" && (module == "" || module == "client" || hasSegment(rest, "image")) {
		module = "image"
	}
	return finishClass(ns, service, module)
}

func otherClass() PathClass {
	return PathClass{Resource: "other", Label: "其他"}
}

func finishClass(ns, service, module string) PathClass {
	if service == "" {
		return otherClass()
	}
	return PathClass{
		Namespace: ns,
		Service:   service,
		Module:    module,
		Resource:  legacyResource(service, module),
		Label:     zhClassLabel(service, module),
	}
}

func legacyResource(service, module string) string {
	switch service {
	case "fs":
		return "image"
	case "member":
		switch module {
		case "addresses", "address":
			return "member_address"
		case "level":
			return "member_level"
		default:
			return "member"
		}
	case "auth":
		switch module {
		case "account":
			return "admin_account"
		case "role":
			return "role"
		case "tenant":
			return "tenant"
		case "app":
			return "app"
		case "password":
			return "password"
		case "":
			return "auth"
		default:
			return module
		}
	case "active":
		return "campaign"
	default:
		return service
	}
}

func zhClassLabel(service, module string) string {
	svc := zhService[service]
	if svc == "" {
		svc = service
	}
	mod := ""
	if table, ok := zhModule[service]; ok {
		mod = table[module]
	}
	if mod == "" {
		mod = module
	}
	if mod == "" {
		return svc
	}
	return svc + " · " + mod
}

func pathSegments(path string) []string {
	path = strings.Split(path, "?")[0]
	raw := strings.Split(strings.ToLower(path), "/")
	out := make([]string, 0, len(raw))
	for _, part := range raw {
		part = strings.TrimSpace(part)
		if part == "" || strings.HasPrefix(part, ":") {
			continue
		}
		out = append(out, part)
	}
	if len(out) > 0 && out[0] == "v1" {
		out = out[1:]
	}
	return out
}

func pickModule(service string, rest []string) string {
	skipped := ""
	for _, part := range rest {
		if _, ok := pathPlatforms[part]; ok {
			if skipped == "" {
				skipped = part
			}
			continue
		}
		return aliasModule(service, part)
	}
	if skipped != "" {
		return aliasModule(service, skipped)
	}
	return ""
}

func aliasModule(service, module string) string {
	switch module {
	case "mp-dist":
		return "mp"
	case "notify":
		if service == "client" {
			return "notification"
		}
	case "address":
		if service == "member" {
			return "addresses"
		}
	}
	return module
}

func hasSegment(parts []string, want string) bool {
	for _, part := range parts {
		if part == want {
			return true
		}
	}
	return false
}
