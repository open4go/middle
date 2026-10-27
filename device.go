package middle

import (
	"regexp"
	"strings"
)

// 把 User-Agent 解析成中文设备描述，例如：
//
//	iPhone · iOS 17.2 · 微信小程序
//	Android 13 · PGJM10 · 微信小程序
//	Windows 10/11 · Chrome 浏览器 120
//	Windows · 智点客户端
//
// 解析不出来时返回「未知设备」。原始 UA 仍保存在 user_agent 字段里，不丢信息。

const unknownDevice = "未知设备"

var (
	reIOS       = regexp.MustCompile(`(?i)(iPhone|iPad|iPod)[^)]*?OS (\d+)[_.](\d+)(?:[_.](\d+))?`)
	reAndroid   = regexp.MustCompile(`(?i)Android[ /]?([\d.]+)?;?\s*([^;)]*)`)
	reWindows   = regexp.MustCompile(`Windows NT (\d+\.\d+)`)
	reMac       = regexp.MustCompile(`Mac OS X (\d+)[_.](\d+)(?:[_.](\d+))?`)
	reEdge      = regexp.MustCompile(`Edg(?:e|A|iOS)?/(\d+)`)
	reChrome    = regexp.MustCompile(`(?:Chrome|CriOS)/(\d+)`)
	reFirefox   = regexp.MustCompile(`(?:Firefox|FxiOS)/(\d+)`)
	reSafari    = regexp.MustCompile(`Version/(\d+)[\d.]* (?:Mobile/\S+ )?Safari`)
	reWeChat    = regexp.MustCompile(`MicroMessenger/([\d.]+)`)
	reQQBrowser = regexp.MustCompile(`M?QQBrowser/(\d+)`)
	reUC        = regexp.MustCompile(`UCBrowser/(\d+)`)
	reBuild     = regexp.MustCompile(`\s*Build/.*$`)
)

func isWeChatMiniProgramUA(ua string) bool {
	l := strings.ToLower(ua)
	return strings.Contains(l, "miniprogram")
}

// ParseDeviceZH 把 UA 解析成中文设备描述。
func ParseDeviceZH(ua string) string {
	ua = strings.TrimSpace(ua)
	if ua == "" {
		return unknownDevice
	}
	if tool := toolFromUA(ua); tool != "" {
		return "程序调用 · " + tool
	}

	var parts []string
	switch {
	case reIOS.MatchString(ua):
		m := reIOS.FindStringSubmatch(ua)
		dev := m[1]
		if strings.EqualFold(dev, "iphone") {
			dev = "iPhone"
		} else if strings.EqualFold(dev, "ipad") {
			dev = "iPad"
		} else {
			dev = "iPod"
		}
		parts = append(parts, dev, "iOS "+m[2]+"."+m[3])
	case strings.Contains(ua, "Android"):
		m := reAndroid.FindStringSubmatch(ua)
		ver, model := "", ""
		if m != nil {
			ver = m[1]
			model = strings.TrimSpace(reBuild.ReplaceAllString(m[2], ""))
		}
		if strings.EqualFold(model, "wv") || strings.EqualFold(model, "U") || strings.HasPrefix(strings.ToLower(model), "zh-") || strings.HasPrefix(strings.ToLower(model), "en-") {
			model = ""
		}
		if ver != "" {
			parts = append(parts, "Android "+ver)
		} else {
			parts = append(parts, "Android")
		}
		if model != "" {
			parts = append(parts, model)
		}
	case reWindows.MatchString(ua):
		parts = append(parts, windowsName(reWindows.FindStringSubmatch(ua)[1]))
	case reMac.MatchString(ua) || strings.Contains(ua, "Macintosh"):
		name := "macOS"
		if m := reMac.FindStringSubmatch(ua); m != nil {
			// Chrome / Safari 把版本冻结在 10_15_7，没有参考价值
			if m[1] != "10" || m[2] != "15" {
				name += " " + m[1] + "." + m[2]
			}
		}
		parts = append(parts, name)
	case strings.Contains(ua, "CrOS"):
		parts = append(parts, "ChromeOS")
	case strings.Contains(ua, "Linux") || strings.Contains(ua, "X11"):
		parts = append(parts, "Linux")
	}

	app := appFromUA(ua)
	if app != "" {
		parts = append(parts, app)
	}
	if len(parts) == 0 {
		return unknownDevice
	}
	return strings.Join(parts, " · ")
}

func windowsName(nt string) string {
	switch nt {
	case "10.0":
		return "Windows 10/11"
	case "6.3":
		return "Windows 8.1"
	case "6.2":
		return "Windows 8"
	case "6.1":
		return "Windows 7"
	default:
		return "Windows"
	}
}

func appFromUA(ua string) string {
	switch {
	case isWeChatMiniProgramUA(ua):
		return "微信小程序"
	case strings.Contains(ua, "Electron/"):
		return "桌面客户端"
	case reWeChat.MatchString(ua):
		return "微信内置浏览器"
	case reQQBrowser.MatchString(ua):
		return "QQ 浏览器 " + reQQBrowser.FindStringSubmatch(ua)[1]
	case reUC.MatchString(ua):
		return "UC 浏览器 " + reUC.FindStringSubmatch(ua)[1]
	case reEdge.MatchString(ua):
		return "Edge 浏览器 " + reEdge.FindStringSubmatch(ua)[1]
	case strings.Contains(ua, "OPR/") || strings.Contains(ua, "Opera"):
		return "Opera 浏览器"
	case reFirefox.MatchString(ua):
		return "火狐浏览器 " + reFirefox.FindStringSubmatch(ua)[1]
	case reChrome.MatchString(ua):
		name := "Chrome 浏览器 "
		if strings.Contains(ua, "; wv)") {
			name = "应用内浏览器 "
		}
		return name + reChrome.FindStringSubmatch(ua)[1]
	case reSafari.MatchString(ua):
		return "Safari 浏览器 " + reSafari.FindStringSubmatch(ua)[1]
	}
	return ""
}

func toolFromUA(ua string) string {
	l := strings.ToLower(ua)
	for _, t := range []struct{ key, name string }{
		{"curl/", "curl"},
		{"postmanruntime", "Postman"},
		{"go-http-client", "Go"},
		{"python-requests", "Python"},
		{"okhttp/", "okhttp"},
		{"apache-httpclient", "Java"},
		{"axios/", "axios"},
		{"node-fetch", "Node"},
	} {
		if strings.Contains(l, t.key) && !strings.Contains(l, "mozilla/") {
			return t.name
		}
	}
	return ""
}

// LooksLikeRawUA 判断一个旧的 device 值是不是原始 UA（旧数据把 UA 直接写进了 device）。
func LooksLikeRawUA(s string) bool {
	return strings.Contains(s, "Mozilla/") || strings.Contains(s, "AppleWebKit") || strings.Contains(s, "Dalvik/")
}
