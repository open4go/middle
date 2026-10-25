package middle

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
)

func ctxWith(t *testing.T, host string, headers map[string]string) *gin.Context {
	t.Helper()
	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	req := httptest.NewRequest(http.MethodPost, "http://"+host+"/v1/x", nil)
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	c.Request = req
	return c
}

func TestResolveClientHeader(t *testing.T) {
	cases := []struct {
		name, host string
		h          map[string]string
		code, ver  string
	}{
		{"header wins over host", "menu.huangliji.tech", map[string]string{"X-Client-Id": "X9", "X-Client-Version": "v0.0.118"}, "x9", "0.0.118"},
		{"new client passes through", "localhost", map[string]string{"X-Client-Id": "x7", "X-Client-Version": "1.2.3-beta.1"}, "x7", "1.2.3-beta.1"},
		{"illegal code dropped", "localhost", map[string]string{"X-Client-Id": "x9;drop", "X-Client-Version": "<script>"}, "", ""},
		{"too long dropped", "localhost", map[string]string{"X-Client-Id": "abcdefghijklmnopqrstuvwxyz0123456789"}, "", ""},
		{"wechat mini program ua", "localhost", map[string]string{"User-Agent": "Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) MicroMessenger/8.0.44 miniProgram"}, "x2", ""},
		{"wechat appid header", "localhost", map[string]string{"X-WeChat-AppId": "wx123"}, "x2", ""},
		{"host admin", "admin.huangliji.tech", nil, "x9", ""},
		{"host tenant", "shop1.tenant.huangliji.tech", nil, "x9", ""},
		{"host menu", "menu.huangliji.tech:443", nil, "x6", ""},
		{"host pad via origin", "10.0.0.1", map[string]string{"Origin": "https://pad.huangliji.tech"}, "x5", ""},
		{"unknown", "localhost", nil, "", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			code, ver := ResolveClient(ctxWith(t, tc.host, tc.h))
			if code != tc.code || ver != tc.ver {
				t.Fatalf("got %q %q want %q %q", code, ver, tc.code, tc.ver)
			}
		})
	}
}

func TestClientNameExtensible(t *testing.T) {
	if ClientName("") != "未知" {
		t.Fatal("empty should be 未知")
	}
	if ClientName("x2") != "大厅小程序" || ClientName("X9") != "后台管理" || ClientName("x6") != "点餐端" || ClientName("x5") != "出餐管理端" {
		t.Fatal("builtin names")
	}
	if ClientName("x42") != "x42" {
		t.Fatal("unregistered code must pass through")
	}
	RegisterClient("x42", "测试端")
	if ClientName("x42") != "测试端" {
		t.Fatal("registered")
	}
	found := false
	for _, o := range ClientOptions() {
		if o.Code == "x42" {
			found = true
		}
	}
	if !found {
		t.Fatal("options should include registered client")
	}
}

func TestParseDeviceZH(t *testing.T) {
	cases := []struct{ ua, want string }{
		{"", "未知设备"},
		{"Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148 MicroMessenger/8.0.44(0x18002c2f) NetType/WIFI Language/zh_CN miniProgram/wx123", "iPhone · iOS 17.2 · 微信小程序"},
		{"Mozilla/5.0 (Linux; Android 13; PGJM10 Build/TP1A.220905.001; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/116.0.0.0 Mobile Safari/537.36 XWEB/1160065 MMWEBSDK/20231201 MMWEBID/1 MicroMessenger/8.0.44 miniProgram/wx123", "Android 13 · PGJM10 · 微信小程序"},
		{"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36", "Windows 10/11 · Chrome 浏览器 120"},
		{"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0", "Windows 10/11 · Edge 浏览器 120"},
		{"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Safari/605.1.15", "macOS · Safari 浏览器 17"},
		{"Mozilla/5.0 (Macintosh; Intel Mac OS X 14_2) Gecko/20100101 Firefox/121.0", "macOS 14.2 · 火狐浏览器 121"},
		{"Mozilla/5.0 (iPad; CPU OS 16_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.6 Mobile/15E148 Safari/604.1", "iPad · iOS 16.6 · Safari 浏览器 16"},
		{"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) zhidian-pos/0.0.16 Chrome/118.0.0.0 Electron/27.0.0 Safari/537.36", "Windows 10/11 · 桌面客户端"},
		{"Mozilla/5.0 (Linux; Android 12; Pad Build/SP1A; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/110.0.0.0 Safari/537.36", "Android 12 · Pad · 应用内浏览器 110"},
		{"curl/8.4.0", "程序调用 · curl"},
		{"SomethingWeird/1.0", "未知设备"},
	}
	for _, tc := range cases {
		if got := ParseDeviceZH(tc.ua); got != tc.want {
			t.Errorf("ua=%q\n got  %q\n want %q", tc.ua, got, tc.want)
		}
	}
}

func TestClientRemoteIP(t *testing.T) {
	cases := []struct {
		name string
		h    map[string]string
		want string
	}{
		{"nginx real ip", map[string]string{"X-Real-IP": "114.114.114.114"}, "114.114.114.114"},
		{"xff fallback", map[string]string{"X-Forwarded-For": "1.2.3.4, 10.0.0.1"}, "1.2.3.4"},
		{"cf edge uses cf header", map[string]string{"X-Real-IP": "172.69.1.1", "CF-Connecting-IP": "2408:8000::1"}, "2408:8000::1"},
		{"spoofed cf header ignored when peer is not cloudflare", map[string]string{"X-Real-IP": "9.9.9.9", "CF-Connecting-IP": "8.8.8.8"}, "9.9.9.9"},
		{"garbage ignored", map[string]string{"X-Real-IP": "<script>", "X-Forwarded-For": "5.6.7.8"}, "5.6.7.8"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := ctxWith(t, "localhost", tc.h)
			if got := clientRemoteIP(c); got != tc.want {
				t.Fatalf("got %q want %q", got, tc.want)
			}
		})
	}
}

func TestLocateIPZH(t *testing.T) {
	t.Cleanup(func() { SetIPLocator(nil) })
	SetIPLocator(nil)
	if LocateIPZH("192.168.1.8") != "内网地址" || LocateIPZH("127.0.0.1") != "内网地址" {
		t.Fatal("private")
	}
	if LocateIPZH("114.114.114.114") != "" {
		t.Fatal("no locator => empty")
	}
	if LocateIPZH("not-an-ip") != "" {
		t.Fatal("invalid")
	}
	SetIPLocator(func(ip string) string { return "江苏南京 联通 " + ip })
	if LocateIPZH("114.114.114.114") != "江苏南京 联通 114.114.114.114" {
		t.Fatal("locator")
	}
}
