package reverseproxy

import (
	"net"
	"net/http"
	"strings"

	"netkit/internal/config"
	"netkit/internal/safe"
)

// matchDomain 支持精确域名与通配符 *.example.com；域名留空表示匹配所有主机名。
// 配置项可能带端口（如 ddz.example.com:8585），与请求比较前统一去掉端口，
// 因为请求侧已经用 StripPort 取了纯主机名，且同一规则下端口必然相同。
func matchDomain(domains []string, host string) bool {
	if len(domains) == 0 {
		return true
	}
	h := strings.ToLower(host)
	for _, d := range domains {
		d = strings.ToLower(strings.TrimSpace(d))
		if d == "" {
			continue
		}
		if hd := stripPortLoose(d); hd != "" {
			d = hd
		}
		if d == h {
			return true
		}
		if strings.HasPrefix(d, "*.") {
			suffix := d[1:] // ".example.com"
			if strings.HasSuffix(h, suffix) && len(h) > len(suffix) {
				return true
			}
		}
	}
	return false
}

// stripPortLoose 去掉 host:port 形式里的端口；解析不了或无端口时返回空。
func stripPortLoose(s string) string {
	// 普通 host:port（含 IPv6 [::1]:8080）
	if host, _, err := net.SplitHostPort(s); err == nil && host != "" {
		return host
	}
	// 通配符域名带端口：*.example.com:8443
	if i := strings.LastIndex(s, ":"); i > 0 && i < len(s)-1 {
		tail := s[i+1:]
		allDigits := true
		for _, ch := range tail {
			if ch < '0' || ch > '9' {
				allDigits = false
				break
			}
		}
		if allDigits {
			return s[:i]
		}
	}
	return ""
}

// matchLocation URL 路由匹配：空表示匹配全部；支持前缀匹配。
func matchLocation(locations []string, path string) bool {
	if len(locations) == 0 {
		return true
	}
	for _, loc := range locations {
		loc = strings.TrimSpace(loc)
		if loc == "" || loc == "/" {
			return true
		}
		if strings.HasPrefix(path, loc) {
			return true
		}
	}
	return false
}

// isExcludedPath 判断路径是否在跳转例外列表中（前缀匹配）。
func isExcludedPath(path string, excludes []string) bool {
	for _, e := range excludes {
		e = strings.TrimSpace(e)
		if e == "" {
			continue
		}
		if strings.HasPrefix(path, e) {
			return true
		}
	}
	return false
}

// realClientIP 在可信代理网段内时，从 X-Forwarded-For 取真实客户端 IP。
func realClientIP(req *http.Request, trusted []string) string {
	peer := safe.StripPort(req.RemoteAddr)
	if len(trusted) == 0 {
		return peer
	}
	if !safe.CheckIP("white", trusted, peer) {
		return peer // 非可信来源，忽略伪造头
	}
	if fwd := req.Header.Get("X-Forwarded-For"); fwd != "" {
		parts := strings.Split(fwd, ",")
		// 从右往左找第一个不在可信网段内的地址
		for i := len(parts) - 1; i >= 0; i-- {
			ip := strings.TrimSpace(parts[i])
			if ip == "" {
				continue
			}
			if !safe.CheckIP("white", trusted, ip) {
				return ip
			}
		}
		return strings.TrimSpace(parts[0])
	}
	return peer
}

// matchUA UserAgent 黑白名单：关键字包含匹配。
// white 模式要求命中任一关键字，black 模式命中任一即拒绝，none 或空名单放行。
func matchUA(mode string, list []string, ua string) bool {
	switch mode {
	case "white", "black":
	default:
		return true
	}
	hit := false
	for _, kw := range list {
		kw = strings.TrimSpace(kw)
		if kw == "" {
			continue
		}
		if strings.Contains(ua, kw) {
			hit = true
			break
		}
	}
	if mode == "white" {
		return hit
	}
	return !hit
}

// hcFrom 把配置转换成内部健康检查结构。
func hcFrom(h config.HealthCheck) healthCfg {
	t := h.Type
	if t == "" {
		t = "http"
	}
	return healthCfg{
		enabled:   h.Enabled,
		hcType:    t,
		path:      h.Path,
		interval:  h.Interval,
		timeout:   h.Timeout,
		maxFailed: h.MaxFailed,
		headers:   h.Headers,
	}
}
