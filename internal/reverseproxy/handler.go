package reverseproxy

import (
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"netkit/internal/config"
	"netkit/internal/ipvisitors"
	"netkit/internal/logcenter"
	"netkit/internal/safe"
)

// buildHandler 组装单条规则的请求处理链：
//
//	统计 → HTTP→HTTPS 跳转 → CORS → 子规则匹配 → 访问控制（全局IP/安全组/IP黑白名单/
//	BasicAuth/UA黑白名单/robots.txt）→ 按服务类型分派（proxy / redirect / urljump / file）
func (m *Manager) buildHandler(r *runningRule, c config.WebRule) http.Handler {
	return http.HandlerFunc(func(rawW http.ResponseWriter, req *http.Request) {
		startAt := time.Now()
		cw := &countingWriter{ResponseWriter: rawW}
		w := http.ResponseWriter(cw)

		var (
			statRuleID   string
			statRuleName string
			statBackend  string
			statBlocked  bool
			statRedirect bool
			statError    bool
		)
		defer func() {
			status := cw.status
			if status == 0 {
				status = 200
			}
			if statBlocked {
				status = 403
			}
			// statRedirect 仅作语义标记（Redirected 计数），状态码以实际写回为准
			in := RecordInput{
				RuleID:   statRuleID,
				RuleName: statRuleName,
				Method:   req.Method,
				Path:     req.URL.Path,
				Status:   status,
				BytesIn:  req.ContentLength,
				BytesOut: cw.bytes,
				Elapsed:  time.Since(startAt),
				Blocked:  statBlocked,
				Redirect: statRedirect,
				Error:    statError,
				Backend:  statBackend,
			}
			r.stats.Record(in)
			// 命中子规则时同步记入子规则的独立统计（供子规则"统计浮窗"）
			if statRuleID != "" {
				if ss := r.subStats[c.ID+"|"+statRuleID]; ss != nil {
					ss.Record(in)
				}
			}
		}()

		// 自动 HTTP → HTTPS（明文侧由同端口分流或独立跳转触发）
		if c.RedirectToHTTPS && req.TLS == nil && !isExcludedPath(req.URL.Path, c.RedirectExclude) {
			code := c.RedirectCode
			if code != 301 && code != 302 && code != 307 && code != 308 {
				code = 301
			}
			target := fmt.Sprintf("https://%s%s", safe.StripPort(req.Host), req.URL.RequestURI())
			http.Redirect(w, req, target, code)
			return
		}

		// CORS：跨域预检与允许头
		if c.CORSEnabled {
			origin := req.Header.Get("Origin")
			allowed := origin != "" && corsOriginAllowed(c.CORSOrigin, origin)
			if allowed {
				if c.CORSOrigin == "*" && !c.CORSCredentials {
					w.Header().Set("Access-Control-Allow-Origin", "*")
				} else {
					w.Header().Set("Access-Control-Allow-Origin", origin)
					w.Header().Add("Vary", "Origin")
				}
				if c.CORSCredentials {
					w.Header().Set("Access-Control-Allow-Credentials", "true")
				}
				if c.CORSMethods != "" {
					w.Header().Set("Access-Control-Allow-Methods", c.CORSMethods)
				} else {
					w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS, PATCH")
				}
				if c.CORSHeaders != "" {
					w.Header().Set("Access-Control-Allow-Headers", c.CORSHeaders)
				} else {
					w.Header().Set("Access-Control-Allow-Headers",
						"Content-Type, Authorization, X-Requested-With, Accept, Origin")
				}
				w.Header().Set("Access-Control-Max-Age", "86400")
			}
			if req.Method == http.MethodOptions && allowed {
				w.WriteHeader(http.StatusNoContent)
				return
			}
		}

		host := safe.StripPort(req.Host)
		ts := time.Now().Format("2006-01-02 15:04:05")
		clientIP := realClientIP(req, c.TrustedCIDRs)

		// 匹配子规则（按配置顺序，命中的即为准）
		var hit *config.WebSubRule
		for i := range c.SubRules {
			sr := &c.SubRules[i]
			if matchDomain(sr.Domains, host) && matchLocation(sr.Locations, req.URL.Path) {
				hit = sr
				break
			}
		}

		// 登记来源 IP（供"IP 访客"页）：命中子规则时来源标注具体子规则，便于追溯访问路径
		src := "Web服务"
		if hit != nil && hit.Name != "" {
			src = "Web服务[" + hit.Name + "]"
		}
		ipvisitors.Default().Record(clientIP, src)

		lc := logcenter.Default()

		// 全局 IP 过滤（拦截时直接终止，不进入任何子规则）
		if r.filter != nil && !r.filter(clientIP) {
			msg := fmt.Sprintf("%s [拦截] 全局IP过滤拒绝 %s %s %s", ts, clientIP, req.Method, req.URL.Path)
			if hit != nil {
				// 已匹配到子规则：双写规则环与子规则记录，并计入子规则统计
				statRuleID = hit.ID
				statRuleName = hit.Name
				r.addLog(hit.ID, msg+fmt.Sprintf(" (规则=%s)", hit.Name))
			} else {
				r.logs.Add(msg)
			}
			lc.Add("Web服务", logcenter.LevelWarn, "规则[%s] 全局IP过滤拒绝 %s (host=%s)", c.Name, clientIP, host)
			statBlocked = true
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}

		// —— 命中子规则时的访问控制（对所有服务类型生效）——
		if hit != nil {
			statRuleID = hit.ID
			statRuleName = hit.Name

			// 安全组 / IP 黑白名单
			allowed := true
			if hit.GroupID != "" {
				if g, ok := r.groups[hit.GroupID]; ok {
					allowed = safe.CheckGroup(g, clientIP)
				}
			} else if hit.FilterMode == "white" || hit.FilterMode == "black" {
				allowed = safe.CheckIP(hit.FilterMode, hit.FilterIPs, clientIP)
			}
			if !allowed {
				r.addLog(hit.ID, fmt.Sprintf("%s [拦截] IP过滤拒绝 %s %s %s (规则=%s)",
					ts, clientIP, req.Method, req.URL.Path, hit.Name))
				lc.Add("Web服务", logcenter.LevelWarn, "规则[%s] IP过滤拒绝 %s (host=%s)", hit.Name, clientIP, host)
				statBlocked = true
				http.Error(w, "Forbidden", http.StatusForbidden)
				return
			}

			// BasicAuth
			if hit.BasicUser != "" {
				u, p, ok := req.BasicAuth()
				if !ok || u != hit.BasicUser || p != hit.BasicPass {
					w.Header().Set("WWW-Authenticate", `Basic realm="netkit"`)
					r.addLog(hit.ID, fmt.Sprintf("%s [拒绝] BasicAuth失败 %s %s %s", ts, clientIP, req.Method, req.URL.Path))
					statBlocked = true
					http.Error(w, "Unauthorized", http.StatusUnauthorized)
					return
				}
			}

			// UserAgent 黑白名单
			if !matchUA(hit.UAMode, hit.UAList, req.UserAgent()) {
				r.addLog(hit.ID, fmt.Sprintf("%s [拦截] UA过滤拒绝 %s [%s] %s %s (规则=%s)",
					ts, clientIP, req.UserAgent(), req.Method, req.URL.Path, hit.Name))
				lc.Add("Web服务", logcenter.LevelWarn, "规则[%s] UA过滤拒绝 %s ua=%q", hit.Name, clientIP, req.UserAgent())
				statBlocked = true
				http.Error(w, "Forbidden", http.StatusForbidden)
				return
			}

			// 自定义 robots.txt（仅该子规则的域名/路径生效）
			if hit.CustomRobot && req.URL.Path == "/robots.txt" {
				if req.Method != http.MethodGet && req.Method != http.MethodHead {
					code := http.StatusMethodNotAllowed
					if req.Method == http.MethodOptions {
						code = http.StatusOK
					}
					w.Header().Set("Allow", "GET,HEAD,OPTIONS")
					w.WriteHeader(code)
					return
				}
				w.Header().Set("Content-Type", "text/plain; charset=utf-8")
				w.WriteHeader(http.StatusOK)
				if req.Method == http.MethodGet {
					io.WriteString(w, hit.RobotTxt)
				}
				return
			}
		}

		// —— 按服务类型分派 ——
		typ := "proxy"
		if hit != nil && hit.Type != "" {
			typ = hit.Type
		}
		switch typ {
		case "file":
			serveFile(r, hit, w, req, clientIP, ts)
			return
		case "redirect", "urljump":
			statRedirect = true
			serveJump(r, hit, w, req, clientIP, ts)
			return
		}

		// 反向代理（含默认后端）
		m.proxyFlow(r, c, hit, w, req, clientIP, ts, host, &statBackend, &statError)
	})
}

// corsOriginAllowed 判断 Origin 是否被允许：* 或精确匹配（支持逗号分隔多条）。
func corsOriginAllowed(allowed, origin string) bool {
	if allowed == "" {
		return true
	}
	for _, o := range strings.Split(allowed, ",") {
		o = strings.TrimSpace(o)
		if o == "*" || o == origin {
			return true
		}
	}
	return false
}
