package reverseproxy

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"sync"
	"time"

	"netkit/internal/config"
	"netkit/internal/logcenter"
)

// getInsecureRT 复用一个忽略后端证书验证的 Transport（子规则勾选"忽略后端TLS证书验证"时用）。
var (
	insecureRTOnce sync.Once
	insecureRTPtr  http.RoundTripper
)

func getInsecureRT() http.RoundTripper {
	insecureRTOnce.Do(func() {
		t := http.DefaultTransport.(*http.Transport).Clone()
		t.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
		insecureRTPtr = t
	})
	return insecureRTPtr
}

// proxyFlow 反向代理主流程：选后端 → 访问控制后的转发 → 失败重试。
// hit 为 nil 时走规则的默认后端。
func (m *Manager) proxyFlow(r *runningRule, c config.WebRule, hit *config.WebSubRule,
	w http.ResponseWriter, req *http.Request, clientIP, ts, host string,
	statBackend *string, statError *bool) {

	lc := logcenter.Default()
	poolKey := r.poolKey("")
	subID := "" // 命中的子规则ID，用于把日志同步写入子规则独立日志环
	var setHeaders map[string]string
	var hideHeaders []string
	var addHeaders map[string]string
	var appendIPHeader string
	var insecureSkip, useTargetHost bool
	if hit != nil {
		poolKey = r.poolKey(hit.ID)
		subID = hit.ID
		setHeaders = hit.SetHeaders
		hideHeaders = hit.HideHeaders
		addHeaders = hit.AddHeaders
		appendIPHeader = hit.AppendClientIPHeader
		insecureSkip = hit.InsecureSkipTLS
		useTargetHost = hit.UseTargetHost
	}

	p := r.pools[poolKey]
	backend := ""
	if p != nil {
		backend = p.pick(clientIP)
	}
	*statBackend = backend
	if backend == "" {
		// 区分"没配置后端"和"后端全忙/全挂"，给出不同状态码便于排查
		noBackend := p == nil || len(p.backends) == 0
		if noBackend {
			r.addLog(subID, fmt.Sprintf("%s [拒绝] 没有对应后端地址 %s %s %s (host=%s)", ts, clientIP, req.Method, req.URL.Path, host))
			lc.Add("Web服务", logcenter.LevelWarn, "规则[%s] 没有对应后端地址 %s (host=%s)", c.Name, req.URL.Path, host)
			*statError = true
			http.Error(w, "no backend configured", http.StatusBadGateway)
			return
		}
		r.addLog(subID, fmt.Sprintf("%s [限流] 无可用后端（全部不健康或并发已满） %s %s %s", ts, clientIP, req.Method, req.URL.Path))
		lc.Add("Web服务", logcenter.LevelWarn, "规则[%s] 无可用后端（全部不健康或并发已满）", c.Name)
		*statError = true
		w.Header().Set("Retry-After", "5")
		http.Error(w, "all backends unavailable or busy", http.StatusServiceUnavailable)
		return
	}
	target, err := parseBackendURL(backend)
	if err != nil {
		r.addLog(subID, fmt.Sprintf("%s [错误] 后端地址无效 %s: %v", ts, backend, err))
		*statError = true
		http.Error(w, "bad backend", http.StatusBadGateway)
		return
	}

	r.addLog(subID, fmt.Sprintf("%s [访问] %s %s %s -> %s", ts, clientIP, req.Method, req.URL.Path, backend))
	lc.Add("Web服务", logcenter.LevelInfo, "规则[%s] %s %s %s -> %s", c.Name, clientIP, req.Method, req.URL.Path, backend)

	// 并发计数 + 代理
	if p != nil {
		p.acquire(backend)
		defer p.release(backend)
	}
	hcMax := c.DefaultHealth.MaxFailed
	if hit != nil {
		hcMax = hit.Health.MaxFailed
	}

	// 记录原始协议，供后端判断是否由 HTTPS 进入
	scheme := "http"
	if req.TLS != nil {
		scheme = "https"
	}

	proxy := &httputil.ReverseProxy{
		// -1 表示立即刷新：SSE / 流式下载 / WebSocket 不会被整体缓冲，
		// 否则首字节会被攒到响应结束才发出，表现为"卡住不动"。
		FlushInterval: -1,
	}
	if insecureSkip {
		proxy.Transport = getInsecureRT()
	}
	proxy.Rewrite = makeRewrite(target, req, clientIP, scheme, setHeaders, appendIPHeader, useTargetHost)
	proxy.ModifyResponse = func(resp *http.Response) error {
		resp.Header.Set("X-Forwarded-By", "netkit")
		// 响应头控制：隐藏后端头 + 追加自定义头
		for _, h := range hideHeaders {
			resp.Header.Del(h)
		}
		for k, v := range addHeaders {
			resp.Header.Set(k, expandVars(v, req, clientIP))
		}
		if p != nil {
			if resp.StatusCode >= 500 {
				p.markFail(backend, hcMax, 30*time.Second)
			} else {
				p.markOK(backend)
			}
		}
		return nil
	}
	proxy.ErrorHandler = func(w http.ResponseWriter, req *http.Request, e error) {
		r.addLog(subID, fmt.Sprintf("%s [错误] 后端请求失败 %s: %v", ts, backend, e))
		lc.Add("Web服务", logcenter.LevelError, "规则[%s] 后端请求失败 %s: %v", c.Name, backend, e)
		*statError = true
		if p != nil {
			p.markFail(backend, hcMax, 30*time.Second)
		}
		http.Error(w, "backend unavailable", http.StatusBadGateway)
	}

	// 失败重试：仅对幂等方法重试，避免重复提交副作用
	retryCount := 0
	retryInterval := c.DefaultLB.RetryInterval
	if hit != nil {
		retryCount = hit.LB.RetryCount
		retryInterval = hit.LB.RetryInterval
	}
	isIdempotent := req.Method == "GET" || req.Method == "HEAD" || req.Method == "OPTIONS"

	if retryCount > 0 && isIdempotent && p != nil && len(p.backends) > 1 {
		if retryInterval <= 0 {
			retryInterval = 100
		}
		rec := &bufferedResponse{header: http.Header{}, status: 200}
		proxy.ServeHTTP(rec, req)
		attempt := 0
		for rec.status >= 500 && attempt < retryCount {
			attempt++
			time.Sleep(time.Duration(retryInterval) * time.Millisecond)
			next := p.pick(clientIP)
			if next == "" || next == backend {
				// 没有其它后端可换，停止
				alt := p.pickClientIPExcluding(clientIP, backend)
				if alt == "" {
					break
				}
				next = alt
			}
			t, err := url.Parse(next)
			if err != nil {
				break
			}
			r.addLog(subID, fmt.Sprintf("%s [重试] %s %s -> %s（第 %d 次）",
				ts, req.Method, req.URL.Path, next, attempt))
			rec2 := &bufferedResponse{header: http.Header{}, status: 200}
			p.acquire(next)
			px := *proxy
			px.Rewrite = makeRewrite(t, req, clientIP, scheme, setHeaders, appendIPHeader, useTargetHost)
			px.ServeHTTP(rec2, req)
			p.release(next)
			if rec2.status < 500 {
				rec = rec2
				backend = next
				break
			}
			rec = rec2
		}
		rec.flushTo(w)
		return
	}

	proxy.ServeHTTP(w, req)
}

// parseBackendURL 解析后端地址，兼容不带协议前缀的写法（如 127.0.0.1:8080），
// 缺省按 http:// 处理；带 https:// 的后端配合 InsecureSkipTLS 可跳过证书验证。
func parseBackendURL(backend string) (*url.URL, error) {
	b := strings.TrimSpace(backend)
	if b != "" && !strings.Contains(b, "://") {
		b = "http://" + b
	}
	return url.Parse(b)
}

// backendURLForHTTP 给健康检查用：确保后端地址带协议前缀，可直接发 HTTP 请求。
func backendURLForHTTP(backend string) string {
	b := strings.TrimSpace(backend)
	if b != "" && !strings.Contains(b, "://") {
		b = "http://" + b
	}
	return b
}

// makeRewrite 构造请求改写回调：设置目标、Host、真实 IP 透传、自定义请求头。
func makeRewrite(target *url.URL, req *http.Request, clientIP, scheme string,
	setHeaders map[string]string, appendIPHeader string, useTargetHost bool) func(*httputil.ProxyRequest) {

	return func(pr *httputil.ProxyRequest) {
		pr.SetURL(target)
		if useTargetHost {
			// 使用目标地址 Host：反代路由器管理页、部分 NAS WebDAV 的兼容开关
			pr.Out.Host = target.Host
		} else {
			pr.Out.Host = req.Host
		}
		// 透传真实客户端 IP
		prev := pr.In.Header.Get("X-Forwarded-For")
		if prev != "" {
			pr.Out.Header.Set("X-Forwarded-For", prev+", "+clientIP)
		} else {
			pr.Out.Header.Set("X-Forwarded-For", clientIP)
		}
		pr.Out.Header.Set("X-Real-IP", clientIP)
		pr.Out.Header.Set("X-Forwarded-Proto", scheme)
		// 追加客户端 IP 到指定请求头（lucky 同名功能，如追加到自定义 Header）
		if appendIPHeader != "" {
			pr.Out.Header.Add(appendIPHeader, clientIP)
		}
		// 自定义请求头（覆盖同名头，值支持变量）
		for k, v := range setHeaders {
			pr.Out.Header.Set(k, expandVars(v, req, clientIP))
		}
		// WebSocket 升级：保留原始 Upgrade/Connection 头
		if strings.EqualFold(pr.In.Header.Get("Upgrade"), "websocket") {
			pr.Out.Header.Set("Upgrade", pr.In.Header.Get("Upgrade"))
			pr.Out.Header.Set("Connection", "Upgrade")
		}
	}
}

// bufferedResponse 收集响应以便判断是否值得重试，最后一次性写回客户端。
type bufferedResponse struct {
	header      http.Header
	status      int
	body        bytes.Buffer
	wroteHeader bool
}

func (b *bufferedResponse) Header() http.Header { return b.header }
func (b *bufferedResponse) WriteHeader(code int) {
	if b.wroteHeader {
		return
	}
	b.status = code
	b.wroteHeader = true
}
func (b *bufferedResponse) Write(p []byte) (int, error) {
	if !b.wroteHeader {
		b.WriteHeader(200)
	}
	return b.body.Write(p)
}
func (b *bufferedResponse) flushTo(w http.ResponseWriter) {
	for k, vs := range b.header {
		for _, v := range vs {
			w.Header().Add(k, v)
		}
	}
	if b.status == 0 {
		b.status = 200
	}
	w.WriteHeader(b.status)
	w.Write(b.body.Bytes())
}
