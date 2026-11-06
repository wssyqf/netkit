package reverseproxy

import (
	"fmt"
	"html"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"netkit/internal/config"
)

// serveFile 子规则服务类型 file：把请求映射到本地静态目录（内置 index.html 支持）。
func serveFile(r *runningRule, hit *config.WebSubRule,
	w http.ResponseWriter, req *http.Request, clientIP, ts string) {

	root := strings.TrimSpace(hit.DocRoot)
	if root == "" {
		r.addLog(hit.ID, fmt.Sprintf("%s [拒绝] 静态文件子规则 %s 未配置目录 %s %s",
			ts, hit.Name, clientIP, req.URL.Path))
		http.Error(w, "docRoot not configured", http.StatusInternalServerError)
		return
	}
	abs, err := filepath.Abs(root)
	if err != nil {
		http.Error(w, "bad docRoot", http.StatusInternalServerError)
		return
	}
	if fi, err := os.Stat(abs); err != nil || !fi.IsDir() {
		r.addLog(hit.ID, fmt.Sprintf("%s [错误] 静态目录不存在 %s (%s)", ts, abs, hit.Name))
		http.Error(w, "docRoot not found", http.StatusNotFound)
		return
	}
	r.addLog(hit.ID, fmt.Sprintf("%s [文件] %s %s GET %s", ts, clientIP, req.URL.Path, abs))
	// 剥离子规则的 URL 路由前缀（如 /static/index.html -> /index.html），
	// 否则 FileServer 会在 docRoot 下再找一层 static/ 目录导致 404。
	rel := req.URL.Path
	for _, loc := range hit.Locations {
		loc = strings.TrimSuffix(strings.TrimSpace(loc), "/")
		if loc != "" && strings.HasPrefix(req.URL.Path, loc) {
			rel = strings.TrimPrefix(req.URL.Path, loc)
			break
		}
	}
	if rel == "" || !strings.HasPrefix(rel, "/") {
		rel = "/" + strings.TrimPrefix(rel, "/")
	}
	r2 := req.Clone(req.Context())
	r2.URL.Path = rel
	r2.URL.RawPath = ""
	// http.Dir 自带路径穿越防护（清理路径并拒绝越出根目录）。
	http.FileServer(http.Dir(abs)).ServeHTTP(w, r2)
}

// serveJump 子规则服务类型 redirect / urljump：把请求跳转到目标地址（支持变量）。
//
//	redirect —— 返回 HTTP 3xx（状态码可配 301/302/307/308），浏览器直接跳转；
//	urljump  —— 返回 200 + HTML 自动跳转页（meta refresh + JS），用于不便使用
//	            3xx 状态码、或需要在跳转前展示提示的场景。
func serveJump(r *runningRule, hit *config.WebSubRule,
	w http.ResponseWriter, req *http.Request, clientIP, ts string) {

	target := expandVars(strings.TrimSpace(hit.Target), req, clientIP)
	if target == "" {
		r.addLog(hit.ID, fmt.Sprintf("%s [拒绝] 跳转子规则 %s 未配置目标地址 %s %s",
			ts, hit.Name, clientIP, req.URL.Path))
		http.Error(w, "jump target not configured", http.StatusInternalServerError)
		return
	}

	if hit.Type == "urljump" {
		r.addLog(hit.ID, fmt.Sprintf("%s [跳转页] %s %s -> %s", ts, clientIP, req.URL.Path, target))
		esc := html.EscapeString(target)
		// JS 字符串字面量：先按 Go 引号规则转义，再把 </ 转成 <\/ 防止提前闭合 script 标签。
		js := strings.ReplaceAll(strconv.Quote(target), "</", `<\/`)
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, jumpPageHTML, esc, esc, esc, js)
		return
	}

	code := hit.StatusCode
	if code != 301 && code != 302 && code != 307 && code != 308 {
		code = 302
	}
	r.addLog(hit.ID, fmt.Sprintf("%s [重定向] %s %s -> %s (%d)",
		ts, clientIP, req.URL.Path, target, code))
	// Location 允许绝对地址与相对路径，交给 http.Redirect 规范化。
	http.Redirect(w, req, target, code)
}

// jumpPageHTML URL 跳转页：优先 JS 立即跳转，meta refresh 兜底。
const jumpPageHTML = `<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta http-equiv="refresh" content="0;url=%s">
<title>正在跳转...</title>
</head>
<body style="font-family:system-ui,-apple-system,sans-serif;display:flex;align-items:center;justify-content:center;height:95vh;margin:0;background:#0f172a;color:#e2e8f0">
<div style="text-align:center">
<p style="font-size:14px;opacity:.7">页面正在跳转，若未自动跳转请点击下方链接</p>
<a href="%s" style="color:#38bdf8;word-break:break-all">%s</a>
</div>
<script>location.replace(%s)</script>
</body>
</html>
`
