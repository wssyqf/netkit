package reverseproxy

import (
	"net"
	"net/http"
	"strings"
	"time"

	"netkit/internal/safe"
)

// expandVars 展开跳转目标 / 后端地址 / 自定义请求头值中的变量。
// 支持的变量（与 lucky 对齐）：
//
//	{host}        请求主机名（不含端口）
//	{port}        访问端口（Host 头带端口则取之，否则按协议取 80/443）
//	{hostAndPort} 请求 Host 头原样
//	{path}        请求路径（含前导 /）
//	{PATH}        请求路径（不含前导 /）
//	{args}        查询参数（含前导 ?，无参数为空）
//	{Args}        查询参数（不含前导 ?）
//	{ClientIP}    客户端 IP（可信代理头还原）
//	{RemoteIP}    直连对端 IP
//	{time}        当前时间，格式 2006-01-02 15:04:05
func expandVars(s string, req *http.Request, clientIP string) string {
	if s == "" || !strings.Contains(s, "{") {
		return s
	}
	host := safe.StripPort(req.Host)
	path := req.URL.Path
	rawQuery := req.URL.RawQuery

	port := ""
	if _, p, err := net.SplitHostPort(req.Host); err == nil {
		port = p
	} else if req.TLS != nil {
		port = "443"
	} else {
		port = "80"
	}

	return strings.NewReplacer(
		"{hostAndPort}", req.Host,
		"{host}", host,
		"{port}", port,
		"{path}", path,
		"{PATH}", strings.TrimPrefix(path, "/"),
		"{args}", rawQueryPrefix(rawQuery),
		"{Args}", strings.TrimPrefix(rawQuery, "?"),
		"{ClientIP}", clientIP,
		"{RemoteIP}", safe.StripPort(req.RemoteAddr),
		"{time}", time.Now().Format("2006-01-02 15:04:05"),
	).Replace(s)
}

// rawQueryPrefix 返回带前导 ? 的查询串（无参数时为空）。
func rawQueryPrefix(q string) string {
	if q == "" {
		return ""
	}
	return "?" + q
}
