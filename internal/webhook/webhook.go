// Package webhook 通用变更通知：支持模板变量、重试、超时、签名、事件过滤与测试。
package webhook

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"netkit/internal/config"
)

// Event 触发事件类型。
const (
	EventDDNS     = "ddns"
	EventPF       = "portforward"
	EventCert     = "cert"
	EventTest     = "test"
	EventChange   = "change" // 配置发生变更
	EventHoneypot = "honeypot"
)

// Payload 一次通知携带的上下文，用于填充模板变量。
type Payload struct {
	Event  string            // 事件类型
	Target string            // 目标（域名列表 / 规则名）
	IP     string            // 同步到的 IP
	Result string            // 结果说明
	OK     bool              // 是否成功
	Module string            // 来源模块
	Extra  map[string]string // 额外变量
}

// Result 发送结果。
type Result struct {
	OK       bool
	Status   int
	Attempts int
	Elapsed  time.Duration
	Message  string // 失败原因或成功摘要
	RespBody string // 响应体（截断）
}

// Client 负责发送 Webhook 请求。
type Client struct {
	http *http.Client
}

// NewClient 创建客户端。
func NewClient() *Client {
	return &Client{http: &http.Client{Timeout: 15 * time.Second}}
}

// buildVars 组装模板变量。
func buildVars(p Payload) map[string]string {
	vars := map[string]string{
		"#{time}":      time.Now().Format("2006-01-02 15:04:05"),
		"#{timestamp}": strconv.FormatInt(time.Now().Unix(), 10),
		"#{event}":     p.Event,
		"#{module}":    p.Module,
		"#{target}":    p.Target,
		"#{ruleName}":  p.Target,
		"#{ipAddr}":    p.IP,
		"#{ip}":        p.IP,
		"#{result}":    p.Result,
		"#{status}":    map[bool]string{true: "success", false: "failed"}[p.OK],
	}
	for k, v := range p.Extra {
		vars["#{"+k+"}"] = v
	}
	return vars
}

// render 替换模板变量。同时兼容 $变量 写法（如 $ipAddr）。
func render(tpl string, vars map[string]string) string {
	if tpl == "" {
		return ""
	}
	// 长键优先替换，避免 #{ip} 抢先匹配 #{ipAddr}
	keys := make([]string, 0, len(vars))
	for k := range vars {
		keys = append(keys, k)
	}
	for i := 0; i < len(keys); i++ {
		for j := i + 1; j < len(keys); j++ {
			if len(keys[j]) > len(keys[i]) {
				keys[i], keys[j] = keys[j], keys[i]
			}
		}
	}
	out := tpl
	for _, k := range keys {
		out = strings.ReplaceAll(out, k, vars[k])
		// 兼容 $ipAddr 形式
		out = strings.ReplaceAll(out, "$"+strings.TrimSuffix(strings.TrimPrefix(k, "#{"), "}"), vars[k])
	}
	return out
}

// shouldSend 判断当前事件是否需要发送。
func shouldSend(wh config.Webhook, ev string) bool {
	if len(wh.Events) == 0 {
		return true // 未配置则所有事件都通知
	}
	for _, e := range wh.Events {
		if strings.EqualFold(e, ev) {
			return true
		}
	}
	return false
}

// Sign HMAC-SHA256 签名，输出十六进制。签名内容 = 时间戳 + "." + body。
func sign(secret, ts, body string) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(ts))
	mac.Write([]byte("."))
	mac.Write([]byte(body))
	return hex.EncodeToString(mac.Sum(nil))
}

// Send 发送一次通知，内部按配置重试。返回最终结果。
func (c *Client) Send(wh config.Webhook, p Payload) Result {
	start := time.Now()
	res := Result{}
	if strings.TrimSpace(wh.URL) == "" {
		res.OK = true
		res.Message = "未配置 Webhook"
		return res
	}
	if !shouldSend(wh, p.Event) {
		res.OK = true
		res.Message = "当前事件未在通知范围内，已跳过"
		return res
	}

	method := strings.ToUpper(strings.TrimSpace(wh.Method))
	if method == "" {
		method = http.MethodPost
	}
	vars := buildVars(p)

	bodyTpl := wh.Body
	if bodyTpl == "" {
		bodyTpl = `{"event":"#{event}","target":"#{target}","ip":"#{ipAddr}","status":"#{status}","result":"#{result}","time":"#{time}"}`
	}
	body := render(bodyTpl, vars)
	targetURL := render(wh.URL, vars)

	// GET 时把 body 变量并入 query，避免请求体被忽略
	if method == http.MethodGet && body != "" {
		if u, err := url.Parse(targetURL); err == nil {
			q := u.Query()
			var m map[string]any
			if err := jsonUnmarshal(body, &m); err == nil {
				for k, v := range m {
					q.Set(k, fmt.Sprint(v))
				}
			} else {
				q.Set("message", body)
			}
			u.RawQuery = q.Encode()
			targetURL = u.String()
		}
	}

	retries := wh.Retry
	if retries < 1 {
		retries = 1
	}
	timeout := wh.TimeoutSec
	if timeout <= 0 {
		timeout = 15
	}
	client := c.http
	if wh.SkipTLSVerify {
		client = &http.Client{Timeout: time.Duration(timeout) * time.Second,
			Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}}
	} else {
		client = &http.Client{Timeout: time.Duration(timeout) * time.Second}
	}

	var lastErr string
	for attempt := 1; attempt <= retries; attempt++ {
		res.Attempts = attempt
		var reader io.Reader
		if method != http.MethodGet && method != http.MethodHead {
			reader = bytes.NewBufferString(body)
		}
		req, err := http.NewRequest(method, targetURL, reader)
		if err != nil {
			lastErr = "构造请求失败: " + err.Error()
			break // URL 错误重试无意义
		}
		if method != http.MethodGet && method != http.MethodHead {
			req.Header.Set("Content-Type", "application/json; charset=utf-8")
		}
		for k, v := range wh.Headers {
			req.Header.Set(k, render(v, vars))
		}
		// 签名
		if wh.Secret != "" {
			ts := strconv.FormatInt(time.Now().Unix(), 10)
			req.Header.Set("X-NetKit-Timestamp", ts)
			req.Header.Set("X-NetKit-Signature", sign(wh.Secret, ts, body))
		}
		req.Header.Set("User-Agent", "NetKit-Webhook/1.0")

		resp, err := client.Do(req)
		if err != nil {
			lastErr = "请求失败: " + err.Error()
			if attempt < retries {
				time.Sleep(backoff(attempt))
			}
			continue
		}
		respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 8192))
		resp.Body.Close()
		text := string(respBody)
		if len(text) > 500 {
			res.RespBody = text[:500] + "…"
		} else {
			res.RespBody = text
		}
		res.Status = resp.StatusCode

		// 成功判定：配置了关键字则按内容判；否则按状态码
		marks := splitMarks(wh.SuccessText)
		if len(marks) > 0 {
			for _, mk := range marks {
				if strings.Contains(text, mk) {
					res.OK = true
					res.Message = "通知成功（命中 " + mk + "）"
					res.Elapsed = time.Since(start)
					return res
				}
			}
			lastErr = fmt.Sprintf("响应未命中成功关键字（HTTP %d）", resp.StatusCode)
			if attempt < retries {
				time.Sleep(backoff(attempt))
			}
			continue
		}
		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			res.OK = true
			res.Message = fmt.Sprintf("通知成功（HTTP %d）", resp.StatusCode)
			if attempt > 1 {
				res.Message += fmt.Sprintf("，重试 %d 次后成功", attempt-1)
			}
			res.Elapsed = time.Since(start)
			return res
		}
		lastErr = fmt.Sprintf("HTTP %d", resp.StatusCode)
		if attempt < retries {
			time.Sleep(backoff(attempt))
		}
	}
	res.OK = false
	res.Message = lastErr
	res.Elapsed = time.Since(start)
	return res
}

// backoff 指数退避：1s, 2s, 4s，最多 8s。
func backoff(attempt int) time.Duration {
	d := time.Duration(1<<uint(attempt-1)) * time.Second
	if d > 8*time.Second {
		d = 8 * time.Second
	}
	return d
}

func splitMarks(s string) []string {
	fields := strings.FieldsFunc(s, func(r rune) bool {
		return r == '\n' || r == '\r'
	})
	out := make([]string, 0, len(fields))
	for _, f := range fields {
		f = strings.TrimSpace(f)
		if f != "" {
			out = append(out, f)
		}
	}
	return out
}

// jsonUnmarshal 轻量封装，避免主文件混杂 import。
func jsonUnmarshal(data string, v any) error {
	return json.Unmarshal([]byte(data), v)
}
