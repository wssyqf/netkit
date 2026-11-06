// Package ai 提供 AI 大模型维护能力：OpenAI 兼容 /chat/completions 调用，
// 以及把 NetKit 各模块运行状态聚合成给模型阅读的系统上下文。
package ai

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"netkit/internal/config"
	"netkit/internal/ddns"
	"netkit/internal/honeypot"
	"netkit/internal/ipvisitors"
	"netkit/internal/logcenter"
	"netkit/internal/portforward"
	"netkit/internal/reverseproxy"
	"netkit/internal/waf"
)

// Msg 一条对话消息（OpenAI 兼容格式）。
type Msg struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

// 健康与元信息由 admin 注入（collectHealth 未导出，避免 import 环）。
var (
	mu        sync.Mutex
	healthFn  func() map[string]any
	metaVer   string
	metaStart time.Time
)

// SetHealth 注入健康采样函数（score/cpu/mem）。
func SetHealth(fn func() map[string]any) {
	mu.Lock()
	healthFn = fn
	mu.Unlock()
}

// SetMeta 注入版本与启动时间，供上下文展示。
func SetMeta(ver string, start time.Time) {
	mu.Lock()
	metaVer, metaStart = ver, start
	mu.Unlock()
}

// httpClient 构造带可选代理的 HTTP 客户端。
// 仅支持 http/https 代理（socks5 依赖 x/net，暂不引入）。
func httpClient(cfg config.AIConfig) (*http.Client, error) {
	tr := &http.Transport{}
	if p := strings.TrimSpace(cfg.Proxy); p != "" {
		if !strings.HasPrefix(p, "http://") && !strings.HasPrefix(p, "https://") {
			return nil, fmt.Errorf("仅支持 http/https 代理地址")
		}
		u, err := url.Parse(p)
		if err != nil {
			return nil, fmt.Errorf("代理地址无效: %v", err)
		}
		tr.Proxy = http.ProxyURL(u)
	} else {
		tr.Proxy = http.ProxyFromEnvironment
	}
	return &http.Client{Timeout: 60 * time.Second, Transport: tr}, nil
}

// Chat 调用 OpenAI 兼容接口完成一次非流式对话，返回模型文本。
// 超时由调用方 ctx 控制（客户端兜底 60s）。
func Chat(ctx context.Context, cfg config.AIConfig, msgs []Msg) (string, error) {
	base := strings.TrimSpace(cfg.BaseURL)
	if base == "" {
		return "", fmt.Errorf("未配置模型服务地址（BaseURL）")
	}
	client, err := httpClient(cfg)
	if err != nil {
		return "", err
	}
	payload := map[string]any{
		"model":    strings.TrimSpace(cfg.Model),
		"messages": msgs,
		"stream":   false,
	}
	body, _ := json.Marshal(payload)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		strings.TrimRight(base, "/")+"/chat/completions", bytes.NewReader(body))
	if err != nil {
		return "", fmt.Errorf("构造请求失败: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "NetKit-AI/1.0")
	if k := strings.TrimSpace(cfg.APIKey); k != "" {
		req.Header.Set("Authorization", "Bearer "+k)
	}

	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("请求模型服务失败: %v", err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", fmt.Errorf("模型服务返回 HTTP %d: %s", resp.StatusCode, clip(strings.TrimSpace(string(raw)), 400))
	}
	var out struct {
		Choices []struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
		} `json:"choices"`
		Error *struct {
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		return "", fmt.Errorf("模型响应解析失败: %v", err)
	}
	if out.Error != nil && out.Error.Message != "" {
		return "", fmt.Errorf("模型服务错误: %s", out.Error.Message)
	}
	if len(out.Choices) == 0 || strings.TrimSpace(out.Choices[0].Message.Content) == "" {
		return "", fmt.Errorf("模型返回空内容")
	}
	return out.Choices[0].Message.Content, nil
}

// BuildContext 把各模块运行状态聚合成给模型阅读的系统上下文（≤6KB）。
func BuildContext(cfg config.Config) string {
	var b strings.Builder
	add := func(format string, args ...any) { fmt.Fprintf(&b, format+"\n", args...) }

	now := time.Now().Format("2006-01-02 15:04:05")
	mu.Lock()
	ver, start, hf := metaVer, metaStart, healthFn
	mu.Unlock()
	if ver == "" {
		ver = "v0.3.0"
	}
	add("时间: %s", now)
	add("版本: %s", ver)
	if !start.IsZero() {
		add("运行时长: %s", time.Since(start).Round(time.Second))
	}
	if hf != nil {
		if h := hf(); h != nil {
			add("健康: 评分=%v CPU=%v%% 内存=%v%%", h["score"], h["cpu"], h["mem"])
		}
	}

	pfStatus := portforward.Default().Status()
	pfRun := 0
	for _, st := range pfStatus {
		if strings.HasPrefix(st, "运行中") {
			pfRun++
		}
	}
	webRun := len(reverseproxy.Default().Status())
	ddnsRun := len(ddns.Default().Status())

	add("端口转发: 规则 %d 条，运行中 %d", len(cfg.PortForwards), pfRun)
	add("Web 服务: 规则 %d 条，运行中 %d", len(cfg.WebRules), webRun)
	add("动态域名: 任务 %d 个，运行中 %d", len(cfg.DDNS), ddnsRun)
	add("计划任务: %d 个，SSL 证书: %d 张", len(cfg.CronTasks), len(cfg.SSLCerts))
	add("IP 地址库: %d 条，安全组: %d 个", len(cfg.IPDB), len(cfg.SecurityGroups))

	// WAF
	wc := waf.Default().Config()
	add("WAF: 总开关=%v 模式=%s 规则命中(内存)=%d", waf.Default().Enabled(), wc.Mode, len(waf.Default().Hits(1000)))
	for i, h := range waf.Default().Hits(5) {
		add("  最近命中%d: %s %s %s rule#%d action=%s geo=%s", i+1, h.Time, h.Method, h.URI, h.RuleID, h.Action, h.Geo)
	}

	// 蜜罐
	add("蜜罐诱捕: 开启=%v 诱饵端口=%d 捕获记录=%d",
		cfg.Honeypot.Enabled, len(honeypot.Default().Status()), len(honeypot.Default().Records(2000)))
	for i, rec := range honeypot.Default().Records(3) {
		add("  最近捕获%d: %s -> :%d geo=%s", i+1, rec.Time, rec.Port, rec.Geo)
	}

	// 访客与过滤
	add("IP 访客: %d 个来源 IP", ipvisitors.Default().Count())
	af := cfg.IPFilter
	add("IP 过滤: 模式=%s 地区模式=%s 国家数=%d", orNone(af.Mode), orNone(af.GeoMode), len(af.GeoCountries))

	// 最近告警日志
	logs := logcenter.Default().Query("", "error", "", 10)
	warns := logcenter.Default().Query("", "warn", "", 10)
	if len(logs)+len(warns) == 0 {
		add("最近告警: 无 error/warn 日志")
	}
	for _, e := range logs {
		add("  [ERROR] %s %s: %s", e.Time, e.Module, clip(e.Msg, 160))
	}
	for _, e := range warns {
		add("  [WARN] %s %s: %s", e.Time, e.Module, clip(e.Msg, 160))
	}

	return clip(b.String(), 6*1024)
}

func orNone(s string) string {
	if strings.TrimSpace(s) == "" {
		return "未设置"
	}
	return s
}

func clip(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
