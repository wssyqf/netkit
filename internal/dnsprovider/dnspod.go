package dnsprovider

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// dnsPodProvider 腾讯云 DNSPod（dnsapi.cn 经典接口）的 DNS-01 Provider。
// 腾讯云控制台与 DNSPod 同源，凭据同为 "ID,Token" 组合。
type dnsPodProvider struct {
	token    string
	client   *http.Client
	zoneOK   map[string]bool // 已确认存在的托管域名
}

func newDNSPod(token string) Provider {
	return &dnsPodProvider{
		token:  token,
		client: &http.Client{Timeout: 20 * time.Second},
		zoneOK: map[string]bool{},
	}
}

func (p *dnsPodProvider) Name() string { return "DNSPod（腾讯云）" }

// post 表单调用 dnsapi.cn，status.code != 1 视为失败。
func (p *dnsPodProvider) post(action string, form url.Values) (map[string]any, error) {
	form.Set("login_token", p.token)
	form.Set("format", "json")
	resp, err := p.client.PostForm("https://dnsapi.cn/"+action, form)
	if err != nil {
		return nil, fmt.Errorf("DNSPod 请求失败: %w", err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	var out map[string]any
	if err := json.Unmarshal(data, &out); err != nil {
		return nil, fmt.Errorf("DNSPod 响应解析失败: %s", cutText(string(data), 200))
	}
	st, _ := out["status"].(map[string]any)
	code, _ := st["code"].(string)
	if code != "1" {
		msg, _ := st["message"].(string)
		return nil, fmt.Errorf("DNSPod 错误: %s", msg)
	}
	return out, nil
}

// findZone 从长到短逐级确认 fqdn 所属的托管域名。
func (p *dnsPodProvider) findZone(fqdn string) (string, error) {
	parts := strings.Split(fqdn, ".")
	for i := 0; i+2 <= len(parts); i++ {
		zone := strings.Join(parts[i:], ".")
		if p.zoneOK[zone] {
			return zone, nil
		}
		if _, err := p.post("Domain.Info", url.Values{"domain": {zone}}); err == nil {
			p.zoneOK[zone] = true
			return zone, nil
		}
	}
	return "", fmt.Errorf("DNSPod 账号下找不到 %s 对应的域名，请先在控制台添加", fqdn)
}

// Present 创建 _acme-challenge 的 TXT 记录，返回删除该记录的 cleanup。
func (p *dnsPodProvider) Present(fqdn, value string) (func() error, error) {
	name := strings.ToLower(strings.TrimSuffix(fqdn, "."))
	zone, err := p.findZone(name)
	if err != nil {
		return nil, err
	}
	rr := strings.TrimSuffix(name, "."+zone)
	if rr == name {
		rr = "@"
	}

	res, err := p.post("Record.Create", url.Values{
		"domain":      {zone},
		"sub_domain":  {rr},
		"record_type": {"TXT"},
		"record_line": {"默认"},
		"value":       {value},
		"ttl":         {"600"},
	})
	if err != nil {
		return nil, fmt.Errorf("创建 TXT 记录失败: %w", err)
	}
	rec, _ := res["record"].(map[string]any)
	recID := fmt.Sprint(rec["id"])
	if recID == "" || recID == "<nil>" {
		return nil, fmt.Errorf("创建 TXT 记录失败: 未返回记录 ID")
	}

	cleanup := func() error {
		// 注意：DNSPod 经典接口删除记录的动作是 Record.Remove，
		// Record.Delete 会返回 404 HTML 页面。
		if _, err := p.post("Record.Remove", url.Values{
			"domain":    {zone},
			"record_id": {recID},
		}); err != nil {
			return fmt.Errorf("删除 TXT 记录失败: %w", err)
		}
		return nil
	}
	return cleanup, nil
}
