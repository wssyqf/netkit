package dnsprovider

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// cfProvider Cloudflare 的 DNS-01 Provider。
type cfProvider struct {
	token     string
	client    *http.Client
	zoneCache map[string]string
}

func newCloudflare(token string) Provider {
	return &cfProvider{
		token:     token,
		client:    &http.Client{Timeout: 20 * time.Second},
		zoneCache: map[string]string{},
	}
}

func (p *cfProvider) Name() string { return "Cloudflare" }

type cfAPIResp struct {
	Success bool                       `json:"success"`
	Errors  []struct{ Message string } `json:"errors"`
	Result  json.RawMessage            `json:"result"`
}

func (p *cfProvider) apif(config any) {}

func (p *cfProvider) do(method, path string, body any) (*cfAPIResp, error) {
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, "https://api.cloudflare.com/client/v4"+path, rd)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+p.token)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := p.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	var out cfAPIResp
	if err := json.Unmarshal(data, &out); err != nil {
		return nil, fmt.Errorf("Cloudflare 响应解析失败: %w", err)
	}
	if !out.Success {
		var msgs []string
		for _, e := range out.Errors {
			msgs = append(msgs, e.Message)
		}
		return nil, fmt.Errorf("Cloudflare 错误: %s", strings.Join(msgs, "; "))
	}
	return &out, nil
}

// findZoneID 逐级向上查找域名所属 zone。
func (p *cfProvider) findZoneID(domain string) (string, error) {
	if id, ok := p.zoneCache[domain]; ok {
		return id, nil
	}
	d := domain
	for {
		resp, err := p.do(http.MethodGet, "/zones?name="+url.QueryEscape(d), nil)
		if err != nil {
			return "", err
		}
		var zones []struct {
			ID string `json:"id"`
		}
		if err := json.Unmarshal(resp.Result, &zones); err == nil && len(zones) > 0 {
			p.zoneCache[domain] = zones[0].ID
			return zones[0].ID, nil
		}
		i := strings.Index(d, ".")
		if i < 0 {
			break
		}
		d = d[i+1:]
	}
	return "", fmt.Errorf("Cloudflare 账号下找不到 %s 对应的 zone", domain)
}

// Present 创建 TXT 记录。
func (p *cfProvider) Present(fqdn, value string) (func() error, error) {
	name := strings.TrimSuffix(strings.ToLower(fqdn), ".")
	// zone 从右往左找
	zoneDomain := name
	// 去掉可能的 _acme-challenge 前缀后再查找 zone
	probe := strings.TrimPrefix(name, "_acme-challenge.")
	zoneID, err := p.findZoneID(probe)
	if err != nil {
		// 再退一步用完整名尝试
		zoneID, err = p.findZoneID(name)
		if err != nil {
			return nil, err
		}
	}
	_ = zoneDomain

	body := map[string]any{
		"type": "TXT", "name": name, "content": value, "ttl": 60,
	}
	resp, err := p.do(http.MethodPost, "/zones/"+zoneID+"/dns_records", body)
	if err != nil {
		return nil, fmt.Errorf("创建 TXT 记录失败: %w", err)
	}
	var rec struct {
		ID string `json:"id"`
	}
	json.Unmarshal(resp.Result, &rec)
	recID := rec.ID

	cleanup := func() error {
		if recID == "" {
			return nil
		}
		_, err := p.do(http.MethodDelete, "/zones/"+zoneID+"/dns_records/"+recID, nil)
		return err
	}
	return cleanup, nil
}
