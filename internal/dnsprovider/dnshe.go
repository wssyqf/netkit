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

const dnsheBase = "https://api005.dnshe.com/index.php?m=domain_hub"

// dnsheProvider 基于 DNSHE 免费域名的 DNS-01 Provider。
type dnsheProvider struct {
	key    string
	secret string
	client *http.Client
	// 缓存 子域名全名 -> subdomain_id，避免重复查询
	zoneCache map[string]int64
}

func newDNSHE(key, secret string) Provider {
	return &dnsheProvider{
		key:       key,
		secret:    secret,
		client:    &http.Client{Timeout: 20 * time.Second},
		zoneCache: map[string]int64{},
	}
}

func (p *dnsheProvider) Name() string { return "DNSHE" }

type dnsheResp struct {
	Success    bool   `json:"success"`
	ErrorCode  string `json:"error_code"`
	Message    string `json:"message"`
	ID         int64  `json:"id"`
	Count      int    `json:"count"`
	Subdomains []struct {
		ID         int64  `json:"id"`
		FullDomain string `json:"full_domain"`
	} `json:"subdomains"`
	Records []struct {
		ID      int64  `json:"id"`
		Name    string `json:"name"`
		Type    string `json:"type"`
		Content string `json:"content"`
	} `json:"records"`
	DNSRecords []struct {
		ID      int64  `json:"id"`
		Name    string `json:"name"`
		Type    string `json:"type"`
		Content string `json:"content"`
	} `json:"dns_records"`
}

func (p *dnsheProvider) call(method, endpoint, action string, query url.Values, body any) (*dnsheResp, error) {
	u := dnsheBase + "&endpoint=" + endpoint + "&action=" + action
	if len(query) > 0 {
		u += "&" + query.Encode()
	}
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, u, rd)
	if err != nil {
		return nil, err
	}
	req.Header.Set("X-API-Key", p.key)
	req.Header.Set("X-API-Secret", p.secret)
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
	var out dnsheResp
	if err := json.Unmarshal(data, &out); err != nil {
		return nil, fmt.Errorf("DNSHE 响应解析失败: %w", err)
	}
	if !out.Success {
		msg := out.Message
		if msg == "" {
			msg = out.ErrorCode
		}
		return nil, fmt.Errorf("DNSHE %s: %s", out.ErrorCode, msg)
	}
	return &out, nil
}

// findZone 根据完整域名定位 DNSHE 子域名对象。
// DNSHE 的子域名可以是多级（如 a.b.cc.cd），所以从长到短逐级尝试。
func (p *dnsheProvider) findZone(full string) (int64, error) {
	if id, ok := p.zoneCache[full]; ok {
		return id, nil
	}
	list, err := p.call(http.MethodGet, "subdomains", "list",
		url.Values{"search": {full}, "per_page": {"200"}}, nil)
	if err != nil {
		return 0, err
	}
	for _, s := range list.Subdomains {
		if strings.EqualFold(s.FullDomain, full) {
			p.zoneCache[full] = s.ID
			return s.ID, nil
		}
	}
	// 退一步：去掉最左边一段继续找（应对 _acme-challenge.a.b 这类更深的名字）
	parts := strings.Split(full, ".")
	for i := 1; i < len(parts)-1; i++ {
		try := strings.Join(parts[i:], ".")
		l2, err := p.call(http.MethodGet, "subdomains", "list",
			url.Values{"search": {try}, "per_page": {"200"}}, nil)
		if err != nil {
			continue
		}
		for _, s := range l2.Subdomains {
			if strings.EqualFold(s.FullDomain, try) {
				p.zoneCache[full] = s.ID
				return s.ID, nil
			}
		}
	}
	return 0, fmt.Errorf("DNSHE 账号下找不到可管理 %s 的子域名，请确认该域名已在 DNSHE 注册", full)
}

// Present 创建 _acme-challenge TXT 记录。
func (p *dnsheProvider) Present(fqdn, value string) (func() error, error) {
	// fqdn 形如 _acme-challenge.ziuzu.cc.cd
	zonePart := strings.TrimPrefix(strings.ToLower(fqdn), "_acme-challenge.")
	zonePart = strings.TrimSuffix(zonePart, ".")

	// 记录名：_acme-challenge 或 _acme-challenge.<多级前缀>
	namePart := strings.TrimSuffix(strings.ToLower(fqdn), "."+zonePart)
	if namePart == "" || namePart == strings.ToLower(fqdn) {
		namePart = "_acme-challenge"
	}

	zoneID, err := p.findZone(zonePart)
	if err != nil {
		return nil, err
	}

	// 先清理同名同值的旧记录，避免重复
	p.deleteExisting(zoneID, namePart, value)

	res, err := p.call(http.MethodPost, "dns_records", "create", nil, map[string]any{
		"subdomain_id": zoneID,
		"type":         "TXT",
		"name":         namePart,
		"content":      value,
		"ttl":          60,
	})
	if err != nil {
		return nil, fmt.Errorf("创建 TXT 记录失败: %w", err)
	}
	recID := res.ID

	cleanup := func() error {
		if recID == 0 {
			return nil
		}
		_, err := p.call(http.MethodPost, "dns_records", "delete", nil, map[string]any{
			"id": recID,
		})
		if err != nil {
			return fmt.Errorf("删除 TXT 记录失败: %w", err)
		}
		return nil
	}
	return cleanup, nil
}

// deleteExisting 删除同名同值的残留记录（上次异常退出可能留下）。
func (p *dnsheProvider) deleteExisting(zoneID int64, name, value string) {
	list, err := p.call(http.MethodGet, "dns_records", "list",
		url.Values{"subdomain_id": {fmt.Sprint(zoneID)}}, nil)
	if err != nil {
		return
	}
	recs := list.Records
	if len(recs) == 0 {
		recs = list.DNSRecords
	}
	for _, r := range recs {
		if !strings.EqualFold(r.Type, "TXT") {
			continue
		}
		if strings.EqualFold(r.Content, value) {
			p.call(http.MethodPost, "dns_records", "delete", nil, map[string]any{"id": r.ID})
		}
	}
}
