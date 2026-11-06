package ddns

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"netkit/internal/config"
)

// ---- DNSHE 免费域名（https://my.dnshe.com）----
//
// 与其他服务商不同：DNSHE 管理的是"子域名"（subdomain）对象，
// 形如 myapp.example.com 中 myapp 是子域名、example.com 是根域名；
// DNS 记录挂在 subdomain_id 之下，记录名用 "@" 表示该子域名本身。
// 认证使用 X-API-Key / X-API-Secret 请求头。

const dnsheBase = "https://api005.dnshe.com/index.php?m=domain_hub"

// dnsheResp DNSHE 统一响应结构。
type dnsheResp struct {
	Success    bool   `json:"success"`
	ErrorCode  string `json:"error_code"`
	Message    string `json:"message"`
	Count      int    `json:"count"`
	Subdomains []struct {
		ID         int64  `json:"id"`
		Subdomain  string `json:"subdomain"`
		RootDomain string `json:"rootdomain"`
		FullDomain string `json:"full_domain"`
		Status     string `json:"status"`
	} `json:"subdomains"`
	// 实测返回字段为 records（文档写 dns_records），两者都兼容
	Records []struct {
		ID       int64  `json:"id"`
		RecordID string `json:"record_id"`
		Name     string `json:"name"`
		Type     string `json:"type"`
		Content  string `json:"content"`
		TTL      int    `json:"ttl"`
	} `json:"records"`
	DNSRecords []struct {
		ID       int64  `json:"id"`
		RecordID string `json:"record_id"`
		Name     string `json:"name"`
		Type     string `json:"type"`
		Content  string `json:"content"`
		TTL      int    `json:"ttl"`
	} `json:"dns_records"`
	ID int64 `json:"id"`
}

// dnsheCall 调用 DNSHE 接口。method 为 GET 或 POST，body 为 JSON 负载。
func (m *Manager) dnsheCall(method, endpoint, action string, query url.Values, body any, key, secret string) (*dnsheResp, error) {
	u := dnsheBase + "&endpoint=" + endpoint + "&action=" + action
	if len(query) > 0 {
		u += "&" + query.Encode()
	}

	var reader io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}
		reader = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, u, reader)
	if err != nil {
		return nil, err
	}
	req.Header.Set("X-API-Key", key)
	req.Header.Set("X-API-Secret", secret)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := m.client.Do(req)
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
		if msg == "" {
			msg = fmt.Sprintf("HTTP %d", resp.StatusCode)
		}
		return nil, fmt.Errorf("DNSHE %s: %s", out.ErrorCode, msg)
	}
	return &out, nil
}

// dnsheSplit 解析 DNSHE 域名，返回 (通配符记录名, 子域名全名)。
// DNSHE 的子域名对象本身不带 *，通配符体现在 DNS 记录的 name 上。
//
//	ziuzu.cc.cd     -> ("@",     "ziuzu.cc.cd")
//	*.ziuzu.cc.cd   -> ("*",     "ziuzu.cc.cd")
//	a.ziuzu.cc.cd   -> ("a",     "ziuzu.cc.cd")
func dnsheSplit(domain string) (recordName, fullSub string) {
	d := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(domain), "."))
	if strings.HasPrefix(d, "*.") {
		return "*", d[2:]
	}
	return "@", d
}

// dnshe 更新 DNSHE 子域名下的 A/AAAA 记录。
func (m *Manager) dnshe(domain, rtype, ip string, t config.DDNSTask) (string, error) {
	key, secret := t.Token, t.AccessKey
	if key == "" || secret == "" {
		return "", fmt.Errorf("DNSHE 需要配置 API Key 与 API Secret")
	}
	// TTL：DNSHE 创建/更新接口原生支持 ttl 字段（原实现固定 600）；
	// 未配置（0）时保持原行为传 600，配置了则透传，最小 600
	ttl := 600
	if v := t.TTL; v > 0 {
		if v < 600 {
			v = 600
		}
		ttl = v
	}
	recName, subDomain := dnsheSplit(domain)
	if subDomain == "" {
		return "", fmt.Errorf("域名格式无效: %s", domain)
	}

	// 1. 定位子域名对象（search 精确匹配 full_domain）
	list, err := m.dnsheCall(http.MethodGet, "subdomains", "list",
		url.Values{"search": {subDomain}, "per_page": {"200"}}, nil, key, secret)
	if err != nil {
		return "", err
	}
	var subID int64
	for _, s := range list.Subdomains {
		if strings.EqualFold(s.FullDomain, subDomain) {
			subID = s.ID
			break
		}
	}
	if subID == 0 {
		return "", fmt.Errorf("DNSHE 账号下未找到子域名 %s（当前填写 %s）。请先在 DNSHE 控制台注册该子域名；若要用通配符，请填 *.域名 或直接填子域名本身", subDomain, domain)
	}

	// 2. 查现有记录（实测字段为 records，兼容 dns_records）
	recs, err := m.dnsheCall(http.MethodGet, "dns_records", "list",
		url.Values{"subdomain_id": {fmt.Sprint(subID)}}, nil, key, secret)
	if err != nil {
		return "", err
	}
	existing := recs.Records
	if len(existing) == 0 {
		existing = recs.DNSRecords
	}

	var recID int64
	var oldIP string
	for _, r := range existing {
		if !strings.EqualFold(r.Type, rtype) {
			continue
		}
		// 记录名需与目标一致：@ 对应子域名本身，* 对应通配符
		shortName := recordNameOf(r.Name, subDomain)
		if shortName != recName {
			continue
		}
		recID = r.ID
		oldIP = r.Content
		break
	}

	// 3. 无则创建，有则按需更新
	if recID == 0 {
		_, err := m.dnsheCall(http.MethodPost, "dns_records", "create", nil, map[string]any{
			"subdomain_id": subID,
			"type":         rtype,
			"name":         recName,
			"content":      ip,
			"ttl":          ttl,
		}, key, secret)
		if err != nil {
			return "", err
		}
		return fmt.Sprintf("新增 %s 记录 %s（%s）", rtype, ip, displayName(recName, subDomain)), nil
	}
	if oldIP == ip {
		return fmt.Sprintf("无需更新 (%s)", ip), nil
	}
	_, err = m.dnsheCall(http.MethodPost, "dns_records", "update", nil, map[string]any{
		"id":      recID,
		"type":    rtype,
		"name":    recName,
		"content": ip,
		"ttl":     ttl,
	}, key, secret)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("已更新 %s -> %s（%s）", oldIP, ip, displayName(recName, subDomain)), nil
}

// recordNameOf 把 DNSHE 返回的完整记录名还原成短名：ziuzu.cc.cd -> @，*.ziuzu.cc.cd -> *
func recordNameOf(name, subDomain string) string {
	n := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(name), "."))
	sd := strings.ToLower(subDomain)
	if n == sd {
		return "@"
	}
	if n == "*."+sd {
		return "*"
	}
	if strings.HasSuffix(n, "."+sd) {
		return strings.TrimSuffix(n, "."+sd)
	}
	return n
}

func displayName(recName, subDomain string) string {
	if recName == "@" {
		return subDomain
	}
	return recName + "." + subDomain
}

// ListDNSHEDomains 列出 DNSHE 账号下的子域名（供后台校验凭据与选择域名）。
func (m *Manager) ListDNSHEDomains(key, secret string) ([]string, error) {
	if key == "" || secret == "" {
		return nil, fmt.Errorf("需要 API Key 与 API Secret")
	}
	out, err := m.dnsheCall(http.MethodGet, "subdomains", "list",
		url.Values{"per_page": {"500"}}, nil, key, secret)
	if err != nil {
		return nil, err
	}
	names := make([]string, 0, len(out.Subdomains))
	for _, s := range out.Subdomains {
		names = append(names, s.FullDomain)
	}
	return names, nil
}
