package ddns

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"netkit/internal/config"
)

// ---- DNSPod（腾讯云 dnspod.cn 经典接口） ----

type dpResp struct {
	Code int    `json:"code"`
	Info string `json:"info"`
}

func (m *Manager) dnspodPost(token string, form url.Values) (map[string]any, error) {
	form.Set("login_token", token)
	form.Set("format", "json")
	resp, err := m.client.PostForm("https://dnsapi.cn/"+strings.TrimPrefix(form.Get("__action"), ""), form)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	var out map[string]any
	if err := json.Unmarshal(b, &out); err != nil {
		return nil, err
	}
	if code, _ := out["status"].(map[string]any)["code"].(float64); code != 1 {
		msg, _ := out["status"].(map[string]any)["message"].(string)
		return nil, fmt.Errorf("dnspod 错误: %s", msg)
	}
	return out, nil
}

func (m *Manager) dnspod(domain, rtype, ip string, t config.DDNSTask) (string, error) {
	token := t.Token
	if token == "" {
		return "", fmt.Errorf("dnspod 需要配置 Token（login_token）")
	}
	// TTL：0 = 不传用服务商默认；dnspod 最小 600，低于 600 按 600 传
	ttl := ""
	if v := t.TTL; v > 0 {
		if v < 600 {
			v = 600
		}
		ttl = strconv.Itoa(v)
	}
	sub, base := splitDomain(domain)
	// 域名未添加过时直接报错，由用户先在服务商控制台添加域名
	listForm := url.Values{
		"__action":    {"Record.List"},
		"domain":      {base},
		"sub_domain":  {sub},
		"record_type": {rtype},
	}
	if ttl != "" {
		listForm.Set("ttl", ttl)
	}
	list, err := m.dnspodPost(token, listForm)
	if err != nil {
		return "", err
	}
	recs, _ := list["records"].([]any)
	if len(recs) == 0 {
		createForm := url.Values{
			"__action":    {"Record.Create"},
			"domain":      {base},
			"sub_domain":  {sub},
			"record_type": {rtype},
			"record_line": {"默认"},
			"value":       {ip},
		}
		if ttl != "" {
			createForm.Set("ttl", ttl)
		}
		_, err := m.dnspodPost(token, createForm)
		return fmt.Sprintf("新增记录 %s", ip), err
	}
	rec, _ := recs[0].(map[string]any)
	recID := fmt.Sprint(rec["id"])
	if fmt.Sprint(rec["value"]) == ip {
		return fmt.Sprintf("无需更新 (%s)", ip), nil
	}
	modifyForm := url.Values{
		"__action":    {"Record.Modify"},
		"domain":      {base},
		"record_id":   {recID},
		"sub_domain":  {sub},
		"record_type": {rtype},
		"record_line": {"默认"},
		"value":       {ip},
	}
	if ttl != "" {
		modifyForm.Set("ttl", ttl)
	}
	_, err = m.dnspodPost(token, modifyForm)
	return fmt.Sprintf("已更新 -> %s", ip), err
}

// ---- 阿里云 DNS（RPC 签名 V1） ----

const aliyunEndpoint = "https://alidns.aliyuncs.com/"

func percentEncode(s string) string {
	u := url.QueryEscape(s)
	u = strings.ReplaceAll(u, "+", "%20")
	u = strings.ReplaceAll(u, "*", "%2A")
	u = strings.ReplaceAll(u, "%7E", "~")
	return u
}

func aliyunSign(params url.Values, secret string) string {
	keys := make([]string, 0, len(params))
	for k := range params {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var sb strings.Builder
	for i, k := range keys {
		if i > 0 {
			sb.WriteString("&")
		}
		sb.WriteString(percentEncode(k))
		sb.WriteString("=")
		sb.WriteString(percentEncode(params.Get(k)))
	}
	stringToSign := "GET&%2F&" + percentEncode(sb.String())
	mac := hmac.New(sha1.New, []byte(secret+"&"))
	mac.Write([]byte(stringToSign))
	return base64.StdEncoding.EncodeToString(mac.Sum(nil))
}

func (m *Manager) aliyunRPC(params url.Values, id, secret string) (map[string]any, error) {
	nonce := make([]byte, 8)
	rand.Read(nonce)
	common := url.Values{
		"Format":           {"JSON"},
		"Version":          {"2015-01-09"},
		"AccessKeyId":      {id},
		"SignatureMethod":  {"HMAC-SHA1"},
		"SignatureVersion": {"1.0"},
		"SignatureNonce":   {hex.EncodeToString(nonce)},
		"Timestamp":        {time.Now().UTC().Format("2006-01-02T15:04:05Z")},
	}
	for k, v := range params {
		common[k] = v
	}
	sig := aliyunSign(common, secret)
	common.Set("Signature", sig)
	resp, err := m.client.Get(aliyunEndpoint + "?" + common.Encode())
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	var out map[string]any
	json.Unmarshal(b, &out)
	if _, bad := out["Code"]; bad {
		msg, _ := out["Message"].(string)
		return nil, fmt.Errorf("aliyun 错误: %s", msg)
	}
	return out, nil
}

func (m *Manager) aliyun(domain, rtype, ip string, t config.DDNSTask) (string, error) {
	id, secret := t.AccessKeyID, t.AccessKey
	if id == "" || secret == "" {
		return "", fmt.Errorf("aliyun 需要配置 AccessKeyID / AccessKey")
	}
	// TTL：0 = 不传用服务商默认；阿里云最小 600，低于 600 按 600 传
	ttl := ""
	if v := t.TTL; v > 0 {
		if v < 600 {
			v = 600
		}
		ttl = strconv.Itoa(v)
	}
	sub, base := splitDomain(domain)
	list, err := m.aliyunRPC(url.Values{
		"Action":     {"DescribeDomainRecords"},
		"DomainName": {base},
		"Type":       {rtype},
	}, id, secret)
	if err != nil {
		return "", err
	}
	recID := ""
	oldValue := ""
	if data, ok := list["DomainRecords"].(map[string]any); ok {
		if arr, ok := data["Record"].([]any); ok {
			for _, item := range arr {
				rec, _ := item.(map[string]any)
				if fmt.Sprint(rec["RR"]) == sub {
					recID = fmt.Sprint(rec["RecordId"])
					oldValue = fmt.Sprint(rec["Value"])
					break
				}
			}
		}
	}
	if recID == "" {
		addForm := url.Values{
			"Action":     {"AddDomainRecord"},
			"DomainName": {base},
			"RR":         {sub},
			"Type":       {rtype},
			"Value":      {ip},
		}
		if ttl != "" {
			addForm.Set("TTL", ttl)
		}
		_, err := m.aliyunRPC(addForm, id, secret)
		return fmt.Sprintf("新增记录 %s", ip), err
	}
	if oldValue == ip {
		return fmt.Sprintf("无需更新 (%s)", ip), nil
	}
	updateForm := url.Values{
		"Action":   {"UpdateDomainRecord"},
		"RecordId": {recID},
		"RR":       {sub},
		"Type":     {rtype},
		"Value":    {ip},
	}
	if ttl != "" {
		updateForm.Set("TTL", ttl)
	}
	_, err = m.aliyunRPC(updateForm, id, secret)
	return fmt.Sprintf("已更新 %s -> %s", oldValue, ip), err
}

// ---- Cloudflare ----

// cfReply Cloudflare 统一响应结构。
type cfReply struct {
	Success bool                       `json:"success"`
	Errors  []struct{ Message string } `json:"errors"`
	Result  json.RawMessage            `json:"result"`
}

// cfCall 调用 Cloudflare API（Bearer Token 鉴权），返回 result 字段。
// 该实现自包含，便于与 ddns.go 中的历史实现各自演进。
func (m *Manager) cfCall(method, path, token string, body any) (json.RawMessage, error) {
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}
		rd = strings.NewReader(string(b))
	}
	req, err := http.NewRequest(method, "https://api.cloudflare.com/client/v4"+path, rd)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := m.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var out cfReply
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, err
	}
	if !out.Success {
		msgs := make([]string, 0, len(out.Errors))
		for _, e := range out.Errors {
			msgs = append(msgs, e.Message)
		}
		return nil, fmt.Errorf("cloudflare 接口错误: %s", strings.Join(msgs, "; "))
	}
	return out.Result, nil
}

// cloudflare 更新 Cloudflare DNS 记录。
func (m *Manager) cloudflare(domain, rtype, ip string, t config.DDNSTask) (string, error) {
	token := t.Token
	if token == "" {
		return "", fmt.Errorf("cloudflare 需要配置 API Token")
	}
	// TTL：0 = 不传用服务商默认（自动）；cloudflare 最小 60，1 表示「自动」原样透传
	var ttlVal any
	if v := t.TTL; v > 0 {
		switch {
		case v == 1:
			ttlVal = 1
		case v < 60:
			ttlVal = 60
		default:
			ttlVal = v
		}
	}
	// 逐级尝试找到所在 zone
	zoneID := ""
	zone := domain
	for z := zone; z != ""; {
		result, err := m.cfCall(http.MethodGet, "/zones?name="+url.QueryEscape(z), token, nil)
		if err != nil {
			return "", fmt.Errorf("cloudflare 查询 zone 失败: %v", err)
		}
		var zones []struct{ ID string }
		if err := json.Unmarshal(result, &zones); err == nil && len(zones) > 0 {
			zoneID = zones[0].ID
			break
		}
		// 去掉最左边一段再试
		i := strings.Index(z, ".")
		if i < 0 {
			break
		}
		z = z[i+1:]
	}
	if zoneID == "" {
		return "", fmt.Errorf("cloudflare 未找到 %s 对应的 zone", domain)
	}

	listPath := fmt.Sprintf("/zones/%s/dns_records?type=%s&name=%s", zoneID, rtype, url.QueryEscape(domain))
	result, err := m.cfCall(http.MethodGet, listPath, token, nil)
	if err != nil {
		return "", fmt.Errorf("cloudflare 查询记录失败: %v", err)
	}
	var records []struct {
		ID      string `json:"id"`
		Content string `json:"content"`
	}
	if err := json.Unmarshal(result, &records); err != nil {
		return "", fmt.Errorf("cloudflare 解析记录失败: %v", err)
	}

	buildBody := func() map[string]any {
		body := map[string]any{"type": rtype, "name": domain, "content": ip}
		if ttlVal != nil {
			body["ttl"] = ttlVal
		}
		return body
	}
	if len(records) == 0 {
		_, err := m.cfCall(http.MethodPost, "/zones/"+zoneID+"/dns_records", token, buildBody())
		if err != nil {
			return "", fmt.Errorf("cloudflare 新增记录失败: %v", err)
		}
		return fmt.Sprintf("新增记录 %s", ip), nil
	}
	if records[0].Content == ip {
		return fmt.Sprintf("无需更新 (%s)", ip), nil
	}
	// PATCH 只更新指定字段，未配置 TTL 时保持原值
	_, err = m.cfCall(http.MethodPatch, "/zones/"+zoneID+"/dns_records/"+records[0].ID, token, buildBody())
	if err != nil {
		return "", fmt.Errorf("cloudflare 修改记录失败: %v", err)
	}
	return fmt.Sprintf("已更新 %s -> %s", records[0].Content, ip), nil
}
