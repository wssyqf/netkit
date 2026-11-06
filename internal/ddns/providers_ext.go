package ddns

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"netkit/internal/config"
)

// cutText 截取字符串前 n 个字符（按 rune），超出部分以省略号代替。
func cutText(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n]) + "…"
}

// keyPair 解析双段凭据：优先 Token 的 "key,secret" 形式（兼容 "key:secret"），
// 否则用 AccessKeyID + AccessKey 组合，都不可用时返回中文错误。
func keyPair(token, id, secret, provider string) (string, string, error) {
	if token != "" {
		sep := strings.Index(token, ",")
		if sep < 0 {
			sep = strings.Index(token, ":")
		}
		if sep > 0 && sep < len(token)-1 {
			return strings.TrimSpace(token[:sep]), strings.TrimSpace(token[sep+1:]), nil
		}
	}
	if id != "" && secret != "" {
		return id, secret, nil
	}
	return "", "", fmt.Errorf("%s 需要填 API Key,Secret（key,secret 格式）", provider)
}

// ---- 自定义回调（callback） ----
//
// 对齐 ddns-go 的 Callback：把变量渲染进 URL / 请求体模板后发起 HTTP 请求，
// 从而接入任意 DNS 服务商。模板变量：#{ip} #{domain} #{recordType} #{ttl}。
func (m *Manager) callback(domain, rtype, ip string, t config.DDNSTask) (string, error) {
	if t.CallbackURL == "" {
		return "", fmt.Errorf("callback 未配置回调地址")
	}
	// 渲染模板：未配置 TTL 时 #{ttl} 填「默认」；URL 与 Body 都替换
	ttlText := "默认"
	if t.TTL > 0 {
		ttlText = strconv.Itoa(t.TTL)
	}
	repl := strings.NewReplacer(
		"#{ip}", ip,
		"#{domain}", domain,
		"#{recordType}", rtype,
		"#{ttl}", ttlText,
	)
	reqURL := repl.Replace(t.CallbackURL)
	body := repl.Replace(t.CallbackBody)

	// 请求前校验 URL 合法性（中文错误提示）
	u, err := url.Parse(reqURL)
	if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") {
		return "", fmt.Errorf("callback 回调地址无效（需 http/https 完整地址）: %s", reqURL)
	}

	// 方法：显式配置优先；为空时按 Body 推断（空 = GET，非空 = POST）
	method := strings.ToUpper(strings.TrimSpace(t.CallbackMethod))
	if method == "" {
		method = http.MethodGet
		if body != "" {
			method = http.MethodPost
		}
	}
	var rd io.Reader
	if body != "" {
		rd = strings.NewReader(body)
	}
	req, err := http.NewRequest(method, u.String(), rd)
	if err != nil {
		return "", fmt.Errorf("callback 构造请求失败: %v", err)
	}
	if body != "" {
		// JSON 负载用 application/json，其余按纯文本发送
		if json.Valid([]byte(body)) {
			req.Header.Set("Content-Type", "application/json; charset=utf-8")
		} else {
			req.Header.Set("Content-Type", "text/plain; charset=utf-8")
		}
	}
	resp, err := m.client.Do(req)
	if err != nil {
		return "", fmt.Errorf("callback 调用 %s 失败: %v", reqURL, err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	snippet := cutText(strings.TrimSpace(string(b)), 200)
	// HTTP 2xx 即成功
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", fmt.Errorf("callback 调用 %s 返回 HTTP %d: %s", reqURL, resp.StatusCode, snippet)
	}
	return fmt.Sprintf("回调成功 %s (HTTP %d): %s", ip, resp.StatusCode, snippet), nil
}

// ---- 华为云 DNS ----
//
// 鉴权选型：采用华为云公开的 AK/SK 签名算法 SDK-HMAC-SHA256 手写实现。
// 任务凭据形态为 AK/SK，而备选的 IAM Bearer Token 方案需要 IAM 用户名/密码才能换取
// token，与凭据形态不符，故不采用。签名严格按官方《API签名认证机制》四步构造
// （规范请求 -> 待签字符串 -> HMAC-SHA256(SK, ...) -> Authorization 头）。
const huaweiDNSEndpoint = "https://dns.myhuaweicloud.com"

// huaweiCanonicalQuery 构造规范查询串：按参数名升序、逐项 percent 编码。
func huaweiCanonicalQuery(u *url.URL) string {
	q := u.Query()
	keys := make([]string, 0, len(q))
	for k := range q {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		for _, v := range q[k] {
			parts = append(parts, percentEncode(k)+"="+percentEncode(v))
		}
	}
	return strings.Join(parts, "&")
}

// huaweiSign 按 SDK-HMAC-SHA256 算法为请求添加 X-Sdk-Date 与 Authorization 头。
// body 必须与实际发送的请求体字节一致。
func huaweiSign(req *http.Request, ak, sk string, body []byte) {
	date := time.Now().UTC().Format("20060102T150405Z")
	req.Header.Set("X-Sdk-Date", date)

	// 参与签名的请求头：host、x-sdk-date，带请求体时再加上 content-type
	signed := []string{"host", "x-sdk-date"}
	vals := map[string]string{
		"host":       req.URL.Host,
		"x-sdk-date": date,
	}
	if ct := req.Header.Get("Content-Type"); ct != "" {
		signed = append(signed, "content-type")
		vals["content-type"] = ct
	}
	sort.Strings(signed)
	var canonicalHeaders strings.Builder
	for _, k := range signed {
		canonicalHeaders.WriteString(k)
		canonicalHeaders.WriteString(":")
		canonicalHeaders.WriteString(strings.TrimSpace(vals[k]))
		canonicalHeaders.WriteString("\n")
	}

	// 规范 URI：签名时统一补尾部 "/"（官方要求，发送时可不带）
	canonicalURI := req.URL.EscapedPath()
	if canonicalURI == "" {
		canonicalURI = "/"
	}
	if !strings.HasSuffix(canonicalURI, "/") {
		canonicalURI += "/"
	}

	// 请求体哈希：无体按空串计算
	bodyHash := sha256.Sum256(body)
	canonical := strings.Join([]string{
		req.Method,
		canonicalURI,
		huaweiCanonicalQuery(req.URL),
		canonicalHeaders.String(),
		strings.Join(signed, ";"),
		hex.EncodeToString(bodyHash[:]),
	}, "\n")
	canonicalHash := sha256.Sum256([]byte(canonical))
	stringToSign := strings.Join([]string{
		"SDK-HMAC-SHA256",
		date,
		hex.EncodeToString(canonicalHash[:]),
	}, "\n")
	mac := hmac.New(sha256.New, []byte(sk))
	mac.Write([]byte(stringToSign))
	signature := hex.EncodeToString(mac.Sum(nil))
	req.Header.Set("Authorization", fmt.Sprintf("SDK-HMAC-SHA256 Access=%s, SignedHeaders=%s, Signature=%s",
		ak, strings.Join(signed, ";"), signature))
}

// huaweiErrMsg 提取华为云错误响应中的可读信息。
func huaweiErrMsg(b []byte) string {
	var m map[string]any
	if json.Unmarshal(b, &m) == nil {
		if s, ok := m["error_msg"].(string); ok && s != "" {
			return s
		}
		if e, ok := m["error"].(map[string]any); ok {
			if s, ok := e["message"].(string); ok && s != "" {
				return s
			}
		}
	}
	return string(b)
}

// huaweiDNSCall 调用华为云 DNS 公开 API（AK/SK 签名）。path 形如 /v2/zones，
// query 为查询参数，body 非 nil 时以 JSON 提交，返回成功响应体。
func (m *Manager) huaweiDNSCall(ak, sk, method, path string, query url.Values, body any) ([]byte, error) {
	var payload []byte
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}
		payload = b
	}
	target := huaweiDNSEndpoint + path
	if len(query) > 0 {
		target += "?" + query.Encode()
	}
	var rd io.Reader
	if payload != nil {
		rd = strings.NewReader(string(payload))
	}
	req, err := http.NewRequest(method, target, rd)
	if err != nil {
		return nil, err
	}
	if payload != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	huaweiSign(req, ak, sk, payload)
	resp, err := m.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, cutText(huaweiErrMsg(data), 200))
	}
	return data, nil
}

// huaweicloud 更新华为云 DNS 记录（记录集语义：同一 name+type 唯一）。
func (m *Manager) huaweicloud(domain, rtype, ip string, t config.DDNSTask) (string, error) {
	ak, sk := t.AccessKeyID, t.AccessKey
	if ak == "" || sk == "" {
		return "", fmt.Errorf("huaweicloud 需要配置 AccessKeyId / SecretAccessKey（AK/SK）")
	}
	_, base := splitDomain(domain)

	// 1. 域名名 -> zone ID（接口要求 zone_id 为 UUID，先按 name 精确查询）
	data, err := m.huaweiDNSCall(ak, sk, http.MethodGet, "/v2/zones",
		url.Values{"name": {base}, "limit": {"500"}}, nil)
	if err != nil {
		return "", fmt.Errorf("huaweicloud 查询域名 %s 失败: %v", base, err)
	}
	var zoneOut struct {
		Zones []struct {
			ID   string `json:"id"`
			Name string `json:"name"`
		} `json:"zones"`
	}
	if err := json.Unmarshal(data, &zoneOut); err != nil {
		return "", fmt.Errorf("huaweicloud 解析域名列表失败: %v", err)
	}
	zoneID := ""
	for _, z := range zoneOut.Zones {
		if strings.EqualFold(strings.TrimSuffix(z.Name, "."), base) {
			zoneID = z.ID
			break
		}
	}
	if zoneID == "" {
		return "", fmt.Errorf("huaweicloud 账号下未找到域名 %s，请先在华为云控制台添加", base)
	}

	// 2. 查现有记录集（记录名要求是以 . 结尾的 FQDN）
	recordName := strings.TrimSuffix(domain, ".") + "."
	data, err = m.huaweiDNSCall(ak, sk, http.MethodGet, "/v2/zones/"+zoneID+"/recordsets",
		url.Values{"type": {rtype}, "name": {recordName}, "limit": {"500"}}, nil)
	if err != nil {
		return "", fmt.Errorf("huaweicloud 查询记录集失败: %v", err)
	}
	var recOut struct {
		Recordsets []struct {
			ID      string   `json:"id"`
			Name    string   `json:"name"`
			Type    string   `json:"type"`
			Records []string `json:"records"`
		} `json:"recordsets"`
	}
	if err := json.Unmarshal(data, &recOut); err != nil {
		return "", fmt.Errorf("huaweicloud 解析记录集失败: %v", err)
	}
	recID := ""
	var oldVals []string
	for _, r := range recOut.Recordsets {
		if strings.EqualFold(strings.TrimSuffix(r.Name, "."), strings.TrimSuffix(recordName, ".")) &&
			strings.EqualFold(r.Type, rtype) {
			recID = r.ID
			oldVals = r.Records
			break
		}
	}

	// TTL：0 = 不传用服务商默认
	buildBody := func() map[string]any {
		body := map[string]any{"name": recordName, "type": rtype, "records": []string{ip}}
		if t.TTL > 0 {
			body["ttl"] = t.TTL
		}
		return body
	}
	if recID == "" {
		if _, err := m.huaweiDNSCall(ak, sk, http.MethodPost,
			"/v2/zones/"+zoneID+"/recordsets", nil, buildBody()); err != nil {
			return "", fmt.Errorf("huaweicloud 新增记录集失败: %v", err)
		}
		return fmt.Sprintf("新增记录 %s", ip), nil
	}
	// 记录集已包含目标 IP 则无需更新
	for _, v := range oldVals {
		if v == ip {
			return fmt.Sprintf("无需更新 (%s)", ip), nil
		}
	}
	// 修改接口官方位于 v2.1（v2 仅提供创建 / 查询 / 删除）
	if _, err := m.huaweiDNSCall(ak, sk, http.MethodPut,
		"/v2.1/zones/"+zoneID+"/recordsets/"+recID, nil, buildBody()); err != nil {
		return "", fmt.Errorf("huaweicloud 修改记录集失败: %v", err)
	}
	return fmt.Sprintf("已更新 %s -> %s", strings.Join(oldVals, ","), ip), nil
}

// ---- GoDaddy ----

const godaddyEndpoint = "https://api.godaddy.com/v1"

// godaddyDo 调用 GoDaddy API（sso-key 鉴权）。body 非 nil 时以 JSON 提交。
func (m *Manager) godaddyDo(key, secret, method, reqURL string, body any) ([]byte, error) {
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}
		rd = strings.NewReader(string(b))
	}
	req, err := http.NewRequest(method, reqURL, rd)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "sso-key "+key+":"+secret)
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
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, cutText(string(data), 200))
	}
	return data, nil
}

// godaddy 更新 GoDaddy DNS 记录（PATCH 整体替换该 type+name 的记录集）。
func (m *Manager) godaddy(domain, rtype, ip string, t config.DDNSTask) (string, error) {
	key, secret, err := keyPair(t.Token, t.AccessKeyID, t.AccessKey, "godaddy")
	if err != nil {
		return "", err
	}
	sub, base := splitDomain(domain)
	// GoDaddy 用 @ 表示根域名，splitDomain 对根域名恰好返回 "@"，直接使用
	name := sub
	reqURL := fmt.Sprintf("%s/domains/%s/records/%s/%s", godaddyEndpoint, base, rtype, url.PathEscape(name))

	// 1. 查现有记录并比对
	data, err := m.godaddyDo(key, secret, http.MethodGet, reqURL, nil)
	if err != nil {
		return "", fmt.Errorf("godaddy 查询记录失败: %v", err)
	}
	var recs []struct {
		Data string `json:"data"`
	}
	if err := json.Unmarshal(data, &recs); err != nil {
		return "", fmt.Errorf("godaddy 解析记录失败: %v", err)
	}
	oldVals := make([]string, 0, len(recs))
	for _, r := range recs {
		if r.Data == ip {
			return fmt.Sprintf("无需更新 (%s)", ip), nil
		}
		oldVals = append(oldVals, r.Data)
	}

	// TTL：0 = 传 GoDaddy 默认值 6001；最小 600，低于 600 按 600 传
	ttl := 6001
	if v := t.TTL; v > 0 {
		if v < 600 {
			v = 600
		}
		ttl = v
	}
	// 2. PATCH 替换该 type+name 的记录集（无记录时等效于新增）
	patchBody := []map[string]any{{"data": ip, "ttl": ttl, "name": name, "type": rtype}}
	if _, err := m.godaddyDo(key, secret, http.MethodPatch, reqURL, patchBody); err != nil {
		return "", fmt.Errorf("godaddy 更新记录失败: %v", err)
	}
	if len(oldVals) == 0 {
		return fmt.Sprintf("新增记录 %s", ip), nil
	}
	return fmt.Sprintf("已更新 %s -> %s", strings.Join(oldVals, ","), ip), nil
}

// ---- Porkbun ----
//
// 使用官方公开的 v0 接口（POST JSON）。鉴权除 Basic Auth 外，
// 官方同样支持在请求体携带 apikey/secretapikey，这里两者同时发送以兼容不同网关形态。
const porkbunEndpoint = "https://api.porkbun.com/api/json/v0"

// porkbunPost 调用 Porkbun v0 接口，响应 status 必须为 SUCCESS 才算成功。
func (m *Manager) porkbunPost(key, secret, path string, payload map[string]any) (map[string]any, error) {
	if payload == nil {
		payload = map[string]any{}
	}
	payload["apikey"] = key
	payload["secretapikey"] = secret
	b, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequest(http.MethodPost, porkbunEndpoint+path, strings.NewReader(string(b)))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.SetBasicAuth(key, secret)
	resp, err := m.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	var out map[string]any
	if err := json.Unmarshal(data, &out); err != nil {
		return nil, fmt.Errorf("porkbun 响应解析失败: %s", cutText(string(data), 200))
	}
	status, _ := out["status"].(string)
	if !strings.EqualFold(status, "SUCCESS") {
		msg, _ := out["message"].(string)
		if msg == "" {
			msg = string(data)
		}
		return nil, fmt.Errorf("porkbun 返回 %s: %s", status, cutText(msg, 200))
	}
	return out, nil
}

// porkbunRecordID 兼容 id 为字符串 / 数字两种返回形态。
func porkbunRecordID(v any) string {
	switch n := v.(type) {
	case string:
		return n
	case float64:
		return strconv.FormatInt(int64(n), 10)
	case nil:
		return ""
	default:
		return fmt.Sprint(v)
	}
}

// porkbun 更新 Porkbun DNS 记录：retrieve 比对后 edit_by_id，无记录则 create。
func (m *Manager) porkbun(domain, rtype, ip string, t config.DDNSTask) (string, error) {
	key, secret, err := keyPair(t.Token, t.AccessKeyID, t.AccessKey, "porkbun")
	if err != nil {
		return "", err
	}
	_, base := splitDomain(domain)
	fqdn := strings.TrimSuffix(strings.ToLower(domain), ".")

	// 1. 取回全部记录，筛出 name 等于完整域名且类型匹配的
	out, err := m.porkbunPost(key, secret, "/domains/"+base+"/records/retrieve", nil)
	if err != nil {
		return "", fmt.Errorf("porkbun 查询记录失败: %v", err)
	}
	raw, _ := out["records"].([]any)
	recID, oldIP := "", ""
	for _, item := range raw {
		rec, _ := item.(map[string]any)
		if !strings.EqualFold(fmt.Sprint(rec["type"]), rtype) {
			continue
		}
		name := strings.TrimSuffix(strings.ToLower(fmt.Sprint(rec["name"])), ".")
		if name != fqdn {
			continue
		}
		id := porkbunRecordID(rec["id"])
		if id == "" {
			continue
		}
		recID, oldIP = id, fmt.Sprint(rec["content"])
		break
	}
	if recID != "" && oldIP == ip {
		return fmt.Sprintf("无需更新 (%s)", ip), nil
	}

	// TTL：0 = 不传（Porkbun 默认 600）；最小 600，低于 600 按 600 传
	ttl := ""
	if v := t.TTL; v > 0 {
		if v < 600 {
			v = 600
		}
		ttl = strconv.Itoa(v)
	}
	body := map[string]any{"type": rtype, "name": fqdn, "content": ip}
	if ttl != "" {
		body["ttl"] = ttl
	}

	if recID == "" {
		if _, err := m.porkbunPost(key, secret, "/domains/"+base+"/records/create", body); err != nil {
			return "", fmt.Errorf("porkbun 新增记录失败: %v", err)
		}
		return fmt.Sprintf("新增记录 %s", ip), nil
	}
	if _, err := m.porkbunPost(key, secret, "/domains/"+base+"/records/edit/"+recID, body); err != nil {
		return "", fmt.Errorf("porkbun 修改记录失败: %v", err)
	}
	return fmt.Sprintf("已更新 %s -> %s", oldIP, ip), nil
}

// ---- Namecheap ----
//
// 凭据：AccessKeyID = ApiUser，AccessKey = ApiKey（Namecheap 后台「API 访问」页申请）。
// setHosts 是整体覆盖语义：先 getHosts 取回全部记录，合并本条后整体回写，
// 保留其他记录。Namecheap DNS 接口未提供 TTL 参数（TTL 由平台侧管理），故不传 TTL。
const namecheapEndpoint = "https://api.namecheap.com/xmlrpc.php"

// namecheapHost Namecheap 单条主机记录（HostName / Name 两种属性名并存，取非空者）。
type namecheapHost struct {
	HostName string `xml:"HostName,attr"`
	Name     string `xml:"Name,attr"`
	Type     string `xml:"Type,attr"`
	Address  string `xml:"Address,attr"`
}

// hostName 返回主机名（根域名可能为 @）。
func (h namecheapHost) hostName() string {
	if h.HostName != "" {
		return h.HostName
	}
	return h.Name
}

// namecheapResp Namecheap XML-RPC 通用响应（getHosts / setHosts 共用）。
type namecheapResp struct {
	Request struct {
		Response string `xml:"response,attr"`
		Errors   []struct {
			Number  string `xml:"Number,attr"`
			Message string `xml:",chardata"`
		} `xml:"Errors>Error"`
	} `xml:"request"`
	Response struct {
		Hosts []namecheapHost `xml:"DomainGetHostsResult>Host"`
	} `xml:"response"`
	Hosts []namecheapHost `xml:"DomainGetHostsResult>Host"` // 兼容直接挂在根下的布局
}

// namecheapErrText 提取 <Errors> 中的错误信息。
func namecheapErrText(out *namecheapResp) string {
	msgs := make([]string, 0, len(out.Request.Errors))
	for _, e := range out.Request.Errors {
		m := strings.TrimSpace(e.Message)
		if e.Number != "" {
			m = e.Number + " " + m
		}
		if m != "" {
			msgs = append(msgs, m)
		}
	}
	if len(msgs) == 0 {
		return "未知错误"
	}
	return strings.Join(msgs, "; ")
}

// namecheapClientIP 取当前出网 IP（Namecheap 的 ClientIp 参数），取不到返回空串。
func (m *Manager) namecheapClientIP() string {
	resp, err := m.client.Get("https://api.ipify.org")
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return ""
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, 64))
	if err != nil {
		return ""
	}
	ip := strings.TrimSpace(string(b))
	if net.ParseIP(ip) == nil {
		return ""
	}
	return ip
}

// namecheapCall 以表单方式调用 Namecheap XML-RPC 接口。
// 成功判定：<Errors> 为空且 response 属性非 ERROR。
func (m *Manager) namecheapCall(t config.DDNSTask, command string, extra url.Values) (*namecheapResp, error) {
	if t.AccessKeyID == "" || t.AccessKey == "" {
		return nil, fmt.Errorf("namecheap 需要配置 AccessKeyID（ApiUser）/ AccessKey（ApiKey）")
	}
	form := url.Values{
		"ApiUser": {t.AccessKeyID},
		"ApiKey":  {t.AccessKey},
		"Command": {command},
	}
	// ClientIp 取当前出网 IP，取不到就不传该参数
	if ip := m.namecheapClientIP(); ip != "" {
		form.Set("ClientIp", ip)
	}
	for k, v := range extra {
		form.Set(k, v[0])
	}
	resp, err := m.client.PostForm(namecheapEndpoint, form)
	if err != nil {
		return nil, fmt.Errorf("namecheap 请求 %s 失败: %v", command, err)
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("namecheap 读取 %s 响应失败: %v", command, err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("namecheap %s 返回 HTTP %d: %s", command, resp.StatusCode, cutText(string(b), 200))
	}
	var out namecheapResp
	if err := xml.Unmarshal(b, &out); err != nil {
		return nil, fmt.Errorf("namecheap %s 响应解析失败: %v（%s）", command, err, cutText(string(b), 200))
	}
	if len(out.Request.Errors) > 0 || out.Request.Response == "ERROR" {
		return nil, fmt.Errorf("namecheap %s 失败: %s", command, namecheapErrText(&out))
	}
	return &out, nil
}

// namecheap 更新 Namecheap DNS 记录（setHosts 整体覆盖，先查后合并回写）。
func (m *Manager) namecheap(domain, rtype, ip string, t config.DDNSTask) (string, error) {
	sub, base := splitDomain(domain)
	sld, tld, ok := strings.Cut(base, ".")
	if !ok || sld == "" || tld == "" {
		return "", fmt.Errorf("namecheap 域名格式无效: %s", base)
	}
	// 根域名主机名用 @
	target := sub

	// 1. 查现有记录（必须先取回才能合并）
	get, err := m.namecheapCall(t, "namecheap.domains.dns.getHosts",
		url.Values{"Sld": {sld}, "Tld": {tld}})
	if err != nil {
		return "", fmt.Errorf("namecheap 查询记录失败: %v", err)
	}
	hosts := get.Response.Hosts
	if len(hosts) == 0 {
		hosts = get.Hosts
	}

	// 2. 合并：首条同名同类型的记录替换为新 IP，其余记录原样保留；
	//    同名同类型的多余记录一并收敛为单条（DDNS 单值语义）
	oldIP := ""
	found := false
	merged := make([]namecheapHost, 0, len(hosts)+1)
	for _, h := range hosts {
		if strings.EqualFold(h.hostName(), target) && strings.EqualFold(h.Type, rtype) {
			if found {
				continue
			}
			oldIP = h.Address
			found = true
			h.Address = ip
		}
		merged = append(merged, h)
	}
	if found && oldIP == ip {
		return fmt.Sprintf("无需更新 (%s)", ip), nil
	}
	if !found {
		merged = append(merged, namecheapHost{HostName: target, Type: rtype, Address: ip})
	}

	// 3. 整体回写（setHosts 为覆盖语义；仅支持 HostName/RecordType/Address 三元组，
	//    TTL、MX 优先级等属性由 Namecheap 平台侧管理）
	set := url.Values{"Sld": {sld}, "Tld": {tld}, "DomainName": {base}}
	for i, h := range merged {
		idx := strconv.Itoa(i + 1)
		set.Set("HostName"+idx, h.hostName())
		set.Set("RecordType"+idx, h.Type)
		set.Set("Address"+idx, h.Address)
	}
	if _, err := m.namecheapCall(t, "namecheap.domains.dns.setHosts", set); err != nil {
		return "", fmt.Errorf("namecheap 写入记录失败: %v", err)
	}
	if found {
		return fmt.Sprintf("已更新 %s -> %s", oldIP, ip), nil
	}
	return fmt.Sprintf("新增记录 %s", ip), nil
}

// ---- NameSilo ----
//
// 凭据：t.Token 填 NameSilo API Key。接口为 GET + XML，响应含 <reply>OK</reply> 才算成功。
const namesiloEndpoint = "https://www.namesilo.com/api/dns"

// namesiloResp NameSilo XML 响应。
type namesiloResp struct {
	Reply   string `xml:"reply"`
	Detail  string `xml:"detail"`
	Records []struct {
		RRID  string `xml:"rrid"`
		Type  string `xml:"type"`
		Host  string `xml:"host"`
		Value string `xml:"value"`
		TTL   string `xml:"ttl"`
	} `xml:"resource_record_set>resource_record"`
}

// namesiloGet 调用 NameSilo DNS 接口（GET + XML）。
func (m *Manager) namesiloGet(action, key, domain string, params url.Values) (*namesiloResp, error) {
	q := url.Values{"version": {"v2"}, "type": {"xml"}, "key": {key}, "domain": {domain}}
	for k, v := range params {
		q.Set(k, v[0])
	}
	target := namesiloEndpoint + "/" + action + "?" + q.Encode()
	resp, err := m.client.Get(target)
	if err != nil {
		return nil, fmt.Errorf("namesilo %s 请求失败: %v", action, err)
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("namesilo %s 读取响应失败: %v", action, err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("namesilo %s 返回 HTTP %d: %s", action, resp.StatusCode, cutText(string(b), 200))
	}
	var out namesiloResp
	if err := xml.Unmarshal(b, &out); err != nil {
		return nil, fmt.Errorf("namesilo %s 响应解析失败: %v（%s）", action, err, cutText(string(b), 200))
	}
	if strings.TrimSpace(out.Reply) != "OK" {
		return nil, fmt.Errorf("namesilo %s 失败: %s %s", action,
			strings.TrimSpace(out.Reply), strings.TrimSpace(out.Detail))
	}
	return &out, nil
}

// namesiloHostMatches 判断 NameSilo 返回的 host 是否为目标主机
// （根域名可能返回空串、@ 或完整域名）。
func namesiloHostMatches(got, want, base string) bool {
	got = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(got), "."))
	want = strings.ToLower(want)
	if got == want {
		return true
	}
	if want == "" {
		return got == "" || got == "@" || got == base
	}
	return got == want+"."+base
}

// namesilo 更新 NameSilo DNS 记录（dnsListRecords 比对，dnsUpdateRecord 修改 / dnsAddRecord 新增）。
func (m *Manager) namesilo(domain, rtype, ip string, t config.DDNSTask) (string, error) {
	key := t.Token
	if key == "" {
		return "", fmt.Errorf("namesilo 需要配置 API Key（填在 Token）")
	}
	sub, base := splitDomain(domain)
	// 根域名 host 留空字符串（NameSilo 用空表示根）
	host := sub
	if sub == "@" {
		host = ""
	}

	// 1. 查现有记录
	out, err := m.namesiloGet("dnsListRecords", key, base, nil)
	if err != nil {
		return "", err
	}
	rrID, oldIP := "", ""
	for _, r := range out.Records {
		if !strings.EqualFold(r.Type, rtype) {
			continue
		}
		if !namesiloHostMatches(r.Host, host, base) {
			continue
		}
		rrID, oldIP = r.RRID, r.Value
		break
	}
	if rrID != "" && oldIP == ip {
		return fmt.Sprintf("无需更新 (%s)", ip), nil
	}

	// TTL：0 = 不传（NameSilo 默认 7207）；最小 600，低于 600 按 600 传
	ttl := ""
	if v := t.TTL; v > 0 {
		if v < 600 {
			v = 600
		}
		ttl = strconv.Itoa(v)
	}
	params := url.Values{"rrtype": {rtype}, "rrhost": {host}, "rrvalue": {ip}}
	if ttl != "" {
		params.Set("rrttl", ttl)
	}

	if rrID == "" {
		if _, err := m.namesiloGet("dnsAddRecord", key, base, params); err != nil {
			return "", fmt.Errorf("namesilo 新增记录失败: %v", err)
		}
		return fmt.Sprintf("新增记录 %s", ip), nil
	}
	params.Set("rrid", rrID)
	if _, err := m.namesiloGet("dnsUpdateRecord", key, base, params); err != nil {
		return "", fmt.Errorf("namesilo 修改记录失败: %v", err)
	}
	return fmt.Sprintf("已更新 %s -> %s", oldIP, ip), nil
}
