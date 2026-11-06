package dnsprovider

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
	"strings"
	"time"
)

const aliyunDNSAPI = "https://alidns.aliyuncs.com/"

// aliyunProvider 阿里云 DNS（alidns）的 DNS-01 Provider，RPC 签名 V1（HMAC-SHA1）。
// 与 DDNS 模块的阿里云实现同一套签名规则。
type aliyunProvider struct {
	id     string
	secret string
	client *http.Client
	// zoneCache 完整域名 -> 托管域名（DomainName）
	zoneCache map[string]string
	// domainList 账号下的托管域名列表（懒加载一次）
	domainList []string
	domainLoad bool
}

func newAliyun(id, secret string) Provider {
	return &aliyunProvider{
		id:        id,
		secret:    secret,
		client:    &http.Client{Timeout: 20 * time.Second},
		zoneCache: map[string]string{},
	}
}

func (p *aliyunProvider) Name() string { return "阿里云 DNS" }

// percentEncode 阿里云 RPC 要求的百分号编码（RFC3986 且大写十六进制）。
func aliyunPercentEncode(s string) string {
	u := url.QueryEscape(s)
	u = strings.ReplaceAll(u, "+", "%20")
	u = strings.ReplaceAll(u, "*", "%2A")
	u = strings.ReplaceAll(u, "%7E", "~")
	return u
}

// aliyunRPCSig 计算 HMAC-SHA1 签名（GET + 规范化 Query + 空 Body）。
func (p *aliyunProvider) rpcSig(params url.Values) string {
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
		sb.WriteString(aliyunPercentEncode(k))
		sb.WriteString("=")
		sb.WriteString(aliyunPercentEncode(params.Get(k)))
	}
	stringToSign := "GET&%2F&" + aliyunPercentEncode(sb.String())
	mac := hmac.New(sha1.New, []byte(p.secret+"&"))
	mac.Write([]byte(stringToSign))
	return base64.StdEncoding.EncodeToString(mac.Sum(nil))
}

// call 调用阿里云 DNS RPC 接口。
func (p *aliyunProvider) call(action string, params url.Values) (map[string]any, error) {
	common := url.Values{
		"Format":           {"JSON"},
		"Version":          {"2015-01-09"},
		"AccessKeyId":      {p.id},
		"SignatureMethod":  {"HMAC-SHA1"},
		"SignatureVersion": {"1.0"},
		"Action":           {action},
	}
	nonce := make([]byte, 8)
	_, _ = rand.Read(nonce) // 失败时退化为全零 nonce，仅影响防重放不影响正确性
	common.Set("SignatureNonce", hex.EncodeToString(nonce))
	common.Set("Timestamp", time.Now().UTC().Format("2006-01-02T15:04:05Z"))
	for k, v := range params {
		common[k] = v
	}
	common.Set("Signature", p.rpcSig(common))

	resp, err := p.client.Get(aliyunDNSAPI + "?" + common.Encode())
	if err != nil {
		return nil, fmt.Errorf("阿里云 DNS 请求失败: %w", err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	var out map[string]any
	if err := json.Unmarshal(data, &out); err != nil {
		return nil, fmt.Errorf("阿里云 DNS 响应解析失败: %s", cutText(string(data), 200))
	}
	if code, bad := out["Code"]; bad && fmt.Sprint(code) != "" {
		msg, _ := out["Message"].(string)
		return nil, fmt.Errorf("阿里云 DNS 错误[%s]: %s", code, msg)
	}
	return out, nil
}

// findZone 从长到短逐级确定 fqdn 所属的托管域名，结果缓存。
func (p *aliyunProvider) findZone(fqdn string) (string, error) {
	if z, ok := p.zoneCache[fqdn]; ok {
		return z, nil
	}
	if !p.domainLoad {
		list, err := p.loadDomains()
		if err != nil {
			return "", err
		}
		p.domainList = list
		p.domainLoad = true
	}
	best := ""
	for _, d := range p.domainList {
		if fqdn == d || strings.HasSuffix(fqdn, "."+d) {
			if len(d) > len(best) {
				best = d
			}
		}
	}
	if best == "" {
		return "", fmt.Errorf("阿里云账号下找不到 %s 对应的托管域名", fqdn)
	}
	p.zoneCache[fqdn] = best
	return best, nil
}

// loadDomains 分页拉取账号下全部托管域名。
func (p *aliyunProvider) loadDomains() ([]string, error) {
	var out []string
	for page := 1; page <= 10; page++ {
		res, err := p.call("DescribeDomains", url.Values{
			"PageNumber": {fmt.Sprint(page)},
			"PageSize":   {"100"},
		})
		if err != nil {
			return nil, err
		}
		data, _ := res["Domains"].(map[string]any)
		arr, _ := data["Domain"].([]any)
		for _, item := range arr {
			m, _ := item.(map[string]any)
			if name := fmt.Sprint(m["DomainName"]); name != "" {
				out = append(out, strings.ToLower(name))
			}
		}
		if len(arr) < 100 {
			break
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("阿里云账号下没有任何托管域名")
	}
	return out, nil
}

// Present 创建 _acme-challenge 的 TXT 记录，返回删除该记录的 cleanup。
func (p *aliyunProvider) Present(fqdn, value string) (func() error, error) {
	name := strings.ToLower(strings.TrimSuffix(fqdn, "."))
	zone, err := p.findZone(name)
	if err != nil {
		return nil, err
	}
	rr := strings.TrimSuffix(name, "."+zone)
	if rr == name {
		// fqdn 就是托管域名本身（理论不会发生，_acme-challenge 前缀至少存在）
		rr = strings.TrimPrefix(name, zone)
		rr = strings.TrimSuffix(strings.TrimSpace(rr), ".")
		if rr == "" {
			rr = "@"
		}
	}

	// 清理上次残留的同名 TXT 记录（同值才删，避免误伤别的用途）
	p.deleteExistingTXT(zone, rr, value)

	res, err := p.call("AddDomainRecord", url.Values{
		"DomainName": {zone},
		"RR":         {rr},
		"Type":       {"TXT"},
		"Value":      {value},
		"TTL":        {"600"},
	})
	if err != nil {
		return nil, fmt.Errorf("创建 TXT 记录失败: %w", err)
	}
	recID := fmt.Sprint(res["RecordId"])
	if recID == "" || recID == "<nil>" {
		return nil, fmt.Errorf("创建 TXT 记录失败: 未返回 RecordId")
	}

	cleanup := func() error {
		_, err := p.call("DeleteDomainRecord", url.Values{"RecordId": {recID}})
		if err != nil {
			return fmt.Errorf("删除 TXT 记录失败: %w", err)
		}
		return nil
	}
	return cleanup, nil
}

// deleteExistingTXT 删除与验证值相同的残留 TXT 记录。
func (p *aliyunProvider) deleteExistingTXT(zone, rr, value string) {
	res, err := p.call("DescribeDomainRecords", url.Values{
		"DomainName": {zone},
		"RRKeyWord":  {rr},
		"TypeKeyWord": {"TXT"},
	})
	if err != nil {
		return
	}
	data, _ := res["DomainRecords"].(map[string]any)
	arr, _ := data["Record"].([]any)
	for _, item := range arr {
		m, _ := item.(map[string]any)
		if fmt.Sprint(m["RR"]) != rr || fmt.Sprint(m["Type"]) != "TXT" {
			continue
		}
		if fmt.Sprint(m["Value"]) != value {
			continue
		}
		_, _ = p.call("DeleteDomainRecord", url.Values{"RecordId": {fmt.Sprint(m["RecordId"])}})
	}
}
