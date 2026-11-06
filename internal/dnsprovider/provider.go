// Package dnsprovider 为 ACME DNS-01 验证提供 DNS 记录读写能力。
package dnsprovider

import (
	"fmt"
	"strings"
)

// Provider 抽象 DNS 记录操作。
// 实现方需保证 Present 创建的 TXT 记录能被公网 DNS 查询到。
type Provider interface {
	// Name 返回服务商标识（用于展示）。
	Name() string
	// Present 为 fqdn 创建一条 TXT 记录（值为 value）。
	// 返回一个 cleanup 函数，用于验证完成后删除该记录。
	Present(fqdn, value string) (cleanup func() error, err error)
}

// Credentials DNS 服务商凭据。
type Credentials struct {
	Provider string            `json:"provider"` // dnshe / cloudflare / aliyun / dnspod
	Key      string            `json:"key"`      // DNSHE: API Key；Cloudflare: API Token；阿里云: AccessKeyID；DNSPod: ID,Token
	Secret   string            `json:"secret"`   // DNSHE: API Secret；阿里云: AccessKey
	Extra    map[string]string `json:"extra"`
}

// New 按凭据创建对应服务商的 Provider。
func New(c Credentials) (Provider, error) {
	switch strings.ToLower(strings.TrimSpace(c.Provider)) {
	case "dnshe":
		if c.Key == "" || c.Secret == "" {
			return nil, fmt.Errorf("DNSHE 需要填写 API Key 与 API Secret")
		}
		return newDNSHE(c.Key, c.Secret), nil
	case "cloudflare":
		if c.Key == "" {
			return nil, fmt.Errorf("Cloudflare 需要填写 API Token")
		}
		return newCloudflare(c.Key), nil
	case "aliyun":
		if c.Key == "" || c.Secret == "" {
			return nil, fmt.Errorf("阿里云 DNS 需要填写 AccessKeyID 与 AccessKey")
		}
		return newAliyun(c.Key, c.Secret), nil
	case "dnspod", "tencentcloud":
		if c.Key == "" {
			return nil, fmt.Errorf("DNSPod（腾讯云）需要填写 Token（ID,Token 格式）")
		}
		return newDNSPod(c.Key), nil
	case "":
		return nil, fmt.Errorf("请选择 DNS 服务商")
	default:
		return nil, fmt.Errorf("暂不支持的 DNS 服务商: %s", c.Provider)
	}
}

// cutText 截断长文本用于错误信息。
func cutText(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

// SplitChallengeName 从 _acme-challenge.xxx 形式的 fqdn 中拆出记录名与根域名。
// DNSHE: 返回 (记录名, 子域名全名)，例如：
//
//	_acme-challenge.ziuzu.cc.cd -> ("_acme-challenge", "ziuzu.cc.cd")
//	_acme-challenge.a.ziuzu.cc.cd -> ("_acme-challenge.a", "ziuzu.cc.cd")
func SplitChallengeName(fqdn string) (recordName string, zone string) {
	d := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(fqdn), "."))
	// 去掉前导的 _acme-challenge.
	const prefix = "_acme-challenge."
	if !strings.HasPrefix(d, prefix) {
		return d, d
	}
	rest := strings.TrimPrefix(d, prefix)
	// rest 形如 a.ziuzu.cc.cd 或 ziuzu.cc.cd
	labels := strings.Split(rest, ".")
	if len(labels) <= 2 {
		return "_acme-challenge", rest
	}
	// DNSHE 的子域名是"去掉最后两段"后的部分，所以 zone 保留全部 rest
	// 记录名则是 _acme-challenge（挂在子域名下），多级子域用 _acme-challenge.a
	subCount := len(labels) - 2
	name := "_acme-challenge"
	if subCount > 1 {
		name = "_acme-challenge." + strings.Join(labels[:subCount-1], ".")
	}
	return name, rest
}

// DomainLabels 返回域名层级，便于调试。
func DomainLabels(fqdn string) []string {
	return strings.Split(strings.TrimSuffix(fqdn, "."), ".")
}
