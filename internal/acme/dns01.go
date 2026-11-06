package acme

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"strings"
	"time"

	"netkit/internal/dnsprovider"
)

// dns01Challenge 一个 DNS-01 挑战。
type dns01Challenge struct {
	authzURL     string
	challengeURL string
	token        string
	identifier   string // 域名
}

// dnstxtValue 计算 DNS-01 需要的 TXT 值：
// base64url(sha256(keyAuthorization))，其中 keyAuthorization = token + "." + thumbprint。
func dnstxtValue(token, thumbprint string) string {
	keyAuth := token + "." + thumbprint
	h := sha256.Sum256([]byte(keyAuth))
	return base64.RawURLEncoding.EncodeToString(h[:])
}

// challengeFQDN 返回 TXT 记录应写入的完整域名：_acme-challenge.<域名去掉通配符>
func challengeFQDN(domain string) string {
	d := strings.TrimPrefix(domain, "*.")
	return "_acme-challenge." + d
}

// collectDNS01 收集订单中所有 DNS-01 挑战。
func (c *Client) collectDNS01(order *orderResp) ([]dns01Challenge, error) {
	var out []dns01Challenge
	for _, azURL := range order.Authorizations {
		var az authzResp
		if err := c.getOrder(azURL, &az); err != nil {
			return nil, err
		}
		found := false
		for i := range az.Challenges {
			if az.Challenges[i].Type == "dns-01" {
				out = append(out, dns01Challenge{
					authzURL:     azURL,
					challengeURL: az.Challenges[i].URL,
					token:        az.Challenges[i].Token,
					identifier:   az.Identifier.Value,
				})
				found = true
				break
			}
		}
		if !found {
			return nil, fmt.Errorf("订单中没有 dns-01 验证（域名 %s）", az.Identifier.Value)
		}
	}
	return out, nil
}

// solveDNS01 完成 DNS-01 验证：写入 TXT → 等待传播 → 提交 → 轮询。
func (c *Client) solveDNS01(challenges []dns01Challenge, prov dnsprovider.Provider, logf func(string, ...any)) error {
	tp, err := c.thumbprint()
	if err != nil {
		return err
	}

	// 1. 写入全部 TXT 记录，并收集 cleanup
	type pending struct {
		fqdn    string
		value   string
		cleanup func() error
	}
	var created []pending
	defer func() {
		for _, p := range created {
			if err := p.cleanup(); err != nil && logf != nil {
				logf("清理 TXT 记录 %s 失败: %v", p.fqdn, err)
			} else if logf != nil {
				logf("已清理 TXT 记录 %s", p.fqdn)
			}
		}
	}()

	for _, ch := range challenges {
		fqdn := challengeFQDN(ch.identifier)
		value := dnstxtValue(ch.token, tp)
		if logf != nil {
			logf("写入 TXT: %s = %s", fqdn, value)
		}
		cleanup, err := prov.Present(fqdn, value)
		if err != nil {
			return fmt.Errorf("写入 %s 的 TXT 记录失败: %w", fqdn, err)
		}
		created = append(created, pending{fqdn: fqdn, value: value, cleanup: cleanup})
	}

	// 2. 等待 DNS 传播：轮询权威 DNS，直到查到预期值
	for _, ch := range challenges {
		fqdn := challengeFQDN(ch.identifier)
		value := dnstxtValue(ch.token, tp)
		if err := waitForTXT(fqdn, value, 180*time.Second, logf); err != nil {
			return err
		}
	}

	// 3. 提交验证
	for _, ch := range challenges {
		if _, _, _, err := c.acmePostRetry(ch.challengeURL, map[string]any{}, true); err != nil {
			return fmt.Errorf("提交 DNS 验证失败: %w", err)
		}
	}

	// 4. 轮询授权状态
	for _, ch := range challenges {
		authzURL := ch.authzURL
		domain := ch.identifier
		if err := c.poll(5*time.Second, 60, func() (bool, error) {
			var az authzResp
			if err := c.getOrder(authzURL, &az); err != nil {
				return false, err
			}
			switch az.Status {
			case "valid":
				return true, nil
			case "invalid":
				return false, fmt.Errorf("域名 %s 的 DNS-01 验证失败，请确认 TXT 记录已正确写入并生效", domain)
			}
			return false, nil
		}); err != nil {
			return err
		}
	}
	return nil
}

// waitForTXT 轮询公共 DNS，直到目标 TXT 值出现。
func waitForTXT(fqdn, want string, timeout time.Duration, logf func(string, ...any)) error {
	deadline := time.Now().Add(timeout)
	// 依次尝试多个公共 DNS，避免单个解析器缓存导致误判
	resolvers := []string{"8.8.8.8:53", "1.1.1.1:53", "223.5.5.5:53", "119.29.29.29:53"}
	attempt := 0
	for time.Now().Before(deadline) {
		attempt++
		for _, rs := range resolvers {
			vals, err := lookupTXT(fqdn, rs)
			if err != nil {
				continue
			}
			for _, v := range vals {
				if strings.Trim(v, "\"") == strings.Trim(want, "\"") || v == want {
					if logf != nil {
						logf("TXT 已生效（%s，第 %d 次探测）", rs, attempt)
					}
					return nil
				}
			}
		}
		if logf != nil && attempt%6 == 1 {
			logf("等待 DNS 传播中…（%s，已等待 %ds）", fqdn, attempt*5)
		}
		time.Sleep(5 * time.Second)
	}
	return fmt.Errorf("等待 %s 的 TXT 记录生效超时（%v），请检查 DNS 服务商是否已正确写入", fqdn, timeout)
}

// lookupTXT 用指定 DNS 服务器查询 TXT 记录。
func lookupTXT(fqdn, server string) ([]string, error) {
	r := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			d := net.Dialer{Timeout: 5 * time.Second}
			return d.DialContext(ctx, "udp", server)
		},
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return r.LookupTXT(ctx, fqdn)
}

// ObtainDNS01 用 DNS-01 方式为（可能含通配符的）域名申请证书。
func (c *Client) ObtainDNS01(domains []string, email string, dirURL string, prov dnsprovider.Provider, logf func(string, ...any)) (certPEM, keyPEM string, err error) {
	if dirURL == "" {
		dirURL = leDirectory
	}
	if len(domains) == 0 {
		return "", "", fmt.Errorf("请至少填写一个域名")
	}
	// 注意：CommonName 必须与订单 identifier 完全一致（含通配符），
	// 否则 CA 会报 "CSR does not specify same identifiers as Order"。
	// 但账号注册用的联系标识可以去掉通配符。
	accountID := strings.TrimPrefix(domains[0], "*.")
	if err := c.initAccount(accountID, email, dirURL); err != nil {
		return "", "", err
	}
	primary := domains[0]

	// 1. 新建订单
	orderURL := c.dir["newOrder"]
	order := orderResp{}
	identifiers := make([]map[string]string, 0, len(domains))
	for _, d := range domains {
		identifiers = append(identifiers, map[string]string{"type": "dns", "value": d})
	}
	data, loc, code, err := c.acmePostRetry(orderURL, map[string]any{"identifiers": identifiers}, true)
	if err != nil {
		return "", "", fmt.Errorf("创建订单失败: %w", err)
	}
	if code < 200 || code >= 300 || loc == "" {
		return "", "", acmeError(orderURL, code, "创建订单失败", data)
	}
	if err := c.getOrder(loc, &order); err != nil {
		return "", "", err
	}

	// 2. 走 DNS-01
	challenges, err := c.collectDNS01(&order)
	if err != nil {
		return "", "", err
	}
	if err := c.solveDNS01(challenges, prov, logf); err != nil {
		return "", "", err
	}

	// 3. 生成 CSR 并 finalize
	orderKey, err := ecdsaGenerate()
	if err != nil {
		return "", "", err
	}
	csrDER, err := createCSR(primary, domains, orderKey)
	if err != nil {
		return "", "", err
	}
	fdata, _, code, err := c.acmePostRetry(order.Finalize, map[string]any{"csr": b64(csrDER)}, true)
	if logf != nil {
		logf("finalize 返回: http %d, body=%s", code, truncateStr(string(fdata), 200))
	}
	if err != nil || code >= 300 {
		return "", "", fmt.Errorf("提交 CSR 失败 (http %d): %v %s", code, err, truncateStr(string(fdata), 150))
	}

	if logf != nil {
		logf("CSR 已提交，开始等待订单生效（finalize=%s）", order.Finalize)
	}

	// 4. 等订单有效并下载证书
	if err := c.poll(3*time.Second, 60, func() (bool, error) {
		if err := c.getOrder(loc, &order); err != nil {
			return false, err
		}
		switch order.Status {
		case "valid":
			return true, nil
		case "invalid":
			return false, fmt.Errorf("订单无效")
		}
		return false, nil
	}); err != nil {
		return "", "", err
	}
	if logf != nil {
		logf("订单状态: %s，证书地址: %q", order.Status, order.Certificate)
	}
	if order.Certificate == "" {
		return "", "", fmt.Errorf("订单未返回证书下载地址（状态 %s），可能是 CA 仍在签发中，请稍后重试", order.Status)
	}
	return c.downloadCert(order.Certificate, orderKey)
}

// ecdsaGenerate 生成证书私钥。
func ecdsaGenerate() (*ecdsa.PrivateKey, error) {
	return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
}

// createCSR 生成包含全部域名的 CSR。
func createCSR(primary string, domains []string, key *ecdsa.PrivateKey) ([]byte, error) {
	return x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject:  pkix.Name{CommonName: primary},
		DNSNames: domains,
	}, key)
}

// downloadCert 下载证书链并编码私钥。
func (c *Client) downloadCert(certURL string, key *ecdsa.PrivateKey) (string, string, error) {
	if certURL == "" {
		return "", "", fmt.Errorf("订单未提供证书下载地址")
	}
	// 证书下载用普通 GET：该 endpoint 直接返回 PEM 证书链（不是 JSON），
	// 若走 POST-as-GET 会得到非预期响应。
	resp, err := c.http.Get(certURL)
	if err != nil {
		return "", "", fmt.Errorf("下载证书失败: %w", err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return "", "", fmt.Errorf("读取证书失败: %w", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", "", fmt.Errorf("下载证书失败 (http %d): %s", resp.StatusCode, truncateStr(string(data), 200))
	}
	// 强烈校验：必须真的拿到 PEM 证书，否则后续会得到一个"成功但为空"的坏状态
	if !bytes.Contains(data, []byte("-----BEGIN CERTIFICATE-----")) {
		return "", "", fmt.Errorf("证书内容无效，未取得 PEM 数据（返回: %s）", truncateStr(string(data), 200))
	}
	kb, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return "", "", err
	}
	keyPEM := string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kb}))
	return string(data), keyPEM, nil
}

// truncateStr 截断字符串用于错误提示。
func truncateStr(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

var _ = json.Marshal
