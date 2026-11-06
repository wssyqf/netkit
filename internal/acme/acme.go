// Package acme 基于标准库实现的 ACME v2 客户端，支持 Let's Encrypt HTTP-01 证书申请。
package acme

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

const leDirectory = "https://acme-v02.api.letsencrypt.org/directory"

// Client 一个 ACME 客户端，持有账号密钥与目录。
type Client struct {
	mu       sync.Mutex
	dir      map[string]string
	key      *ecdsa.PrivateKey
	keyID    string
	nonces   []string
	http     *http.Client
	nextPort int // HTTP-01 验证监听端口（默认 80）
}

// NewClient 创建客户端；email 用于账号注册。
func NewClient() (*Client, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	return &Client{
		key:  key,
		http: &http.Client{Timeout: 30 * time.Second},
	}, nil
}

// ---- JWS 基础 ----

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

func (c *Client) jwk() map[string]any {
	pub := c.key.PublicKey
	return map[string]any{
		"kty": "EC", "crv": "P-256",
		"x": b64(pub.X.FillBytes(make([]byte, 32))),
		"y": b64(pub.Y.FillBytes(make([]byte, 32))),
	}
}

func (c *Client) thumbprint() (string, error) {
	b, err := json.Marshal(c.jwk())
	if err != nil {
		return "", err
	}
	h := sha256.Sum256(b)
	return b64(h[:]), nil
}

func (c *Client) popNonce() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	if n := len(c.nonces); n > 0 {
		v := c.nonces[n-1]
		c.nonces = c.nonces[:n-1]
		return v
	}
	return ""
}

func (c *Client) pushNonce(n string) {
	c.mu.Lock()
	c.nonces = append(c.nonces, n)
	c.mu.Unlock()
}

// signJWS 生成请求 JWS。useKID=false 时携带 JWK（账号注册）。
func (c *Client) signJWS(url string, payload any, useKID bool) ([]byte, error) {
	// POST-as-GET 规范：payload 必须是空字符串（base64url 后为空），
	// 而不是 JSON 的 "null"。传 nil 时 json.Marshal 会得到 "null"，
	// 某些端点（如查询授权状态）会因此返回 400。
	var pb []byte
	if payload == nil {
		pb = []byte{}
	} else {
		var err error
		pb, err = json.Marshal(payload)
		if err != nil {
			return nil, err
		}
	}
	var header map[string]any
	if useKID {
		header = map[string]any{"alg": "ES256", "nonce": c.popNonce(), "url": url, "kid": c.keyID}
	} else {
		header = map[string]any{"alg": "ES256", "nonce": c.popNonce(), "url": url, "jwk": c.jwk()}
	}
	hb, err := json.Marshal(header)
	if err != nil {
		return nil, err
	}
	signing := []byte(b64(hb) + "." + b64(pb))
	h := sha256.Sum256(signing)
	// JWS ES256 要求 raw R||S（各 32 字节定长）格式，
	// 而非 ASN.1 DER —— 用 DER 会导致服务端 JWS 校验失败。
	r, ss, err := ecdsa.Sign(rand.Reader, c.key, h[:])
	if err != nil {
		return nil, err
	}
	sig := make([]byte, 64)
	r.FillBytes(sig[:32])
	ss.FillBytes(sig[32:])
	return json.Marshal(map[string]any{
		"protected": b64(hb), "payload": b64(pb), "signature": b64(sig),
	})
}

// acmePost 发送 POST-as-GET / POST 请求，返回 body、location、status。
func (c *Client) acmePost(url string, payload any, useKID bool) ([]byte, string, int, error) {
	body, err := c.signJWS(url, payload, useKID)
	if err != nil {
		return nil, "", 0, err
	}
	resp, err := c.http.Post(url, "application/jose+json", strings.NewReader(string(body)))
	if err != nil {
		return nil, "", 0, err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, "", resp.StatusCode, err
	}
	if n := resp.Header.Get("Replay-Nonce"); n != "" {
		c.pushNonce(n)
	}
	loc := resp.Header.Get("Location")
	return data, loc, resp.StatusCode, nil
}

// acmePostRetry 自动处理 badNonce 重试。
func (c *Client) acmePostRetry(url string, payload any, useKID bool) ([]byte, string, int, error) {
	data, loc, code, err := c.acmePost(url, payload, useKID)
	if err != nil {
		return data, loc, code, err
	}
	if code == http.StatusBadRequest && strings.Contains(string(data), "urn:ietf:params:acme:error:badNonce") {
		return c.acmePost(url, payload, useKID)
	}
	return data, loc, code, nil
}

// ---- ACME 流程 ----

type orderResp struct {
	Status         string   `json:"status"`
	Finalize       string   `json:"finalize"`
	Certificate    string   `json:"certificate"`
	Authorizations []string `json:"authorizations"`
	Expires        string   `json:"expires"`
}

type authzResp struct {
	Status     string `json:"status"`
	Identifier struct {
		Type  string `json:"type"`
		Value string `json:"value"`
	} `json:"identifier"`
	Challenges []struct {
		Type  string `json:"type"`
		URL   string `json:"url"`
		Token string `json:"token"`
	} `json:"challenges"`
}

type problemResp struct {
	Detail string `json:"detail"`
}

// Obtain 走完整 ACME 流程为 domain 申请证书，返回证书链 PEM 与私钥 PEM。
// challengePort 为 HTTP-01 验证监听端口（需要公网可访问，通常 80）。
// ParseDomains 把用户输入的域名列表规范化为去重后的数组。
// 支持逗号、空格、分号、换行分隔；自动去空白与大小写。
func ParseDomains(s string) []string {
	fields := strings.FieldsFunc(s, func(r rune) bool {
		return r == ',' || r == '，' || r == ' ' || r == '\n' || r == '\r' || r == ';' || r == '；'
	})
	seen := map[string]bool{}
	out := make([]string, 0, len(fields))
	for _, f := range fields {
		d := strings.ToLower(strings.TrimSpace(f))
		if d == "" || seen[d] {
			continue
		}
		seen[d] = true
		out = append(out, d)
	}
	return out
}

// ValidateDomains 校验域名格式。allowWildcard 为 true 时允许 *. 前缀（DNS-01 场景）。
func ValidateDomains(domains []string) error {
	return ValidateDomainsOpt(domains, false)
}

// ValidateDomainsOpt 校验域名格式，可指定是否允许通配符。
func ValidateDomainsOpt(domains []string, allowWildcard bool) error {
	if len(domains) == 0 {
		return fmt.Errorf("请至少填写一个域名")
	}
	for _, d := range domains {
		if strings.ContainsAny(d, " ,;，；\t") {
			return fmt.Errorf("域名 %q 含非法分隔符，请用英文逗号分开", d)
		}
		// 通配符域名必须用 DNS-01 验证，HTTP-01 无法签发
		if strings.HasPrefix(d, "*.") && !allowWildcard {
			return fmt.Errorf("通配符域名 %q 需要 DNS-01 验证，当前仅支持 HTTP-01，无法签发。"+
				"请去掉通配符逐个填写具体子域名（如 ziuzu.cc.cd），或在 DNS 服务商处手动申请通配符证书", d)
		}
		// 通配符只允许出现在最左侧的 *. 前缀
		check := d
		if strings.HasPrefix(check, "*.") {
			check = check[2:]
			if check == "" {
				return fmt.Errorf("通配符域名格式无效: %q", d)
			}
		}
		if strings.Contains(check, "*") {
			return fmt.Errorf("通配符只能写在最前面（如 *.example.com），当前: %q", d)
		}
		if !strings.Contains(check, ".") {
			return fmt.Errorf("域名 %q 缺少点号，请填写完整域名", d)
		}
		for _, label := range strings.Split(check, ".") {
			if label == "" {
				return fmt.Errorf("域名 %q 含空的标签", d)
			}
			if len(label) > 63 {
				return fmt.Errorf("域名 %q 的标签超过 63 字符", d)
			}
		}
	}
	return nil
}

// Obtain 为单个域名申请证书（兼容旧调用）。
func (c *Client) Obtain(domain, email string, challengePort int, dirURL string) (certPEM, keyPEM string, err error) {
	return c.ObtainMulti([]string{domain}, email, challengePort, dirURL)
}

// ObtainMulti 为多个域名申请同一张证书（SAN 证书）。
// 所有域名共用一张证书，各自需要通过 HTTP-01 验证。
func (c *Client) ObtainMulti(domains []string, email string, challengePort int, dirURL string) (certPEM, keyPEM string, err error) {
	if dirURL == "" {
		dirURL = leDirectory
	}
	if err := ValidateDomains(domains); err != nil {
		return "", "", err
	}
	primary := domains[0]
	if err := c.initAccount(primary, email, dirURL); err != nil {
		return "", "", err
	}
	// 1. 新建订单：每个域名一个 identifier
	orderURL := c.dir["newOrder"]
	order := orderResp{}
	identifiers := make([]map[string]string, 0, len(domains))
	for _, d := range domains {
		identifiers = append(identifiers, map[string]string{"type": "dns", "value": d})
	}
	data, loc, code, err := c.acmePostRetry(orderURL, map[string]any{
		"identifiers": identifiers,
	}, true)
	if err != nil {
		return "", "", fmt.Errorf("创建订单失败: %w", err)
	}
	if code < 200 || code >= 300 || loc == "" {
		return "", "", acmeError(orderURL, code, "创建订单失败", data)
	}
	if err := c.getOrder(loc, &order); err != nil {
		return "", "", err
	}

	// 2. 收集所有域名的 HTTP-01 验证
	type challenge struct {
		authzURL     string
		challengeURL string
		token        string
	}
	var challenges []challenge
	for _, azURL := range order.Authorizations {
		var az authzResp
		if err := c.getOrder(azURL, &az); err != nil {
			return "", "", err
		}
		found := false
		for i := range az.Challenges {
			if az.Challenges[i].Type == "http-01" {
				challenges = append(challenges, challenge{
					authzURL:     azURL,
					challengeURL: az.Challenges[i].URL,
					token:        az.Challenges[i].Token,
				})
				found = true
				break
			}
		}
		if !found {
			return "", "", errors.New("订单中存在没有 HTTP-01 验证的域名，请检查域名是否正确")
		}
	}
	if len(challenges) == 0 {
		return "", "", errors.New("订单中没有 HTTP-01 验证")
	}

	// 3. 启动验证服务器，同时响应所有 token
	tp, err := c.thumbprint()
	if err != nil {
		return "", "", err
	}
	keys := make(map[string]string, len(challenges))
	for _, ch := range challenges {
		keys[ch.token] = ch.token + "." + tp
	}
	stop := serveChallenges(challengePort, keys)
	defer stop()

	// 逐个提交验证
	for _, ch := range challenges {
		if _, _, _, err := c.acmePostRetry(ch.challengeURL, map[string]any{}, true); err != nil {
			return "", "", fmt.Errorf("提交域名验证失败: %w", err)
		}
	}

	// 4. 轮询每个授权的状态
	for _, ch := range challenges {
		authzURL := ch.authzURL
		if err := c.poll(5*time.Second, 60, func() (bool, error) {
			var az authzResp
			if err := c.getOrder(authzURL, &az); err != nil {
				return false, err
			}
			switch az.Status {
			case "valid":
				return true, nil
			case "invalid":
				return false, errors.New("域名验证失败（HTTP-01），请确认该域名的 80 端口公网可达且解析指向本机")
			}
			return false, nil
		}); err != nil {
			return "", "", err
		}
	}

	// 5. 生成 CSR 并 finalize
	orderKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return "", "", err
	}
	// CommonName 只放首个域名（长度限制 64），全部域名放进 SAN
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject:  pkix.Name{CommonName: primary},
		DNSNames: domains,
	}, orderKey)
	if err != nil {
		return "", "", err
	}
	_, _, code, err = c.acmePostRetry(order.Finalize, map[string]any{
		"csr": b64(csrDER),
	}, true)
	if err != nil || code >= 300 {
		return "", "", fmt.Errorf("提交 CSR 失败 (http %d): %v", code, err)
	}

	// 6. 轮询订单状态并下载证书
	if err := c.poll(3*time.Second, 60, func() (bool, error) {
		if err := c.getOrder(loc, &order); err != nil {
			return false, err
		}
		switch order.Status {
		case "valid":
			return true, nil
		case "invalid":
			return false, errors.New("订单无效")
		}
		return false, nil
	}); err != nil {
		return "", "", err
	}
	resp, err := c.http.Get(order.Certificate)
	if err != nil {
		return "", "", err
	}
	defer resp.Body.Close()
	cb, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	certPEM = string(cb)

	kb, _ := x509.MarshalECPrivateKey(orderKey)
	keyPEM = string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kb}))
	return certPEM, keyPEM, nil
}

func (c *Client) initAccount(domain, email, dirURL string) error {
	if c.dir == nil {
		resp, err := c.http.Get(dirURL)
		if err != nil {
			return fmt.Errorf("获取 ACME 目录失败: %w", err)
		}
		defer resp.Body.Close()
		var raw map[string]json.RawMessage
		if err := json.NewDecoder(resp.Body).Decode(&raw); err != nil {
			return err
		}
		c.dir = map[string]string{}
		for k, v := range raw {
			var s string
			if json.Unmarshal(v, &s) == nil {
				c.dir[k] = s
			}
		}
		if n := resp.Header.Get("Replay-Nonce"); n != "" {
			c.pushNonce(n)
		}
	}
	if c.keyID != "" {
		return nil
	}
	acc := map[string]any{"termsOfServiceAgreed": true}
	if email != "" {
		acc["contact"] = []string{"mailto:" + email}
	}
	data, loc, code, err := c.acmePostRetry(c.dir["newAccount"], acc, false)
	if err != nil {
		return fmt.Errorf("注册账号失败: %w", err)
	}
	if code < 200 || code >= 300 || loc == "" {
		return acmeError(c.dir["newAccount"], code, "注册账号失败", data)
	}
	c.keyID = loc
	return nil
}

func (c *Client) getOrder(url string, out any) error {
	data, _, code, err := c.acmePostRetry(url, nil, true)
	if err != nil {
		return err
	}
	if code < 200 || code >= 300 {
		return acmeError(url, code, "查询失败")
	}
	return json.Unmarshal(data, out)
}

func (c *Client) poll(interval time.Duration, maxTry int, fn func() (bool, error)) error {
	for i := 0; i < maxTry; i++ {
		done, err := fn()
		if err != nil {
			return err
		}
		if done {
			return nil
		}
		time.Sleep(interval)
	}
	return errors.New("等待超时")
}

func acmeError(url string, code int, prefix string, body ...[]byte) error {
	if len(body) > 0 {
		var pr problemResp
		if json.Unmarshal(body[0], &pr) == nil && pr.Detail != "" {
			return fmt.Errorf("%s (http %d): %s", prefix, code, pr.Detail)
		}
	}
	return fmt.Errorf("%s (http %d)", prefix, code)
}

// serveChallenges 启动 HTTP-01 验证服务器，可同时响应多个 token。
// keys: token -> keyAuth（token + "." + thumbprint）。
// 返回停止函数。
func serveChallenges(port int, keys map[string]string) func() {
	mux := http.NewServeMux()
	for token, keyAuth := range keys {
		ka := keyAuth
		mux.HandleFunc("/.well-known/acme-challenge/"+token, func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/plain")
			w.Write([]byte(ka))
		})
	}
	// 未命中的 token 也返回一个可读提示，便于排查
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	})
	srv := &http.Server{Addr: fmt.Sprintf(":%d", port), Handler: mux}
	go srv.ListenAndServe()
	return func() { srv.Close() }
}
