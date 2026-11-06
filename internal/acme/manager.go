package acme

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log"
	"strings"
	"sync"
	"time"

	"netkit/internal/config"
	"netkit/internal/dnsprovider"
	"netkit/internal/logcenter"
)

// CertManager 管理证书申请与自动续签。
type CertManager struct {
	mu      sync.Mutex
	running map[string]bool // 正在申请的证书 ID
	store   *config.Store
	client  *Client
	logs    map[string]*logRing // 每张证书独立的申请日志
}

// logRing 简单的定长环形日志。
type logRing struct {
	mu    sync.Mutex
	max   int
	lines []string
}

func newLogRing(max int) *logRing { return &logRing{max: max} }

func (r *logRing) add(line string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.lines = append(r.lines, line)
	if len(r.lines) > r.max {
		r.lines = r.lines[len(r.lines)-r.max:]
	}
}

func (r *logRing) snapshot() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]string, len(r.lines))
	copy(out, r.lines)
	return out
}

var defManager = &CertManager{
	running: map[string]bool{},
	logs:    map[string]*logRing{},
}

// Logs 返回某张证书的申请日志（时间正序）。
func (m *CertManager) Logs(id string) []string {
	m.mu.Lock()
	lr := m.logs[id]
	m.mu.Unlock()
	if lr == nil {
		return []string{}
	}
	return lr.snapshot()
}

// IsRunning 返回该证书当前是否正在申请。
func (m *CertManager) IsRunning(id string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.running[id]
}

// logFor 取（或创建）某张证书的日志缓冲。
func (m *CertManager) logFor(id string) *logRing {
	m.mu.Lock()
	defer m.mu.Unlock()
	lr := m.logs[id]
	if lr == nil {
		lr = newLogRing(200)
		m.logs[id] = lr
	}
	return lr
}

// Default 返回证书管理单例。
func Default() *CertManager { return defManager }

// SetStore 注入配置存储。
func (m *CertManager) SetStore(s *config.Store) { m.store = s }

// Apply 启动自动续签巡检。
func (m *CertManager) Apply() {
	go m.renewLoop()
}

// Request 异步申请一张证书。
func (m *CertManager) Request(id string) error {
	m.mu.Lock()
	if m.running[id] {
		m.mu.Unlock()
		return fmt.Errorf("该证书正在申请中")
	}
	if m.store == nil {
		m.mu.Unlock()
		return fmt.Errorf("管理器未初始化")
	}
	var task *config.SSLCert
	cfg := m.store.Get()
	for i := range cfg.SSLCerts {
		if cfg.SSLCerts[i].ID == id {
			task = &cfg.SSLCerts[i]
			break
		}
	}
	if task == nil {
		m.mu.Unlock()
		return fmt.Errorf("证书条目不存在")
	}
	m.running[id] = true
	m.mu.Unlock()

	go func(t config.SSLCert) {
		defer func() {
			m.mu.Lock()
			delete(m.running, t.ID)
			m.mu.Unlock()
		}()
		lr := m.logFor(t.ID)
		note := func(level, format string, args ...any) {
			msg := fmt.Sprintf(format, args...)
			lr.add(time.Now().Format("2006-01-02 15:04:05") + " [" + level + "] " + msg)
			logcenter.Default().Add("证书", level, "%s", msg)
		}

		m.setStatus(t.ID, "pending", "申请中…")
		caName := "Let's Encrypt"
		if t.Directory != "" {
			caName = t.Directory
		}
		note(logcenter.LevelInfo, "开始为 %s 申请证书（CA: %s）", t.Domain, caName)
		port := 80
		client, err := NewClient()
		if err != nil {
			m.setStatus(t.ID, "error", err.Error())
			return
		}
		// 支持多域名（逗号分隔），申请同一张 SAN 证书
		challenge := strings.ToLower(strings.TrimSpace(t.Challenge))
		if challenge == "" {
			challenge = "http-01"
		}
		domains := ParseDomains(t.Domain)
		// 只有 DNS-01 允许通配符
		if err := ValidateDomainsOpt(domains, challenge == "dns-01"); err != nil {
			m.setStatus(t.ID, "error", err.Error())
			note(logcenter.LevelError, "域名校验失败: %v", err)
			return
		}
		if len(domains) > 100 {
			m.setStatus(t.ID, "error", "单张证书最多 100 个域名")
			note(logcenter.LevelError, "域名数量超过上限（100）")
			return
		}

		var certPEM, keyPEM string
		if challenge == "dns-01" {
			// DNS-01：支持泛域名
			note(logcenter.LevelInfo, "验证方式 DNS-01，共 %d 个域名: %s（服务商 %s）",
				len(domains), strings.Join(domains, ", "), t.DNSSource)
			prov, perr := dnsprovider.New(dnsprovider.Credentials{
				Provider: t.DNSSource,
				Key:      t.DNSKey,
				Secret:   t.DNSSecret,
			})
			if perr != nil {
				m.setStatus(t.ID, "error", perr.Error())
				note(logcenter.LevelError, "初始化 DNS 服务商失败: %v", perr)
				return
			}
			logf := func(f string, a ...any) {
				note(logcenter.LevelInfo, f, a...)
			}
			// 注意：这里必须赋给函数作用域的 err（不能用 :=），否则下方
			// if err != nil 判断的是外层 err，DNS-01 失败会被静默吞掉。
			certPEM, keyPEM, err = client.ObtainDNS01(domains, t.Email, t.Directory, prov, logf)
		} else {
			note(logcenter.LevelInfo, "验证方式 HTTP-01，共 %d 个域名: %s",
				len(domains), strings.Join(domains, ", "))
			certPEM, keyPEM, err = client.ObtainMulti(domains, t.Email, port, t.Directory)
		}
		if err != nil {
			note(logcenter.LevelError, "申请失败: %v", err)
			m.setStatus(t.ID, "error", err.Error())
			return
		}
		// 二次校验：绝不把空证书标记为成功
		if strings.TrimSpace(certPEM) == "" || strings.TrimSpace(keyPEM) == "" {
			msg := "CA 返回了空证书，申请未真正完成"
			note(logcenter.LevelError, "%s", msg)
			m.setStatus(t.ID, "error", msg)
			return
		}
		notAfter := int64(0)
		for blk, rest := pem.Decode([]byte(certPEM)); blk != nil; blk, rest = pem.Decode(rest) {
			if blk.Type == "CERTIFICATE" {
				if crt, e := x509.ParseCertificate(blk.Bytes); e == nil {
					notAfter = crt.NotAfter.Unix()
					break
				}
			}
		}
		if err := m.store.Update(func(c *config.Config) {
			for i := range c.SSLCerts {
				if c.SSLCerts[i].ID == t.ID {
					c.SSLCerts[i].CertPEM = certPEM
					c.SSLCerts[i].KeyPEM = keyPEM
					c.SSLCerts[i].NotAfter = notAfter
					c.SSLCerts[i].Status = "ok"
					c.SSLCerts[i].ErrMsg = ""
				}
			}
		}); err != nil {
			m.setStatus(t.ID, "error", "保存证书失败: "+err.Error())
			return
		}
		note(logcenter.LevelInfo, "申请成功，有效期至 %s", time.Unix(notAfter, 0).Format("2006-01-02 15:04:05"))
	}(*task)
	return nil
}

func (m *CertManager) setStatus(id, status, msg string) {
	if err := m.store.Update(func(c *config.Config) {
		for i := range c.SSLCerts {
			if c.SSLCerts[i].ID == id {
				c.SSLCerts[i].Status = status
				c.SSLCerts[i].ErrMsg = msg
			}
		}
	}); err != nil {
		log.Printf("[证书] 更新状态失败: %v", err)
	}
}

func (m *CertManager) renewLoop() {
	for {
		time.Sleep(12 * time.Hour)
		if m.store == nil {
			continue
		}
		cfg := m.store.Get()
		for _, t := range cfg.SSLCerts {
			if !t.AutoRenew || t.Disabled || t.Status != "ok" {
				continue
			}
			// 剩余天数低于该项设定的提前量则续签
			advance := t.AdvanceDays
			if advance <= 0 {
				advance = 30
			}
			if t.NotAfter > 0 && t.NotAfter-time.Now().Unix() < int64(advance)*86400 {
				if err := m.Request(t.ID); err == nil {
					logcenter.Default().Add("证书", logcenter.LevelInfo, "%s 触发自动续签", t.Domain)
				}
			}
		}
	}
}
