package reverseproxy

import (
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"sync"

	"netkit/internal/config"
	"netkit/internal/logcenter"
	"netkit/internal/safe"
	"netkit/internal/waf"
)

// runningRule 单条 Web 规则的运行上下文，被 handler 闭包引用。
type runningRule struct {
	ruleID   string
	logs     *safe.LogRing
	stats    *Stats
	subStats map[string]*Stats        // ruleID|subID -> 子规则统计
	subLogs  map[string]*safe.LogRing // ruleID|subID -> 子规则日志
	pools    map[string]*pool
	filter   func(ip string) bool
	groups   map[string]safe.GroupInfo // Apply 时解析一次的安全组
}

// addLog 同时写入规则日志与命中子规则的独立日志环（subID 为空表示未命中子规则，
// 例如默认后端或全局过滤命中前的日志，只进规则环）。
func (r *runningRule) addLog(subID, msg string) {
	r.logs.Add(msg)
	if subID == "" {
		return
	}
	if ring := r.subLogs[r.ruleID+"|"+subID]; ring != nil {
		ring.Add(msg)
	}
}

// poolKey 后端池键：规则ID|子规则ID（默认池子规则ID为 __default__）。
func (r *runningRule) poolKey(subID string) string {
	if subID == "" {
		subID = "__default__"
	}
	return r.ruleID + "|" + subID
}

// Manager Web 服务规则管理器（单例，配置热生效）。
type Manager struct {
	mu       sync.Mutex
	store    *config.Store
	closers  map[string][]func() error // ruleID -> 关闭监听/服务
	pools    map[string]*pool          // ruleID|subID -> 后端池
	hcStops  map[string]func()         // ruleID|subID -> 停止健康检查
	logs     map[string]*safe.LogRing  // ruleID -> 访问日志（跨热更新保留）
	stats    map[string]*Stats         // ruleID -> 流量统计（跨热更新保留）
	subLogs  map[string]*safe.LogRing  // ruleID|subID -> 子规则独立日志（跨热更新保留）
	subStats map[string]*Stats         // ruleID|subID -> 子规则独立统计（跨热更新保留）
	status   map[string]string         // ruleID -> 运行状态文本
	filter   func(ip string) bool      // 全局 IP 过滤
}

// NewManager 创建管理器。
func NewManager() *Manager {
	return &Manager{
		closers:  map[string][]func() error{},
		pools:    map[string]*pool{},
		hcStops:  map[string]func(){},
		logs:     map[string]*safe.LogRing{},
		stats:    map[string]*Stats{},
		subLogs:  map[string]*safe.LogRing{},
		subStats: map[string]*Stats{},
		status:   map[string]string{},
	}
}

// Default 返回单例。
var defaultManager = NewManager()

func Default() *Manager { return defaultManager }

// SetStore 注入配置存储（读取证书库 / 安全组）。
func (m *Manager) SetStore(s *config.Store) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.store = s
}

// SetGlobalFilter 注入全局 IP 过滤器。
func (m *Manager) SetGlobalFilter(f func(ip string) bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.filter = f
}

// Apply 热应用全部 Web 规则：停旧 → 建池 → 组 handler → 监听。
func (m *Manager) Apply(cfgs []config.WebRule) {
	m.mu.Lock()
	defer m.mu.Unlock()

	// 停止旧服务与健康检查
	for _, fns := range m.closers {
		for _, f := range fns {
			f()
		}
	}
	for _, stop := range m.hcStops {
		stop()
	}
	m.closers = map[string][]func() error{}
	m.hcStops = map[string]func(){}
	m.pools = map[string]*pool{}
	m.status = map[string]string{}

	// 清理已删除规则的统计与日志
	live := map[string]bool{}
	for _, c := range cfgs {
		if c.ID != "" {
			live[c.ID] = true
		}
	}
	for id := range m.stats {
		if !live[id] {
			delete(m.stats, id)
		}
	}
	for id := range m.logs {
		if !live[id] {
			delete(m.logs, id)
		}
	}
	// 子规则级统计/日志：规则被删或子规则被删都清理
	liveSub := map[string]bool{}
	for _, c := range cfgs {
		for _, sr := range c.SubRules {
			if c.ID != "" && sr.ID != "" {
				liveSub[c.ID+"|"+sr.ID] = true
			}
		}
	}
	for id := range m.subStats {
		if !liveSub[id] {
			delete(m.subStats, id)
		}
	}
	for id := range m.subLogs {
		if !liveSub[id] {
			delete(m.subLogs, id)
		}
	}

	// 安全组解析一次，供所有规则的子规则引用
	var groups map[string]safe.GroupInfo
	if m.store != nil {
		snap := m.store.Get()
		groups = safe.ResolveGroups(snap.SecurityGroups, snap.IPDB)
	}

	for _, c := range cfgs {
		if c.ID == "" {
			continue
		}
		if !c.Enabled || c.Port <= 0 {
			delete(m.stats, c.ID)
			delete(m.logs, c.ID)
			continue
		}
		m.startRule(c, groups)
	}
}

// startRule 为一条规则建池、组 handler 并启动监听。
func (m *Manager) startRule(c config.WebRule, groups map[string]safe.GroupInfo) {
	lc := logcenter.Default()

	if m.stats[c.ID] == nil {
		m.stats[c.ID] = NewStats()
	}
	if m.logs[c.ID] == nil {
		m.logs[c.ID] = safe.NewLogRing(200)
	}

	// 子规则后端池 + 主动健康检查
	for i := range c.SubRules {
		sr := &c.SubRules[i]
		key := c.ID + "|" + sr.ID
		p := newPool(sr.Backends, sr.Weights, sr.LB.Policy, sr.LB.Sticky, sr.LB.MaxActive)
		m.pools[key] = p
		if m.subStats[key] == nil {
			m.subStats[key] = NewStats()
		}
		if m.subLogs[key] == nil {
			m.subLogs[key] = safe.NewLogRing(200)
		}
		if hc := hcFrom(sr.Health); hc.enabled {
			stop := make(chan struct{})
			p.startHealthCheck(hc, stop)
			m.hcStops[key] = func() { close(stop) }
		}
	}
	// 默认后端池（未匹配任何子规则时兜底）
	if len(c.DefaultBackends) > 0 {
		key := c.ID + "|__default__"
		p := newPool(c.DefaultBackends, nil, c.DefaultLB.Policy, c.DefaultLB.Sticky, c.DefaultLB.MaxActive)
		m.pools[key] = p
		if hc := hcFrom(c.DefaultHealth); hc.enabled {
			stop := make(chan struct{})
			p.startHealthCheck(hc, stop)
			m.hcStops[key] = func() { close(stop) }
		}
	}

	rl := &runningRule{
		ruleID:   c.ID,
		logs:     m.logs[c.ID],
		stats:    m.stats[c.ID],
		subStats: m.subStats,
		subLogs:  m.subLogs,
		pools:    m.pools,
		filter:   m.filter,
		groups:   groups,
	}
	var h http.Handler = m.buildHandler(rl, c)
	if c.WAFEnabled {
		if wrapped, err := waf.Default().WrapHandler(h); err == nil {
			h = wrapped
		} else {
			lc.Add("Web服务", logcenter.LevelWarn, "规则[%s] WAF包装失败: %v", c.Name, err)
		}
	}

	addr := net.JoinHostPort(c.ListenIP, strconv.Itoa(c.Port))
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		m.status[c.ID] = "异常: " + err.Error()
		lc.Add("Web服务", logcenter.LevelError, "规则[%s] 监听失败 %s: %v", c.Name, addr, err)
		return
	}
	m.status[c.ID] = "运行中"

	cert := m.loadCert(c)
	if cert == nil {
		// 纯明文 HTTP
		srv := &http.Server{Handler: h}
		m.closers[c.ID] = []func() error{func() error { return srv.Close() }}
		go serveQuiet(srv, ln, c, m)
		return
	}

	// 证书每次握手时从证书库实时读取：ACME 续签更新后立即生效，无需重启监听。
	// （c 是 Apply 传入的值副本，闭包持副本安全；loadCert 内部每次从 store 取最新 PEM）
	rule := c
	tlsCfg := &tls.Config{
		GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
			kp := m.loadCert(rule)
			if kp == nil {
				return nil, fmt.Errorf("规则[%s] 暂无可用证书", rule.Name)
			}
			return kp, nil
		},
	}
	if c.SamePortTLS {
		// 同端口：按首字节嗅探分流 HTTP / HTTPS
		sameLn := &samePortListener{Listener: ln, tlsCfg: tlsCfg}
		plainCh, tlsCh := sameLn.split()
		plainSrv := &http.Server{Handler: h}
		tlsSrv := &http.Server{Handler: h}
		m.closers[c.ID] = []func() error{
			// 必须先关底层监听：split 转发 goroutine 只有在 Accept 出错后
			// 才会关闭 plain/tls 通道，两个 Serve 循环才能退出。若先调
			// plainSrv.Close()，其内部 listenerGroup.Wait() 会永远等下去
			// （oneShotListener.Close 是空操作），整个 Apply 持锁死锁。
			func() error { return ln.Close() },
			func() error { return plainSrv.Close() },
			func() error { return tlsSrv.Close() },
		}
		go serveQuiet(plainSrv, &oneShotListener{addr: addr, ch: plainCh}, c, m)
		go serveQuiet(tlsSrv, tls.NewListener(&oneShotListener{addr: addr, ch: tlsCh}, tlsCfg), c, m)
		return
	}

	// 纯 HTTPS 监听
	tlsSrv := &http.Server{Handler: h}
	m.closers[c.ID] = []func() error{func() error { return tlsSrv.Close() }}
	go serveQuiet(tlsSrv, tls.NewListener(ln, tlsCfg), c, m)
}

// serveQuiet 启动服务，非正常退出时把异常写入状态与日志。
func serveQuiet(srv *http.Server, ln net.Listener, c config.WebRule, m *Manager) {
	if err := srv.Serve(ln); err != nil &&
		!errors.Is(err, http.ErrServerClosed) && err != io.EOF {
		m.mu.Lock()
		m.status[c.ID] = "异常: " + err.Error()
		m.mu.Unlock()
		logcenter.Default().Add("Web服务", logcenter.LevelError,
			"规则[%s] 服务退出: %v", c.Name, err)
	}
}

// loadCert 加载规则使用的证书：优先证书库（CertID），其次证书/私钥文件路径。
func (m *Manager) loadCert(c config.WebRule) *tls.Certificate {
	lc := logcenter.Default()
	if c.CertID != "" && m.store != nil {
		snap := m.store.Get()
		for _, sc := range snap.SSLCerts {
			if sc.ID == c.CertID && sc.CertPEM != "" && !sc.Disabled {
				kp, err := tls.X509KeyPair([]byte(sc.CertPEM), []byte(sc.KeyPEM))
				if err != nil {
					lc.Add("Web服务", logcenter.LevelError, "规则[%s] 证书库证书解析失败: %v", c.Name, err)
					break
				}
				return &kp
			}
		}
	}
	if c.TLSCertFile != "" && c.TLSKeyFile != "" {
		kp, err := tls.LoadX509KeyPair(c.TLSCertFile, c.TLSKeyFile)
		if err != nil {
			lc.Add("Web服务", logcenter.LevelError, "规则[%s] 证书文件加载失败 %s: %v", c.Name, c.TLSCertFile, err)
			return nil
		}
		return &kp
	}
	return nil
}

// Status 返回各规则的运行状态（ruleID -> 文本）。
func (m *Manager) Status() map[string]string {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make(map[string]string, len(m.status))
	for k, v := range m.status {
		out[k] = v
	}
	return out
}

// HealthDetail 返回健康状态：ruleID -> 子规则ID -> 后端 -> 状态文本。
func (m *Manager) HealthDetail() map[string]map[string]map[string]string {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := map[string]map[string]map[string]string{}
	for key, p := range m.pools {
		ruleID, subID, ok := splitPoolKey(key)
		if !ok {
			continue
		}
		if out[ruleID] == nil {
			out[ruleID] = map[string]map[string]string{}
		}
		out[ruleID][subID] = p.snapshot()
	}
	return out
}

// splitPoolKey 拆分 "ruleID|subID" 形式的池键。
func splitPoolKey(key string) (ruleID, subID string, ok bool) {
	for i := 0; i < len(key); i++ {
		if key[i] == '|' {
			return key[:i], key[i+1:], true
		}
	}
	return "", "", false
}

// Logs 返回指定规则的访问日志快照；sub 非空时返回该子规则的独立日志环。
func (m *Manager) Logs(id, sub string) []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	if sub != "" {
		if r := m.subLogs[id+"|"+sub]; r != nil {
			return r.Snapshot()
		}
		return nil
	}
	if r := m.logs[id]; r != nil {
		return r.Snapshot()
	}
	return nil
}

// StatsOf 返回指定规则的统计快照；sub 非空时返回该子规则的独立统计。
// 规则/子规则不存在时 ok=false。
func (m *Manager) StatsOf(id, sub string, topN int) (StatsSnapshot, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if sub != "" {
		s := m.subStats[id+"|"+sub]
		if s == nil {
			return StatsSnapshot{}, false
		}
		return s.Snapshot(topN), true
	}
	s := m.stats[id]
	if s == nil {
		return StatsSnapshot{}, false
	}
	return s.Snapshot(topN), true
}

// ResetStats 清零指定规则的统计（sub 非空时只清零该子规则）；不存在时返回 false。
func (m *Manager) ResetStats(id, sub string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	if sub != "" {
		s := m.subStats[id+"|"+sub]
		if s == nil {
			return false
		}
		s.Reset()
		return true
	}
	s := m.stats[id]
	if s == nil {
		return false
	}
	s.Reset()
	return true
}

// AllStats 返回全部规则的统计快照（ruleID -> 快照）。
func (m *Manager) AllStats(topN int) map[string]StatsSnapshot {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make(map[string]StatsSnapshot, len(m.stats))
	for id, s := range m.stats {
		out[id] = s.Snapshot(topN)
	}
	return out
}
