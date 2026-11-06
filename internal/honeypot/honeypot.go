// Package honeypot 蜜罐诱捕：开放诱饵端口，捕获扫描/入侵连接的来源 IP、端口与首包载荷。
package honeypot

import (
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"netkit/internal/config"
	"netkit/internal/geoip"
	"netkit/internal/ipvisitors"
	"netkit/internal/logcenter"
	"netkit/internal/safe"
	"netkit/internal/webhook"
)

// Record 一次诱捕记录。
type Record struct {
	Time    string   `json:"time"`
	IP      string   `json:"ip"`
	Port    int      `json:"port"`
	Geo     string   `json:"geo"`     // 国家码，未知为空
	Payload string   `json:"payload"` // 首包载荷（清洗后截断）
	Remark  string   `json:"remark"`  // 端口备注
	Service string   `json:"service,omitempty"` // 服务模板（自定义为空）
	UA      string   `json:"ua,omitempty"`      // HTTP User-Agent
	Tag     string   `json:"tag,omitempty"`     // AI Agent / 扫描器
	Creds   []string `json:"creds,omitempty"`   // 捕获的凭据
}

// portStatus 单个诱饵端口的运行状态。
type portStatus struct {
	ID      string `json:"id"`
	Port    int    `json:"port"`
	Running bool   `json:"running"`
	ErrMsg  string `json:"errMsg,omitempty"`
}

type runningPort struct {
	cfg    config.HoneypotPort
	stop   chan struct{}
	wg     sync.WaitGroup
	errMsg string
}

// Manager 蜜罐管理器。
type Manager struct {
	mu       sync.Mutex
	store    *config.Store
	enabled  bool
	running  map[string]*runningPort // key: HoneypotPort.ID
	records  []Record
	ring     *safe.LogRing
	reserved map[int]string // 外部预留端口：端口 -> 归属描述（管理端口/端口转发/反代）

	// 通知节流：IP -> 上次通知时间（同 IP 5 分钟内只通知一次）
	notifyMu sync.Mutex
	notified map[string]time.Time
}

var defaultMgr = newManager()

// Default 返回蜜罐单例。
func Default() *Manager { return defaultMgr }

// SetStore 注入配置存储（用于读取全局通知配置）。
func (m *Manager) SetStore(s *config.Store) {
	m.mu.Lock()
	m.store = s
	m.mu.Unlock()
}

func newManager() *Manager {
	return &Manager{
		running: map[string]*runningPort{},
		ring:    safe.NewLogRing(500),
		notified: map[string]time.Time{},
	}
}

// Apply 应用新配置：先停掉已移除/变更的端口，再启动新增端口。
func (m *Manager) Apply(cfg config.HoneypotConfig) {
	m.mu.Lock()
	m.enabled = cfg.Enabled
	ports := cfg.Ports

	// 停掉不再保留的：先摘出再解锁等待，避免持锁 Wait 与 serve 里的加锁互相死锁
	var toStop []*runningPort
	for id, rp := range m.running {
		keep := false
		for _, p := range ports {
			if p.ID == id {
				keep = cfg.Enabled && p.Enabled && !portChanged(rp.cfg, p)
				break
			}
		}
		if !keep {
			toStop = append(toStop, rp)
			delete(m.running, id)
		}
	}
	m.mu.Unlock()
	for _, rp := range toStop {
		close(rp.stop)
		rp.wg.Wait()
	}
	if !cfg.Enabled {
		return
	}
	// 启动新增的（端口冲突预检）
	m.mu.Lock()
	busy := m.busyPortsLocked(ports)
	// 蜜罐列表内部端口重复检查（只报第二个及以后）
	seenPort := map[int]string{}
	for _, p := range ports {
		if p.Port > 0 {
			if first, dup := seenPort[p.Port]; dup {
				busy[p.Port] = "蜜罐端口[" + first + "]"
			} else {
				seenPort[p.Port] = p.Remark
			}
		}
	}
	for _, p := range ports {
		if !p.Enabled {
			continue
		}
		if _, ok := m.running[p.ID]; ok {
			continue
		}
		if p.Port <= 0 || p.Port > 65535 {
			m.logErr(p, "端口号无效: "+strconv.Itoa(p.Port))
			continue
		}
		if name, conflict := busy[p.Port]; conflict {
			// 仅当归属不是"自己这条配置"时才跳过
			m.logErr(p, fmt.Sprintf("端口 %d 与%s冲突，已跳过", p.Port, name))
			continue
		}
		rp := &runningPort{cfg: p, stop: make(chan struct{})}
		m.running[p.ID] = rp
		rp.wg.Add(1)
		go m.serve(rp)
	}
	m.mu.Unlock()
}

func portChanged(a, b config.HoneypotPort) bool {
	return a.ListenIP != b.ListenIP || a.Port != b.Port || a.Banner != b.Banner || a.Remark != b.Remark || a.Service != b.Service
}

// busyPortsLocked 收集已被占用的端口（预留端口）及归属描述；
// 蜜罐列表内部的端口重复单独检查（两个诱饵配置同一端口才冲突）。
func (m *Manager) busyPortsLocked(ports []config.HoneypotPort) map[int]string {
	out := map[int]string{}
	for port, name := range m.reserved {
		out[port] = name
	}
	return out
}

// SetReservedPorts 由外部注入预留端口（管理端口/端口转发/反代），在 Apply 前调用。
func (m *Manager) SetReservedPorts(reserved map[int]string) {
	m.mu.Lock()
	m.reserved = reserved
	m.mu.Unlock()
}

// serve 启动单个诱饵端口的监听循环。
func (m *Manager) serve(rp *runningPort) {
	defer rp.wg.Done()
	ip := rp.cfg.ListenIP
	if ip == "" {
		ip = "0.0.0.0"
	}
	addr := net.JoinHostPort(ip, strconv.Itoa(rp.cfg.Port))
	l, err := net.Listen("tcp", addr)
	if err != nil {
		m.mu.Lock()
		rp.errMsg = err.Error()
		m.mu.Unlock()
		m.logErr(rp.cfg, fmt.Sprintf("监听失败 %s: %v", addr, err))
		return
	}
	go func() {
		<-rp.stop
		l.Close()
	}()
	m.logLine(fmt.Sprintf("[启动] 蜜罐端口 %s 已监听", addr))
	logcenter.Default().Add("蜜罐", logcenter.LevelInfo, "诱饵端口 %d 已监听（%s）", rp.cfg.Port, addr)

	for {
		conn, err := l.Accept()
		if err != nil {
			select {
			case <-rp.stop:
				return
			default:
			}
			// 监听已关闭或系统错误，记录后退出本端口
			m.mu.Lock()
			rp.errMsg = err.Error()
			m.mu.Unlock()
			m.logErr(rp.cfg, fmt.Sprintf("接受连接失败 %s: %v", addr, err))
			return
		}
		rp.wg.Add(1)
		go func() {
			defer rp.wg.Done()
			m.handleConn(rp, conn)
		}()
	}
}

// handleConn 按服务模板执行一次会话：读取/诱导交互、捕获凭据与请求特征并记录告警。
func (m *Manager) handleConn(rp *runningPort, conn net.Conn) {
	defer conn.Close()
	remote := conn.RemoteAddr().String()
	ip := remote
	if h, _, err := net.SplitHostPort(remote); err == nil {
		ip = h
	}

	svc := rp.cfg.Service
	if svc == "" {
		svc = "custom"
	}
	_ = conn.SetDeadline(time.Now().Add(15 * time.Second))
	res := runSession(conn, svc, rp.cfg.Banner)

	label := ""
	if svc != "custom" {
		label = tmpl(svc).Name
	}
	geo := geoip.Country(ip)
	rec := Record{
		Time: time.Now().Format("2006-01-02 15:04:05"),
		IP:   ip, Port: rp.cfg.Port, Geo: geo,
		Payload: res.Payload, Remark: rp.cfg.Remark,
		Service: label, UA: res.UA, Tag: res.Tag, Creds: res.Creds,
	}
	m.mu.Lock()
	m.records = append(m.records, rec)
	if len(m.records) > 2000 {
		m.records = m.records[len(m.records)-2000:]
	}
	m.mu.Unlock()

	line := fmt.Sprintf("[捕获] %s 访问端口%d", ip, rp.cfg.Port)
	if label != "" {
		line += " [" + label + "]"
	}
	if res.Tag != "" {
		line += " 标签=" + res.Tag
	}
	for _, c := range res.Creds {
		line += " 凭据=" + c
	}
	line += fmt.Sprintf(" 首包=%q", res.Payload)
	if geo != "" {
		line += " 国家=" + geo
	}
	m.logLine(line)

	lcMsg := fmt.Sprintf("捕获连接 %s 访问诱饵端口 %d（国家=%s）", ip, rp.cfg.Port, geoOrUnknown(geo))
	if res.Tag != "" {
		lcMsg += " 标签=" + res.Tag
	}
	if len(res.Creds) > 0 {
		lcMsg += " 捕获凭据 " + strings.Join(res.Creds, "；")
	}
	lcMsg += " 首包: " + res.Payload
	logcenter.Default().Add("蜜罐", logcenter.LevelWarn, "%s", lcMsg)

	ipvisitors.Default().Record(ip, "蜜罐")
	m.notify(rp, rec)
}

// notify 全局 Webhook 通知（凭据/标签优先），同一 IP 5 分钟节流。
func (m *Manager) notify(rp *runningPort, rec Record) {
	m.notifyMu.Lock()
	if t, ok := m.notified[rec.IP]; ok && time.Since(t) < 5*time.Minute {
		m.notifyMu.Unlock()
		return
	}
	m.notified[rec.IP] = time.Now()
	// 顺带清理过期条目，防 map 无限增长
	if len(m.notified) > 4096 {
		for k, t := range m.notified {
			if time.Since(t) > 5*time.Minute {
				delete(m.notified, k)
			}
		}
	}
	m.notifyMu.Unlock()

	result := fmt.Sprintf("捕获连接，首包: %s", rec.Payload)
	if len(rec.Creds) > 0 {
		result = "捕获凭据 " + strings.Join(rec.Creds, "；") + "（首包: " + rec.Payload + "）"
	}
	if rec.Tag != "" {
		result = "[" + rec.Tag + "] " + result
	}
	go webhook.NewClient().Send(m.globalWebhook(), webhook.Payload{
		Event:  webhook.EventHoneypot,
		Module: "蜜罐",
		Target: strings.TrimSpace(fmt.Sprintf("诱饵端口 %d %s", rec.Port, rec.Service)),
		IP:     rec.IP,
		Result: result,
		OK:     false,
		Extra: map[string]string{
			"geo":     geoOrUnknown(rec.Geo),
			"port":    strconv.Itoa(rec.Port),
			"service": rec.Service,
			"tag":     rec.Tag,
			"ua":      rec.UA,
		},
	})
}

// globalWebhook 读取全局通知配置快照。
func (m *Manager) globalWebhook() config.Webhook {
	m.mu.Lock()
	s := m.store
	m.mu.Unlock()
	if s == nil {
		return config.Webhook{}
	}
	return s.Get().GlobalWebhook
}

// Status 返回各端口运行状态。
func (m *Manager) Status() []portStatus {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]portStatus, 0, len(m.running))
	for id, rp := range m.running {
		out = append(out, portStatus{ID: id, Port: rp.cfg.Port, Running: true, ErrMsg: rp.errMsg})
	}
	return out
}

// Records 返回诱捕记录（最近在前）。
func (m *Manager) Records(limit int) []Record {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := []Record{}
	for i := len(m.records) - 1; i >= 0 && len(out) < limit; i-- {
		out = append(out, m.records[i])
	}
	return out
}

// Ring 返回事件日志环快照。
func (m *Manager) Ring() []string { return m.ring.Snapshot() }

// Clear 清空诱捕记录与日志环。
func (m *Manager) Clear() {
	m.mu.Lock()
	m.records = nil
	m.mu.Unlock()
	m.ring.Clear()
}

func (m *Manager) logLine(s string) {
	m.ring.Add(time.Now().Format("2006-01-02 15:04:05") + " " + s)
}

func (m *Manager) logErr(p config.HoneypotPort, msg string) {
	m.logLine("[错误] " + msg)
	logcenter.Default().Add("蜜罐", logcenter.LevelError, "诱饵端口%d: %s", p.Port, msg)
}

// cleanPayload 把首包载荷转成可打印文本：不可打印字节替换为 '.'，超长截断。
func cleanPayload(b []byte) string {
	var sb strings.Builder
	for _, c := range b {
		if c == '\r' || c == '\n' || c == '\t' {
			sb.WriteByte(' ')
			continue
		}
		if c < 0x20 || c >= 0x7f {
			sb.WriteByte('.')
			continue
		}
		sb.WriteByte(c)
	}
	s := sb.String()
	if len(s) > 200 {
		s = s[:200] + "…"
	}
	return s
}

func geoOrUnknown(cc string) string {
	if cc == "" {
		return "未知"
	}
	return cc
}
