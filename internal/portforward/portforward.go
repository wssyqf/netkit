package portforward

import (
	"fmt"
	"io"
	"log"
	"net"
	"strings"
	"sync"
	"time"

	"netkit/internal/config"
	"netkit/internal/ipvisitors"
	"netkit/internal/logcenter"
	"netkit/internal/safe"
	"netkit/internal/webhook"
)

// Manager 管理所有端口转发规则的运行态，配置变化时增量启停。
type Manager struct {
	mu      sync.Mutex
	store   *config.Store
	cfgs    []config.PortForwardRule
	running map[string]*runningRule
	filter  func(ip string) bool // 全局 IP 过滤，返回 false 拒绝
}

// SetStore 注入配置存储（用于解析安全组）。
func (m *Manager) SetStore(s *config.Store) { m.store = s }

// SetGlobalFilter 设置全局 IP 过滤函数。
func (m *Manager) SetGlobalFilter(f func(ip string) bool) { m.filter = f }

type runningRule struct {
	stop    chan struct{}
	wg      sync.WaitGroup
	logs    *safe.LogRing
	listens []string
	errMsg  string
	cfg     config.PortForwardRule
	sem     chan struct{} // 并发限制信号量，nil 表示不限
	allow   func(ip string) bool
}

func NewManager() *Manager {
	return &Manager{running: map[string]*runningRule{}}
}

func (m *Manager) Logs(ruleID string) []string {
	m.mu.Lock()
	r := m.running[ruleID]
	m.mu.Unlock()
	if r == nil {
		return nil
	}
	return r.logs.Snapshot()
}

// Apply 按新配置增量调整运行中的规则：配置变化或被停用的先停，新增的再启动。
func (m *Manager) Apply(cfgs []config.PortForwardRule) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.cfgs = cfgs

	for id, r := range m.running {
		keep := false
		for _, c := range cfgs {
			if c.ID == id {
				keep = c.Enabled && !ruleChanged(r.cfg, c)
				break
			}
		}
		if !keep {
			close(r.stop)
			r.wg.Wait()
			delete(m.running, id)
		}
	}
	for _, c := range cfgs {
		if !c.Enabled {
			continue
		}
		if _, ok := m.running[c.ID]; ok {
			continue
		}
		r := &runningRule{
			stop: make(chan struct{}),
			logs: safe.NewLogRing(100),
			cfg:  c,
		}
		if c.MaxConns > 0 {
			r.sem = make(chan struct{}, c.MaxConns)
		}
		if c.GroupID != "" && m.store != nil {
			cfgSnap := m.store.Get()
			groups := safe.ResolveGroups(cfgSnap.SecurityGroups, cfgSnap.IPDB)
			if g, ok := groups[c.GroupID]; ok {
				grp := g
				r.allow = func(ip string) bool { return safe.CheckGroup(grp, ip) }
			}
		} else if c.FilterMode != "" && c.FilterMode != "none" {
			mode := c.FilterMode
			r.allow = func(ip string) bool { return safe.CheckIP(mode, nil, ip) }
		}
		m.running[c.ID] = r
		for _, ln := range buildListens(c) {
			r.wg.Add(1)
			go m.serve(r, ln)
		}
	}
}

func ruleChanged(a, b config.PortForwardRule) bool {
	return a.Proto != b.Proto || a.ListenIP != b.ListenIP || a.TargetIP != b.TargetIP ||
		fmt.Sprint(a.ListenPorts) != fmt.Sprint(b.ListenPorts) ||
		fmt.Sprint(a.TargetPorts) != fmt.Sprint(b.TargetPorts)
}

// buildListens 生成 "proto|listenIP|listenPort|targetPort" 描述串。
func buildListens(c config.PortForwardRule) []string {
	var out []string
	var protos []string
	switch strings.ToLower(c.Proto) {
	case "tcp":
		protos = []string{"tcp"}
	case "udp":
		protos = []string{"udp"}
	default:
		protos = []string{"tcp", "udp"}
	}
	for _, proto := range protos {
		for i, lp := range c.ListenPorts {
			tp := lp
			if i < len(c.TargetPorts) {
				tp = c.TargetPorts[i]
			} else if len(c.TargetPorts) > 0 {
				tp = c.TargetPorts[0]
			}
			out = append(out, fmt.Sprintf("%s|%s|%d|%d", proto, c.ListenIP, lp, tp))
		}
	}
	return out
}

func (m *Manager) fail(r *runningRule, format string, args ...any) {
	msg := fmt.Sprintf(format, args...)
	first := r.errMsg == ""
	if first {
		r.errMsg = msg
	}
	r.logs.Add(time.Now().Format("2006-01-02 15:04:05") + " [错误] " + msg)
	log.Printf("[端口转发] %s", msg)
	logcenter.Default().Add("端口转发", logcenter.LevelError, "规则[%s] %s", r.cfg.Name, msg)

	// 只在首次出错时通知，避免同一故障刷屏
	if first && r.cfg.Webhook.URL != "" {
		go webhook.NewClient().Send(r.cfg.Webhook, webhook.Payload{
			Event:  webhook.EventPF,
			Module: "端口转发",
			Target: r.cfg.Name,
			IP:     r.cfg.TargetIP,
			Result: msg,
			OK:     false,
			Extra: map[string]string{
				"listenPorts": fmt.Sprint(r.cfg.ListenPorts),
				"targetPorts": fmt.Sprint(r.cfg.TargetPorts),
				"proto":       r.cfg.Proto,
			},
		})
	}
}

func (m *Manager) serve(r *runningRule, ln string) {
	defer r.wg.Done()
	parts := strings.Split(ln, "|")
	proto, listenIP, lp, tp := parts[0], parts[1], parts[2], parts[3]
	addr := net.JoinHostPort(listenIP, lp)
	r.listens = append(r.listens, proto+"://"+addr)
	target := net.JoinHostPort(r.cfg.TargetIP, tp)

	if proto == "tcp" {
		m.serveTCP(r, addr, target)
	} else {
		m.serveUDP(r, addr, target)
	}
}

func (m *Manager) serveTCP(r *runningRule, addr, target string) {
	l, err := net.Listen("tcp", addr)
	if err != nil {
		m.fail(r, "监听失败 %s: %v", addr, err)
		return
	}
	go func() {
		<-r.stop
		l.Close()
	}()
	r.logs.Add(time.Now().Format("2006-01-02 15:04:05") + fmt.Sprintf(" [启动] %s -> %s", addr, target))
	for {
		conn, err := l.Accept()
		if err != nil {
			select {
			case <-r.stop:
				return
			default:
			}
			m.fail(r, "接受连接失败 %s: %v", addr, err)
			return
		}
		r.wg.Add(1)
		go func() {
			defer r.wg.Done()
			m.pipeTCP(r, conn, target)
		}()
	}
}

func (m *Manager) pipeTCP(r *runningRule, client net.Conn, target string) {
	defer client.Close()
	if r.allow != nil {
		if rip, _, e := net.SplitHostPort(client.RemoteAddr().String()); e == nil && !r.allow(rip) {
			r.logs.Add(time.Now().Format("2006-01-02 15:04:05") +
				fmt.Sprintf(" [拦截] 安全组拒绝 %s", rip))
			logcenter.Default().Add("端口转发", logcenter.LevelWarn, "规则[%s] 安全组拒绝 %s", r.cfg.Name, rip)
			return
		}
	}
	if r.sem != nil {
		select {
		case r.sem <- struct{}{}:
			defer func() { <-r.sem }()
		case <-time.After(3 * time.Second):
			r.logs.Add(time.Now().Format("2006-01-02 15:04:05") +
				fmt.Sprintf(" [限流] 并发连接已满(%d)，拒绝 %s", r.cfg.MaxConns, client.RemoteAddr()))
			return
		}
	}
	if m.filter != nil {
		if rip, _, err := net.SplitHostPort(client.RemoteAddr().String()); err == nil && !m.filter(rip) {
			r.logs.Add(time.Now().Format("2006-01-02 15:04:05") +
				fmt.Sprintf(" [拦截] 全局IP过滤拒绝 %s", rip))
			logcenter.Default().Add("端口转发", logcenter.LevelWarn, "规则[%s] 全局IP过滤拒绝 %s", r.cfg.Name, rip)
			return
		}
	}
	up, err := net.DialTimeout("tcp", target, 5*time.Second)
	if err != nil {
		r.logs.Add(time.Now().Format("2006-01-02 15:04:05") +
			fmt.Sprintf(" [错误] 连接后端失败 %s: %v (来自 %s)", target, err, client.RemoteAddr()))
		return
	}
	defer up.Close()
	r.logs.Add(time.Now().Format("2006-01-02 15:04:05") +
		fmt.Sprintf(" [连接] %s -> %s", client.RemoteAddr(), target))
	if host, _, e := net.SplitHostPort(client.RemoteAddr().String()); e == nil {
		ipvisitors.Default().Record(host, "端口转发")
	}

	done := make(chan struct{}, 2)
	cp := func(dst, src net.Conn) {
		io.Copy(dst, src)
		if v, ok := dst.(*net.TCPConn); ok {
			v.CloseWrite()
		}
		done <- struct{}{}
	}
	go cp(up, client)
	go cp(client, up)
	select {
	case <-done:
	case <-r.stop:
	}
	// 触发另一方向尽快退出
	client.SetDeadline(time.Now())
	up.SetDeadline(time.Now())
}

// serveUDP 面向会话的 UDP 中继：每个客户端地址对应一条到后端的 UDP 连接。
func (m *Manager) serveUDP(r *runningRule, addr, target string) {
	pc, err := net.ListenPacket("udp", addr)
	if err != nil {
		m.fail(r, "监听失败 %s: %v", addr, err)
		return
	}
	go func() {
		<-r.stop
		pc.Close()
	}()
	r.logs.Add(time.Now().Format("2006-01-02 15:04:05") + fmt.Sprintf(" [启动] %s -> %s", addr, target))

	var (
		smu  sync.Mutex
		sess = map[string]net.Conn{}
		idle = map[net.Conn]time.Time{}
		buf  = make([]byte, 65535)
	)
	// 关停时清空会话
	go func() {
		<-r.stop
		smu.Lock()
		for k, c := range sess {
			c.Close()
			delete(sess, k)
		}
		smu.Unlock()
	}()
	// 会话超时清理
	go func() {
		t := time.NewTicker(30 * time.Second)
		defer t.Stop()
		for range t.C {
			smu.Lock()
			for k, c := range sess {
				if time.Since(idle[c]) > 90*time.Second {
					c.Close()
					delete(sess, k)
					delete(idle, c)
				}
			}
			smu.Unlock()
		}
	}()

	for {
		n, cli, err := pc.ReadFrom(buf)
		if err != nil {
			select {
			case <-r.stop:
				return
			default:
			}
			m.fail(r, "读取 UDP 失败 %s: %v", addr, err)
			return
		}
		if m.filter != nil {
			if rip, _, e := net.SplitHostPort(cli.String()); e == nil && !m.filter(rip) {
				continue
			}
		}
		key := cli.String()
		smu.Lock()
		up, ok := sess[key]
		if !ok {
			var derr error
			up, derr = net.Dial("udp", target)
			if derr != nil {
				smu.Unlock()
				r.logs.Add(time.Now().Format("2006-01-02 15:04:05") +
					fmt.Sprintf(" [错误] 连接后端失败 %s: %v", target, derr))
				continue
			}
			sess[key] = up
			idle[up] = time.Now()
			go func(cli net.Addr, up net.Conn) {
				defer func() {
					smu.Lock()
					if _, ok := sess[key]; ok {
						delete(sess, key)
					}
					delete(idle, up)
					smu.Unlock()
					up.Close()
				}()
				b := make([]byte, 65535)
				for {
					n, err := up.Read(b)
					if err != nil {
						return
					}
					if _, err := pc.WriteTo(b[:n], cli); err != nil {
						return
					}
				}
			}(cli, up)
			r.logs.Add(time.Now().Format("2006-01-02 15:04:05") +
				fmt.Sprintf(" [会话] %s -> %s", cli, target))
		}
		idle[up] = time.Now()
		smu.Unlock()

		up.Write(buf[:n])
	}
}

// Status 汇总各规则运行状态，供后台展示。
func (m *Manager) Status() map[string]string {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := map[string]string{}
	for id, r := range m.running {
		st := "运行中"
		if r.errMsg != "" {
			st = "异常: " + r.errMsg
		}
		out[id] = st + " (" + strings.Join(r.listens, ", ") + ")"
	}
	return out
}

var defaultMgr = NewManager()

// Default 返回模块级单例。
func Default() *Manager { return defaultMgr }
