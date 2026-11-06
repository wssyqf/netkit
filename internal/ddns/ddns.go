package ddns

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os/exec"
	"runtime"
	"strings"
	"sync"
	"time"

	"netkit/internal/config"
	"netkit/internal/logcenter"
	"netkit/internal/safe"
	"netkit/internal/webhook"
)

// Manager 管理全部 DDNS 任务。
type Manager struct {
	mu      sync.Mutex
	running map[string]*runningTask
	client  *http.Client
}

type runningTask struct {
	stop          chan struct{}
	done          chan struct{}
	task          config.DDNSTask
	lastMsg       string
	lastOK        bool
	lastTime      string
	lastV6Skipped bool
	lastIP        string // 本次同步解析到的公网 IP
	lastWebhook   string
	prevRunIP4    string // 上一次同步使用的 IPv4（Webhook 仅在 IP 变动时发送）
	prevRunIP6    string // 上一次同步使用的 IPv6
	lastFailMsg   string // 上次已推送提醒的失败内容（同一失败只推一次）
	round         int           // 已执行轮数（cacheTimes 每 N 轮与服务商比对）
	comparedIP4   string        // 上次真正与服务商比对时使用的 IPv4
	comparedIP6   string        // 上次真正与服务商比对时使用的 IPv6
	logs          *safe.LogRing // 每次同步的详细记录
}

func NewManager() *Manager {
	return &Manager{
		running: map[string]*runningTask{},
		client:  &http.Client{Timeout: 15 * time.Second},
	}
}

// lastIPOf 返回本次同步使用的 IP。
func (m *Manager) lastIPOf(rt *runningTask) string {
	return rt.lastIP
}

// Logs 返回指定任务最近的同步记录（时间正序）。
func (m *Manager) Logs(taskID string) []string {
	m.mu.Lock()
	rt := m.running[taskID]
	m.mu.Unlock()
	if rt == nil {
		return nil
	}
	return rt.logs.Snapshot()
}

func (m *Manager) Apply(cfgs []config.DDNSTask) {
	m.mu.Lock()
	defer m.mu.Unlock()

	for id, rt := range m.running {
		keep := false
		for _, c := range cfgs {
			if c.ID == id {
				keep = c.Enabled && !sameTask(rt.task, c)
				break
			}
		}
		if !keep {
			close(rt.stop)
			<-rt.done
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
		rt := &runningTask{
			stop: make(chan struct{}), done: make(chan struct{}),
			task: c, logs: safe.NewLogRing(200),
		}
		m.running[c.ID] = rt
		go m.loop(rt)
	}
}

func sameTask(a, b config.DDNSTask) bool {
	return fmt.Sprint(a) == fmt.Sprint(b)
}

func (m *Manager) loop(rt *runningTask) {
	defer close(rt.done)
	interval := rt.task.IntervalSec
	if interval < 60 {
		interval = 60
	}
	m.runOnce(rt)
	t := time.NewTicker(time.Duration(interval) * time.Second)
	defer t.Stop()
	for {
		select {
		case <-rt.stop:
			return
		case <-t.C:
			m.runOnce(rt)
		}
	}
}

func (m *Manager) runOnce(rt *runningTask) {
	t := rt.task
	rt.round++
	msgs := []string{}
	ok := true

	// 每轮只取一次公网 IP：接口 / 网卡 / 指令三种来源在 getPublicIP 内分派
	var ip4, ip6 string
	var err4, err6 error
	if t.IPv4 {
		ip4, err4 = m.getPublicIP(false, t)
	}
	if t.IPv6 {
		ip6, err6 = m.getPublicIP(true, t)
	}
	switch {
	case ip4 != "":
		rt.lastIP = ip4
	case ip6 != "":
		rt.lastIP = ip6
	}

	// syncFamily 同步一个地址族的全部域名，返回该族结果（成功/失败/未改变）供 Webhook 使用
	syncFamily := func(v6 bool) string {
		tag := "IPv4"
		rtype, ip, err := "A", ip4, err4
		compared := &rt.comparedIP4
		if v6 {
			tag, rtype, ip, err = "IPv6", "AAAA", ip6, err6
			compared = &rt.comparedIP6
		}
		if err != nil {
			if errors.Is(err, errNoIPv6) {
				// 本机确实没有 IPv6 出口：这是正常情况，标记为跳过而非失败
				for _, domain := range t.Domains {
					msgs = append(msgs, fmt.Sprintf("%s %s 已跳过（本机无 IPv6 出口）", tag, domain))
				}
				return "未改变"
			}
			ok = false
			msgs = append(msgs, fmt.Sprintf("%s 获取公网IP失败: %v", tag, err))
			return "失败"
		}
		// cacheTimes：IP 未变且未到比对轮次时跳过服务商调用，避免触发接口限流
		if t.CacheTimes > 0 && ip == *compared && rt.round%t.CacheTimes != 0 {
			msgs = append(msgs, fmt.Sprintf("%s 未改变 (%s)，第 %d/%d 轮跳过服务商比对", tag, ip, rt.round, t.CacheTimes))
			return "未改变"
		}
		failed := 0
		for _, domain := range t.Domains {
			msg, e := m.dispatch(domain, rtype, ip, t)
			if e != nil {
				ok = false
				failed++
				msgs = append(msgs, fmt.Sprintf("%s %s 失败: %v", tag, domain, e))
			} else {
				msgs = append(msgs, fmt.Sprintf("%s %s %s", tag, domain, msg))
			}
		}
		if failed == 0 {
			*compared = ip // 记录本次真正与服务商比对过的 IP
		}
		if failed > 0 {
			return "失败"
		}
		return "成功"
	}

	v4Result, v6Result := "", ""
	v4Domains, v6Domains := t.Domains, t.Domains
	if t.IPv4 {
		v4Result = syncFamily(false)
	}
	if t.IPv6 {
		v6Result = syncFamily(true)
	}
	// 先把本次结果定稿，Webhook 才能拿到完整的 #{result}
	// （旧实现先发通知再赋值，导致 result 恒为空）
	rt.lastTime = time.Now().Format("2006-01-02 15:04:05")
	rt.lastOK = ok
	rt.lastV6Skipped = strings.Contains(strings.Join(msgs, "；"), "已跳过（本机无 IPv6 出口）")
	resultText := strings.Join(msgs, "；")

	// Webhook 触发条件（避免 IP 不变时每分钟推送一条"无需更新"刷屏）：
	//  1. IP 相比上一次同步发生变动（首次同步视为变动）
	//  2. 出现新的失败——同一失败原因只提醒一次，恢复成功后重置，下次失败重新提醒
	ipChanged := (ip4 != "" && ip4 != rt.prevRunIP4) || (ip6 != "" && ip6 != rt.prevRunIP6)
	if ip4 != "" {
		rt.prevRunIP4 = ip4
	}
	if ip6 != "" {
		rt.prevRunIP6 = ip6
	}
	failLines := []string{}
	for _, line := range msgs {
		if strings.Contains(line, "失败") {
			failLines = append(failLines, line)
		}
	}
	failText := strings.Join(failLines, "；")
	if ok {
		rt.lastFailMsg = "" // 已恢复：重置失败提醒去重状态
	}
	failNew := !ok && failText != "" && failText != rt.lastFailMsg
	sendWH := ipChanged || failNew
	if sendWH && !ok {
		rt.lastFailMsg = failText
	}

	// 同步完成后触发 Webhook（变量对齐 ddns-go：#{ipv4Addr} #{ipv4Result} #{ipv4Domains} #{ipv6*}）
	if rt.task.Webhook.URL != "" {
		if !sendWH {
			rt.lastWebhook = "IP 未变化且无新失败，已跳过通知"
		} else {
			ip := m.lastIPOf(rt)
			res := webhook.NewClient().Send(rt.task.Webhook, webhook.Payload{
				Event:  webhook.EventDDNS,
				Module: "动态域名",
				Target: strings.Join(rt.task.Domains, ","),
				IP:     ip,
				Result: resultText,
				OK:     ok,
				Extra: map[string]string{
					"provider":    rt.task.Provider,
					"domains":     strings.Join(rt.task.Domains, ","),
					"ipv4Addr":    ip4,
					"ipv4Result":  v4Result,
					"ipv4Domains": strings.Join(v4Domains, ","),
					"ipv6Addr":    ip6,
					"ipv6Result":  v6Result,
					"ipv6Domains": strings.Join(v6Domains, ","),
				},
			})
			if res.OK {
				if res.Attempts > 1 {
					msgs = append(msgs, "Webhook "+res.Message)
				}
			} else {
				msgs = append(msgs, "Webhook 失败: "+res.Message)
			}
			rt.lastWebhook = res.Message
		}
	}

	rt.lastMsg = strings.Join(msgs, "；")
	// 写入本任务的同步明细，供"查看记录"展示
	tag := "成功"
	if !ok {
		tag = "失败"
	}
	rt.logs.Add(rt.lastTime + " [" + tag + "] " + rt.lastMsg)
	level := logcenter.LevelInfo
	if !ok {
		level = logcenter.LevelError
		log.Printf("[DDNS] %s: %s", rt.task.Name, rt.lastMsg)
	}
	logcenter.Default().Add("动态域名", level, "任务[%s] %s", rt.task.Name, rt.lastMsg)
}

// TaskStatus 供后台展示。
func (m *Manager) Status() map[string]string {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := map[string]string{}
	for id, rt := range m.running {
		st := "未知"
		switch {
		case rt.lastMsg == "":
			st = "等待首次同步"
		case rt.lastOK && rt.lastV6Skipped:
			st = "正常（IPv6 已跳过）"
		case rt.lastOK:
			st = "正常"
		default:
			st = "异常"
		}
		out[id] = fmt.Sprintf("%s | 最近同步 %s | %s", st, rt.lastTime, rt.lastMsg)
	}
	return out
}

// ---- 公网 IP 获取 ----

// errNoIPv6 表示本机无 IPv6 出口，属于"跳过"而非"失败"。
var errNoIPv6 = errors.New("本机无可用 IPv6 出口")

// shortHost 取 URL 的主机名，用于精简错误提示。
func shortHost(u string) string {
	if pu, err := url.Parse(u); err == nil && pu.Host != "" {
		return pu.Host
	}
	return u
}

// truncate 截断过长字符串，避免日志被污染。
func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

// isPrivateIP 判断是否为内网/保留地址。
func isPrivateIP(s string) bool {
	ip := net.ParseIP(strings.TrimSpace(s))
	if ip == nil {
		return true // 解析不了也当作不可用
	}
	return ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsUnspecified()
}

// v6Available 探测本机是否具备可用的 IPv6 出口。
// 没有全局 IPv6 地址或默认路由时，IPv6 同步应跳过而非报错。
var (
	v6Checked bool
	v6Usable  bool
	v6CheckMu sync.Mutex
)

func v6Available() bool {
	v6CheckMu.Lock()
	defer v6CheckMu.Unlock()
	if v6Checked {
		return v6Usable
	}
	v6Checked = true
	// 判断依据：本机是否拥有全局 IPv6 地址（2000::/3）。
	// 不要用"能否连某个境外 IPv6 地址"来判断——目标被墙会误判为无 IPv6，
	// 而实际上本地有 IPv6 地址只是出不去，两者语义不同。
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		v6Usable = false
		return false
	}
	for _, a := range addrs {
		ipnet, ok := a.(*net.IPNet)
		if !ok {
			continue
		}
		ip := ipnet.IP.To16()
		if ip == nil || ip.To4() != nil {
			continue // 非 IPv6
		}
		// 全局单播地址：2000::/3 且不是文档/回环/链路本地
		if len(ip) == net.IPv6len && ip[0]&0xe0 == 0x20 {
			// 排除文档前缀 2001:db8::/32
			if ip[0] == 0x20 && ip[1] == 0x01 && ip[2] == 0x0d && ip[3] == 0xb8 {
				continue
			}
			v6Usable = true
			return true
		}
	}
	v6Usable = false
	return false
}

// resetV6Cache 允许在网络变化后重新探测。
func resetV6Cache() {
	v6CheckMu.Lock()
	v6Checked = false
	v6CheckMu.Unlock()
}

// getPublicIP 按任务配置的 IPSource 获取公网 IP：
// api（默认：自定义接口优先，随后内置多源）/ netiface（网卡）/ cmd（自定义指令）。
func (m *Manager) getPublicIP(v6 bool, t config.DDNSTask) (string, error) {
	switch strings.ToLower(strings.TrimSpace(t.IPSource)) {
	case "netiface":
		return ipFromInterface(v6, t.IPInterface)
	case "cmd":
		return ipFromCmd(v6, t.IPCmd)
	default:
		// IPv6 请求前先判断本机是否有全局 IPv6 地址
		if v6 && !v6Available() {
			return "", errNoIPv6
		}
		urls := make([]string, 0, len(t.IPURLs)+5)
		urls = append(urls, t.IPURLs...) // 自定义接口优先
		urls = append(urls, builtinIPURLs(v6)...)
		return m.ipFromURLs(urls, v6)
	}
}

// builtinIPURLs 内置公网 IP 接口多源（按可靠性排序）。
func builtinIPURLs(v6 bool) []string {
	if v6 {
		return []string{
			"https://api6.ipify.org",
			"https://ipv6.icanhazip.com",
			"https://ifconfig.co/ip",
			"https://ipv6.ident.me",
		}
	}
	return []string{
		"https://api.ipify.org",
		"https://ipv4.icanhazip.com",
		"https://ifconfig.me/ip",
		"https://ipinfo.io/ip",
		"https://v4.ident.me",
	}
}

// ipFromURLs 依次请求接口，返回第一个可用且地址族匹配的公网 IP。
func (m *Manager) ipFromURLs(urls []string, v6 bool) (string, error) {
	// 关键点：必须强制指定拨号网络为 tcp4 / tcp6。
	// 否则双栈服务（如 ifconfig.co）会根据 Go 默认的拨号选择（通常优先 IPv4）
	// 返回 IPv4 地址，导致 IPv6 查询拿到 v4 结果。
	network := "tcp4"
	if v6 {
		network = "tcp6"
	}
	client := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, addr string) (net.Conn, error) {
				d := net.Dialer{Timeout: 8 * time.Second}
				return d.DialContext(ctx, network, addr)
			},
			ForceAttemptHTTP2: false, // 简化握手，避免不必要的协商差异
		},
	}

	// 收集每个源的失败原因，便于定位「到底是网络不通还是返回了错误地址族」
	// （旧实现只保留最后一个错误，掩盖了前面几个源的真实情况）
	var reasons []string
	for _, u := range urls {
		resp, err := client.Get(u)
		if err != nil {
			reasons = append(reasons, fmt.Sprintf("%s 连接失败(%v)", shortHost(u), err))
			continue
		}
		b, err := io.ReadAll(io.LimitReader(resp.Body, 256))
		resp.Body.Close()
		if err != nil {
			reasons = append(reasons, fmt.Sprintf("%s 读取失败", shortHost(u)))
			continue
		}
		if resp.StatusCode >= 400 {
			reasons = append(reasons, fmt.Sprintf("%s HTTP %d", shortHost(u), resp.StatusCode))
			continue
		}
		ip := strings.TrimSpace(string(b))
		if ip == "" || strings.Contains(ip, "<") {
			reasons = append(reasons, fmt.Sprintf("%s 返回内容无法解析", shortHost(u)))
			continue
		}
		parsed := net.ParseIP(ip)
		if parsed == nil {
			reasons = append(reasons, fmt.Sprintf("%s 返回非 IP: %q", shortHost(u), truncate(ip, 40)))
			continue
		}
		// 二次保险：地址族必须匹配
		if (parsed.To4() == nil) != v6 {
			reasons = append(reasons, fmt.Sprintf("%s 返回地址族不符: %s", shortHost(u), ip))
			continue
		}
		if isPrivateIP(ip) {
			return "", fmt.Errorf("本机无公网 IPv%d 出口（检测到内网地址 %s）。若上层有 NAT，请改用「网卡」或「自定义指令」方式获取公网 IP",
				map[bool]int{true: 6, false: 4}[v6], ip)
		}
		return ip, nil
	}

	if len(reasons) > 0 {
		return "", fmt.Errorf("获取公网 IPv%d 失败：%s", map[bool]int{true: 6, false: 4}[v6],
			strings.Join(reasons, "；"))
	}
	return "", errors.New("获取公网 IP 失败")
}

// ipFromInterface 从网卡取地址。网卡名留空时按本机默认路由自动判断出口地址。
// 网卡模式不做公网校验——它服务于「本机网卡已持有公网地址」与「NAT 场景由用户自行判断」。
func ipFromInterface(v6 bool, name string) (string, error) {
	fam := map[bool]int{true: 6, false: 4}[v6]
	if name == "" {
		// UDP Dial 只做路由选择，不会真正发包，用于取本机出口地址
		target := "223.5.5.5:53"
		network := "udp4"
		if v6 {
			target, network = "2400:3200::1:53", "udp6"
		}
		conn, err := net.Dial(network, target)
		if err != nil {
			return "", fmt.Errorf("无法自动判断出口网卡（IPv%d）: %v", fam, err)
		}
		defer conn.Close()
		return conn.LocalAddr().(*net.UDPAddr).IP.String(), nil
	}
	iface, err := net.InterfaceByName(name)
	if err != nil {
		return "", fmt.Errorf("网卡不存在: %s（%v）", name, err)
	}
	addrs, err := iface.Addrs()
	if err != nil {
		return "", fmt.Errorf("读取网卡 %s 地址失败: %v", name, err)
	}
	var fallback6 string
	for _, a := range addrs {
		ipnet, ok := a.(*net.IPNet)
		if !ok {
			continue
		}
		ip := ipnet.IP
		if v6 {
			if ip.To4() != nil {
				continue
			}
			// 优先全局单播地址（2000::/3）
			if len(ip) == net.IPv6len && ip[0]&0xe0 == 0x20 && fallback6 == "" {
				return ip.String(), nil
			}
			if fallback6 == "" && !ip.IsLinkLocalUnicast() && !ip.IsLoopback() {
				fallback6 = ip.String()
			}
			continue
		}
		if ip.To4() == nil || ip.IsLinkLocalUnicast() {
			continue
		}
		return ip.String(), nil
	}
	if fallback6 != "" {
		return fallback6, nil
	}
	return "", fmt.Errorf("网卡 %s 上未找到可用的 IPv%d 地址", name, fam)
}

// ipFromCmd 执行自定义指令，取 stdout 首行作为 IP（对齐 ddns-go 的「通过命令获取 IP」）。
func ipFromCmd(v6 bool, command string) (string, error) {
	command = strings.TrimSpace(command)
	if command == "" {
		return "", errors.New("指令模式需要填写获取 IP 的命令")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	var cmd *exec.Cmd
	if runtime.GOOS == "windows" {
		cmd = exec.CommandContext(ctx, "cmd", "/C", command)
	} else {
		cmd = exec.CommandContext(ctx, "sh", "-c", command)
	}
	out, err := cmd.Output()
	if err != nil {
		var stderr string
		if ee, ok := err.(*exec.ExitError); ok {
			stderr = truncate(strings.TrimSpace(string(ee.Stderr)), 120)
		}
		if stderr != "" {
			return "", fmt.Errorf("指令执行失败: %v，输出: %s", err, stderr)
		}
		return "", fmt.Errorf("指令执行失败: %v", err)
	}
	line := strings.TrimSpace(string(out))
	if i := strings.IndexAny(line, "\r\n"); i >= 0 {
		line = strings.TrimSpace(line[:i])
	}
	parsed := net.ParseIP(line)
	if parsed == nil {
		return "", fmt.Errorf("指令输出不是 IP: %q", truncate(line, 60))
	}
	fam := map[bool]int{true: 6, false: 4}[v6]
	if (parsed.To4() == nil) != v6 {
		return "", fmt.Errorf("指令输出地址族不符: 期望 IPv%d 得到 %s", fam, line)
	}
	return line, nil
}

// ---- 各服务商的统一入口 ----

// dispatch 把一次解析请求交给对应服务商。ip 由 runOnce 按任务配置统一获取后传入。
func (m *Manager) dispatch(domain, rtype, ip string, t config.DDNSTask) (string, error) {
	switch strings.ToLower(t.Provider) {
	case "cloudflare":
		return m.cloudflare(domain, rtype, ip, t)
	case "dnspod":
		return m.dnspod(domain, rtype, ip, t)
	case "aliyun":
		return m.aliyun(domain, rtype, ip, t)
	case "dnshe":
		return m.dnshe(domain, rtype, ip, t)
	case "callback":
		return m.callback(domain, rtype, ip, t)
	case "huaweicloud":
		return m.huaweicloud(domain, rtype, ip, t)
	case "godaddy":
		return m.godaddy(domain, rtype, ip, t)
	case "porkbun":
		return m.porkbun(domain, rtype, ip, t)
	case "namecheap":
		return m.namecheap(domain, rtype, ip, t)
	case "namesilo":
		return m.namesilo(domain, rtype, ip, t)
	default:
		return "", fmt.Errorf("未知服务商: %s", t.Provider)
	}
}

// splitDomain 把 fqdn 拆成 (子域名 RR, 主域名 zone)。例：
//
//	home.example.com -> ("home", "example.com")
//	a.b.example.com  -> ("a.b", "example.com")
func splitDomain(fqdn string) (string, string) {
	labels := strings.Split(strings.TrimSuffix(fqdn, "."), ".")
	if len(labels) <= 2 {
		return "@", strings.Join(labels, ".")
	}
	sub := strings.Join(labels[:len(labels)-2], ".")
	base := strings.Join(labels[len(labels)-2:], ".")
	return sub, base
}

var defaultMgr = NewManager()

// Default 返回模块级单例。
func Default() *Manager { return defaultMgr }
