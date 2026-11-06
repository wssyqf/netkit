package safe

import (
	"net"
	"net/netip"
	"strings"
	"sync"
)

// LogRing 每条规则独立的环形日志缓冲，最多保留 max 条。
type LogRing struct {
	mu   sync.Mutex
	max  int
	logs []string
}

func NewLogRing(max int) *LogRing {
	if max <= 0 {
		max = 100
	}
	return &LogRing{max: max}
}

func (r *LogRing) Add(line string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.logs = append(r.logs, line)
	if len(r.logs) > r.max {
		r.logs = r.logs[len(r.logs)-r.max:]
	}
}

func (r *LogRing) Snapshot() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]string, len(r.logs))
	copy(out, r.logs)
	return out
}

// Clear 清空日志。
func (r *LogRing) Clear() {
	r.mu.Lock()
	r.logs = nil
	r.mu.Unlock()
}

// CheckIP 对单个 IP 按 黑/白 名单做判断。
// mode: "none" 全放行；"white" 命中名单才放行；"black" 命中名单即拦截。
// 名单项支持单个 IP 或 CIDR 网段（如 192.168.1.0/24）。
func CheckIP(mode string, entries []string, ip string) bool {
	mode = strings.ToLower(strings.TrimSpace(mode))
	if mode == "" || mode == "none" {
		return true
	}
	a, err := netip.ParseAddr(strings.TrimSpace(ip))
	if err != nil {
		return mode == "black"
	}
	for _, e := range entries {
		e = strings.TrimSpace(e)
		if e == "" {
			continue
		}
		if strings.Contains(e, "/") {
			p, err := netip.ParsePrefix(e)
			if err != nil {
				continue
			}
			if p.Contains(a.Unmap()) {
				// 命中名单：白名单放行，黑名单拒绝
				return mode == "white"
			}
		} else if b, err := netip.ParseAddr(e); err == nil && b.Unmap() == a.Unmap() {
			// 命中名单：白名单放行，黑名单拒绝
			return mode == "white"
		}
	}
	return mode != "white"
}

// SplitHostPort 把 Host 头里的端口剥掉，返回纯域名。
func StripPort(host string) string {
	if h, _, err := net.SplitHostPort(host); err == nil {
		return h
	}
	return host
}
