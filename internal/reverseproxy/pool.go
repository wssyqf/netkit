package reverseproxy

import (
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// backendState 单个后端的运行态：健康状态、并发数、被动失败计数。
type backendState struct {
	healthy    bool
	active     int
	weight     int
	fails      int
	lastFail   time.Time
	lastCheck  time.Time
	lastErr    string
	roundRobin uint64
	// 被动健康：滑动窗口内的 5xx 计数
	windowStart time.Time
	window5xx   int
}

// pool 一个后端池（对应一个子规则或默认规则）的运行时状态。
type pool struct {
	mu        sync.Mutex
	backends  []string
	states    map[string]*backendState
	rr        uint64
	policy    string
	sticky    bool
	maxActive int
}

func newPool(backends []string, weights []int, policy string, sticky bool, maxActive int) *pool {
	p := &pool{
		backends:  backends,
		states:    map[string]*backendState{},
		policy:    policy,
		sticky:    sticky,
		maxActive: maxActive,
	}
	if p.policy == "" {
		p.policy = "roundrobin"
	}
	for i, b := range backends {
		w := 1
		if i < len(weights) && weights[i] > 0 {
			w = weights[i]
		}
		p.states[b] = &backendState{healthy: true, weight: w}
	}
	return p
}

// pick 按策略选一个可用后端；sticky 时同 IP 固定到同一后端。
func (p *pool) pick(clientIP string) string {
	p.mu.Lock()
	defer p.mu.Unlock()
	if len(p.backends) == 0 {
		return ""
	}

	// 先筛健康 + 未超并发
	avail := make([]string, 0, len(p.backends))
	for _, b := range p.backends {
		st := p.states[b]
		if st == nil || !st.healthy {
			continue
		}
		if p.maxActive > 0 && st.active >= p.maxActive {
			continue
		}
		avail = append(avail, b)
	}
	if len(avail) == 0 {
		// 并发全部占满：不应绕过限制去压后端。
		// 只有"全部不健康"才降级（否则会把过载流量继续打进去）。
		healthy := make([]string, 0, len(p.backends))
		for _, b := range p.backends {
			if st := p.states[b]; st != nil && st.healthy {
				healthy = append(healthy, b)
			}
		}
		if len(healthy) == 0 {
			// 没有健康后端：返回空，让上层报 502，而不是硬塞
			return ""
		}
		// 有健康但都满并发：返回空由上层返回 503，避免压垮后端
		return ""
	}

	// 会话保持：同一客户端固定到同一后端（在该后端可用时）
	if p.sticky && clientIP != "" {
		var h uint64 = 1469598103934665603
		for i := 0; i < len(clientIP); i++ {
			h ^= uint64(clientIP[i])
			h *= 1099511628211
		}
		picked := avail[h%uint64(len(avail))]
		return picked
	}

	switch p.policy {
	case "iphash":
		if clientIP != "" {
			var h uint64 = 1469598103934665603
			for i := 0; i < len(clientIP); i++ {
				h ^= uint64(clientIP[i])
				h *= 1099511628211
			}
			return avail[h%uint64(len(avail))]
		}
		fallthrough
	case "weighted":
		total := 0
		for _, b := range avail {
			total += p.states[b].weight
		}
		p.rr++
		point := int(p.rr % uint64(total))
		for _, b := range avail {
			point -= p.states[b].weight
			if point < 0 {
				return b
			}
		}
		return avail[0]
	default: // roundrobin
		p.rr++
		return avail[p.rr%uint64(len(avail))]
	}
}

// pickClientIPExcluding 选一个不是 exclude 的可用后端（用于失败重试切换）。
func (p *pool) pickClientIPExcluding(clientIP, exclude string) string {
	p.mu.Lock()
	defer p.mu.Unlock()
	cands := make([]string, 0, len(p.backends))
	for _, b := range p.backends {
		if b == exclude {
			continue
		}
		st := p.states[b]
		if st == nil || !st.healthy {
			continue
		}
		if p.maxActive > 0 && st.active >= p.maxActive {
			continue
		}
		cands = append(cands, b)
	}
	if len(cands) == 0 {
		return ""
	}
	p.rr++
	return cands[p.rr%uint64(len(cands))]
}

// acquire/release 维护并发计数。
func (p *pool) acquire(b string) {
	p.mu.Lock()
	if st := p.states[b]; st != nil {
		st.active++
	}
	p.mu.Unlock()
}

func (p *pool) release(b string) {
	p.mu.Lock()
	if st := p.states[b]; st != nil && st.active > 0 {
		st.active--
	}
	p.mu.Unlock()
}

// markFail 被动健康：滑动窗口内 5xx 达到阈值则摘除，冷却后可恢复探测。
func (p *pool) markFail(b string, maxFailed int, cooldown time.Duration) {
	p.mu.Lock()
	defer p.mu.Unlock()
	st := p.states[b]
	if st == nil {
		return
	}
	now := time.Now()
	if st.windowStart.IsZero() || now.Sub(st.windowStart) > 60*time.Second {
		st.windowStart = now
		st.window5xx = 0
	}
	st.fails++
	st.window5xx++
	st.lastFail = now

	limit := maxFailed
	if limit <= 0 {
		limit = 5
	}
	if st.window5xx >= limit {
		st.healthy = false
		st.lastErr = itoa(st.window5xx) + " 次失败（60 秒窗口内）"
		cd := cooldown
		if cd <= 0 {
			cd = 30 * time.Second
		}
		time.AfterFunc(cd, func() {
			p.mu.Lock()
			if s := p.states[b]; s != nil && !s.healthy {
				s.healthy = true
				s.fails = 0
				s.window5xx = 0
				s.windowStart = time.Time{}
			}
			p.mu.Unlock()
		})
	}
}

func (p *pool) markOK(b string) {
	p.mu.Lock()
	if st := p.states[b]; st != nil {
		st.fails = 0
		st.healthy = true
		st.lastErr = ""
		st.window5xx = 0
	}
	p.mu.Unlock()
}

// snapshot 导出健康状态供后台展示。
func (p *pool) snapshot() map[string]string {
	p.mu.Lock()
	defer p.mu.Unlock()
	out := map[string]string{}
	for b, st := range p.states {
		s := "健康"
		if !st.healthy {
			s = "不健康"
			if st.lastErr != "" {
				s += "（" + st.lastErr + "）"
			}
		}
		if st.active > 0 {
			s += " 并发" + itoa(st.active)
		}
		out[b] = s
	}
	return out
}

// startHealthCheck 启动主动健康检查循环。
func (p *pool) startHealthCheck(hc healthCfg, stop <-chan struct{}) {
	if !hc.enabled {
		return
	}
	go func() {
		interval := time.Duration(hc.interval) * time.Second
		if interval <= 0 {
			interval = 10 * time.Second
		}
		timeout := time.Duration(hc.timeout) * time.Second
		if timeout <= 0 {
			timeout = 3 * time.Second
		}
		client := &http.Client{Timeout: timeout}
		t := time.NewTicker(interval)
		defer t.Stop()
		for {
			select {
			case <-stop:
				return
			case <-t.C:
				for _, b := range p.backends {
					go p.checkOne(client, b, hc)
				}
			}
		}
	}()
}

func (p *pool) checkOne(client *http.Client, backend string, hc healthCfg) {
	ok := false
	var errMsg string
	switch hc.hcType {
	case "tcp":
		u, err := parseBackendURL(backend)
		if err != nil {
			errMsg = err.Error()
			break
		}
		host := u.Host
		if u.Port() == "" {
			if u.Scheme == "https" {
				host += ":443"
			} else {
				host += ":80"
			}
		}
		conn, err := net.DialTimeout("tcp", host, client.Timeout)
		if err != nil {
			errMsg = err.Error()
		} else {
			conn.Close()
			ok = true
		}
	default: // http
		checkURL := backendURLForHTTP(backend)
		if hc.path != "" {
			// 拼接健康检查路径（保留后端已有路径前缀）
			base := strings.TrimSuffix(checkURL, "/")
			pth := hc.path
			if !strings.HasPrefix(pth, "/") {
				pth = "/" + pth
			}
			checkURL = base + pth
		}
		req, err := http.NewRequest(http.MethodGet, checkURL, nil)
		if err != nil {
			errMsg = err.Error()
			break
		}
		for k, v := range hc.headers {
			req.Header.Set(k, v)
		}
		resp, err := client.Do(req)
		if err != nil {
			errMsg = err.Error()
		} else {
			resp.Body.Close()
			ok = resp.StatusCode < 500
			if !ok {
				errMsg = "HTTP " + itoa(resp.StatusCode)
			}
		}
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	st := p.states[backend]
	if st == nil {
		return
	}
	st.lastCheck = time.Now()
	if ok {
		st.healthy = true
		st.fails = 0
		st.lastErr = ""
	} else {
		st.lastErr = errMsg
		st.fails++
		if hc.maxFailed > 0 && st.fails >= hc.maxFailed {
			st.healthy = false
		}
	}
}

// healthCfg 内部使用的健康检查配置。
type healthCfg struct {
	enabled   bool
	hcType    string
	path      string
	interval  int
	timeout   int
	maxFailed int
	headers   map[string]string
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		b[i] = '-'
	}
	return string(b[i:])
}
