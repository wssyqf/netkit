package waf

import (
	"net"
	"net/http"
	"net/netip"
	"strings"
	"time"
)

func nowStr() string { return time.Now().Format("2006-01-02 15:04:05") }

// clientIP 取客户端 IP。仅当 TCP 对端属于可信代理（trustedIPs）时才采信
// X-Forwarded-For，否则一律用对端地址——防止外部攻击者伪造 XFF 绕过检测或在日志中栽赃任意 IP。
func clientIP(r *http.Request, trustedIPs []string) string {
	peer := peerAddr(r)
	if fwd := r.Header.Get("X-Forwarded-For"); fwd != "" && peerIn(peer, trustedIPs) {
		parts := strings.Split(fwd, ",")
		if v := strings.TrimSpace(parts[0]); v != "" {
			return v
		}
	}
	return peer
}

// peerAddr 返回 TCP 连接对端 IP。
func peerAddr(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// peerIn 判断 IP 是否命中可信名单中的任一条目。
func peerIn(ip string, trusted []string) bool {
	for _, t := range trusted {
		if matchIP(t, ip) {
			return true
		}
	}
	return false
}

// matchIP 判断 ip 是否命中 entry（单 IP 或 CIDR）。
func matchIP(entry, ip string) bool {
	entry = strings.TrimSpace(entry)
	if entry == "" || ip == "" {
		return false
	}
	a, err := netip.ParseAddr(ip)
	if err != nil {
		return false
	}
	a = a.Unmap()
	if strings.Contains(entry, "/") {
		p, err := netip.ParsePrefix(entry)
		if err != nil {
			return false
		}
		return p.Contains(a)
	}
	b, err := netip.ParseAddr(entry)
	if err != nil {
		return false
	}
	return b.Unmap() == a
}
