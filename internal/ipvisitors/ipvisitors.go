// Package ipvisitors 登记出现过的来源 IP 及其地理位置，供后台"IP 访客"页展示。
package ipvisitors

import (
	"net"
	"sort"
	"strings"
	"sync"
	"time"

	"netkit/internal/geoip"
)

// Entry 一个出现过的 IP 的聚合信息。
type Entry struct {
	IP      string `json:"ip"`
	CC      string `json:"cc"`      // ISO 3166-1 二位国家码，未知/私网为空
	Sources string `json:"sources"` // 出现过的来源，逗号分隔
	Count   int    `json:"count"`
	First   string `json:"first"`
	Last    string `json:"last"`
}

const maxEntries = 5000

type entry struct {
	Entry
	srcs map[string]bool
}

type registry struct {
	mu   sync.Mutex
	ips  map[string]*entry
}

var def = &registry{ips: map[string]*entry{}}

// Default 返回全局登记单例。
func Default() *registry { return def }

// Record 记录一次 IP 出现。私网/回环地址仅在安全类来源（蜜罐/WAF）登记，
// 避免内网正常访问把访客列表刷满；所有来源均去重登记 IP 计数。
func (r *registry) Record(ip, source string) {
	if ip == "" || ip == "127.0.0.1" || ip == "::1" {
		return
	}
	ipn := net.ParseIP(ip)
	isPrivate := ipn != nil && (ipn.IsPrivate() || ipn.IsLoopback() || ipn.IsUnspecified())
	if isPrivate && source != "蜜罐" && source != "WAF" {
		return
	}
	now := time.Now().Format("2006-01-02 15:04:05")
	r.mu.Lock()
	defer r.mu.Unlock()
	e, ok := r.ips[ip]
	if !ok {
		if len(r.ips) >= maxEntries {
			r.evictLocked()
		}
		e = &entry{Entry: Entry{IP: ip, CC: geoip.Country(ip), First: now}, srcs: map[string]bool{}}
		r.ips[ip] = e
	}
	e.Count++
	e.Last = now
	if source != "" {
		e.srcs[source] = true
	}
	// Sources 拼接在读取时做，这里只维护集合；CC 查询放读取侧（查询国家库有锁）
}

// evictLocked 淘汰最久未出现的条目，保持容量（调用方须持锁）。
func (r *registry) evictLocked() {
	// 找出 Last 最早的 10% 一并淘汰，避免每次只挤掉一个
	type kv struct {
		ip  string
		lst string
	}
	all := make([]kv, 0, len(r.ips))
	for ip, e := range r.ips {
		all = append(all, kv{ip, e.Last})
	}
	sort.Slice(all, func(i, j int) bool { return all[i].lst < all[j].lst })
	n := len(all) / 10
	if n < 1 {
		n = 1
	}
	for i := 0; i < n && i < len(all); i++ {
		delete(r.ips, all[i].ip)
	}
}

// Query 返回访客列表（最近出现优先），cc/kw 过滤可选。
func (r *registry) Query(cc, kw string, limit int) []Entry {
	r.mu.Lock()
	out := make([]Entry, 0, len(r.ips))
	for _, e := range r.ips {
		e2 := e.Entry
		srcs := make([]string, 0, len(e.srcs))
		for s := range e.srcs {
			srcs = append(srcs, s)
		}
		sort.Strings(srcs)
		e2.Sources = joinComma(srcs)
		out = append(out, e2)
	}
	r.mu.Unlock()

	filtered := out[:0:0]
	for _, e := range out {
		if cc != "" && e.CC != cc {
			continue
		}
		if kw != "" && !strings.Contains(strings.ToLower(e.IP), strings.ToLower(kw)) {
			continue
		}
		filtered = append(filtered, e)
	}
	sort.Slice(filtered, func(i, j int) bool { return filtered[i].Last > filtered[j].Last })
	if limit > 0 && len(filtered) > limit {
		filtered = filtered[:limit]
	}
	return filtered
}

// Count 返回登记的 IP 总数。
func (r *registry) Count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.ips)
}

// Clear 清空登记。
func (r *registry) Clear() {
	r.mu.Lock()
	r.ips = map[string]*entry{}
	r.mu.Unlock()
}

func joinComma(ss []string) string {
	out := ""
	for i, s := range ss {
		if i > 0 {
			out += ","
		}
		out += s
	}
	return out
}
