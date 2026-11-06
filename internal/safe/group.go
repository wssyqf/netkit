package safe

import (
	"strings"
	"time"

	"netkit/internal/config"
)

// GroupInfo 解析后的安全组：过滤模式 + 生效中的 IP/CIDR 列表。
type GroupInfo struct {
	ID   string
	Name string
	Mode string
	IPs  []string
}

// ResolveGroups 把安全组引用的地址库条目解析为实际 IP 列表，跳过已过期条目。
// 地址库条目 ID 不存在时按 CIDR/单 IP 直接解析，兼容手填地址。
func ResolveGroups(groups []config.SecurityGroup, ipdb []config.IPDBEntry) map[string]GroupInfo {
	now := time.Now().Unix()
	byID := map[string]config.IPDBEntry{}
	for _, e := range ipdb {
		byID[e.ID] = e
	}
	out := map[string]GroupInfo{}
	for _, g := range groups {
		gi := GroupInfo{ID: g.ID, Name: g.Name, Mode: g.Mode}
		for _, ref := range g.ItemIDs {
			if e, ok := byID[ref]; ok {
				if e.ExpireAt > 0 && e.ExpireAt < now {
					continue
				}
				gi.IPs = append(gi.IPs, e.Value)
			} else {
				gi.IPs = append(gi.IPs, ref)
			}
		}
		out[g.ID] = gi
	}
	return out
}

// CheckGroup 判断 IP 是否能通过该安全组。
func CheckGroup(g GroupInfo, ip string) bool {
	return CheckIP(g.Mode, g.IPs, ip)
}

// GlobalFilterFunc 由外部组装的全局过滤函数：返回 false 表示拒绝访问。
type GlobalFilterFunc func(ip string) bool

// ParseIPList 兼容空格/逗号分隔的 IP 列表输入。
func ParseIPList(s string) []string {
	fields := strings.FieldsFunc(s, func(r rune) bool {
		return r == ',' || r == '\n' || r == ' ' || r == '，'
	})
	out := make([]string, 0, len(fields))
	for _, f := range fields {
		f = strings.TrimSpace(f)
		if f != "" {
			out = append(out, f)
		}
	}
	return out
}
