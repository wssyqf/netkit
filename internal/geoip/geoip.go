// Package geoip 提供 GeoLite2 国家库离线查询，用于全局区域（国家/地区）拦截。
package geoip

import (
	"io"
	"net"
	"os"
	"sync"
	"time"

	"github.com/oschwald/maxminddb-golang"
)

// record GeoLite2-Country 记录：优先取归属国，其次注册国。
type record struct {
	Country struct {
		IsoCode string `maxminddb:"iso_code"`
	} `maxminddb:"country"`
	RegisteredCountry struct {
		IsoCode string `maxminddb:"iso_code"`
	} `maxminddb:"registered_country"`
}

type state struct {
	reader    *maxminddb.Reader
	path      string
	modTime   time.Time
	err       string
	lastCheck time.Time
}

var (
	mu  sync.RWMutex
	cur state
)

// Load 打开指定路径的 mmdb。文件缺失不致命：仅记录状态，查询一律返回 ""（放行）。
func Load(path string) {
	mu.Lock()
	defer mu.Unlock()
	cur.path = path
	reopenLocked()
}

// reopenLocked 按 mtime 变化重开数据库（调用方须持写锁）。
func reopenLocked() {
	cur.lastCheck = time.Now()
	st, err := os.Stat(cur.path)
	if err != nil {
		closeLocked()
		cur.err = "数据库文件不可用: " + err.Error()
		return
	}
	if cur.reader != nil && cur.modTime.Equal(st.ModTime()) {
		return // 未变化，保持打开
	}
	closeLocked()
	r, err := maxminddb.Open(cur.path)
	if err != nil {
		cur.err = "打开数据库失败: " + err.Error()
		return
	}
	cur.reader = r
	cur.modTime = st.ModTime()
	cur.err = ""
}

func closeLocked() {
	if cur.reader != nil {
		cur.reader.Close()
		cur.reader = nil
	}
}

// Country 查询 IP 的 ISO 3166-1 二位国家码（如 CN）。
// 未知地址、私网地址、无数据库或查询出错时返回 ""（调用方应放行）。
func Country(ip string) string {
	ipn := net.ParseIP(ip)
	if ipn == nil {
		return ""
	}
	mu.RLock()
	r := cur.reader
	stale := time.Since(cur.lastCheck) > 30*time.Second
	mu.RUnlock()
	if stale {
		mu.Lock()
		if time.Since(cur.lastCheck) > 30*time.Second {
			reopenLocked() // 每 30 秒最多检查一次文件 mtime，热替换生效
		}
		r = cur.reader
		mu.Unlock()
	}
	if r == nil {
		return ""
	}
	var rec record
	if err := r.Lookup(ipn, &rec); err != nil && err != io.EOF {
		return ""
	}
	if rec.Country.IsoCode != "" {
		return rec.Country.IsoCode
	}
	return rec.RegisteredCountry.IsoCode
}

// Status 返回数据库加载状态（供管理 API 展示）。
func Status() map[string]any {
	mu.RLock()
	defer mu.RUnlock()
	mt := ""
	if !cur.modTime.IsZero() {
		mt = cur.modTime.Format("2006-01-02 15:04:05")
	}
	return map[string]any{
		"path":    cur.path,
		"loaded":  cur.reader != nil,
		"error":   cur.err,
		"modTime": mt,
	}
}
