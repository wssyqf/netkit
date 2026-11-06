// Package logcenter 全局日志中心：各模块日志统一汇总，支持模块过滤与关键字查询。
package logcenter

import (
	"fmt"
	"strings"
	"sync"
	"time"
)

const (
	LevelInfo  = "info"
	LevelWarn  = "warn"
	LevelError = "error"
)

// Entry 日志中心的一条日志。
type Entry struct {
	Time   string `json:"time"`
	Module string `json:"module"`
	Level  string `json:"level"`
	Msg    string `json:"msg"`
}

type LogCenter struct {
	mu   sync.Mutex
	max  int
	logs []Entry
	seq  uint64
	subs map[chan Entry]struct{}
}

var def = newCenter(5000)

// Default 返回全局日志中心单例。
func Default() *LogCenter { return def }

func newCenter(max int) *LogCenter {
	return &LogCenter{max: max, subs: map[chan Entry]struct{}{}}
}

// Add 写入一条日志（并发安全）。
func (c *LogCenter) Add(module, level, format string, args ...any) {
	msg := format
	if len(args) > 0 {
		msg = sprintf(format, args...)
	}
	e := Entry{
		Time:   time.Now().Format("2006-01-02 15:04:05"),
		Module: module,
		Level:  level,
		Msg:    msg,
	}
	c.mu.Lock()
	c.logs = append(c.logs, e)
	if len(c.logs) > c.max {
		c.logs = c.logs[len(c.logs)-c.max:]
	}
	c.mu.Unlock()
	c.notify(e)
}

func (c *LogCenter) notify(e Entry) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for ch := range c.subs {
		select {
		case ch <- e:
		default:
		}
	}
}

// Subscribe 返回一个实时日志通道，用返回的 cancel 函数退订。
func (c *LogCenter) Subscribe() (<-chan Entry, func()) {
	ch := make(chan Entry, 256)
	c.mu.Lock()
	c.subs[ch] = struct{}{}
	c.mu.Unlock()
	return ch, func() {
		c.mu.Lock()
		delete(c.subs, ch)
		c.mu.Unlock()
	}
}

// Query 按模块/级别/关键字过滤，limit<=0 时取全部缓冲。
func (c *LogCenter) Query(module, level, keyword string, limit int) []Entry {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := []Entry{}
	kw := strings.ToLower(strings.TrimSpace(keyword))
	for i := len(c.logs) - 1; i >= 0; i-- {
		e := c.logs[i]
		if module != "" && e.Module != module {
			continue
		}
		if level != "" && e.Level != level {
			continue
		}
		if kw != "" && !strings.Contains(strings.ToLower(e.Msg), kw) {
			continue
		}
		out = append(out, e)
		if limit > 0 && len(out) >= limit {
			break
		}
	}
	// 反转回时间正序
	for i, j := 0, len(out)-1; i < j; i, j = i+1, j-1 {
		out[i], out[j] = out[j], out[i]
	}
	return out
}

// Modules 返回日志中出现过的模块名。
func (c *LogCenter) Modules() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	seen := map[string]bool{}
	out := []string{} // 必须是非 nil：日志被清空时若返回 null，前端 map 会崩
	for i := len(c.logs) - 1; i >= 0 && len(out) < 32; i-- {
		if !seen[c.logs[i].Module] {
			seen[c.logs[i].Module] = true
			out = append(out, c.logs[i].Module)
		}
	}
	return out
}

// Clear 清空日志。
func (c *LogCenter) Clear() {
	c.mu.Lock()
	c.logs = nil
	c.mu.Unlock()
}

func sprintf(format string, args ...any) string { return fmt.Sprintf(format, args...) }
