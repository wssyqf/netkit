package admin

import (
	"runtime"
	"sync"
	"time"
)

// sysCPU / sysMem 由各平台的 init 注册系统级采样函数；
// 未注册时退回进程级近似值，保证任意平台都能编译运行。
var (
	sysCPU func() float64
	sysMem func() float64
)

// memUsagePercent 返回系统内存使用率（0-100）。
func memUsagePercent() float64 {
	if sysMem != nil {
		return sysMem()
	}
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	// 无系统级数据时，用进程自身占用做粗略估计（GB 数 × 10，上限 100）
	return mathMin(100, float64(m.Sys)/(1024*1024*1024)*10)
}

// cpuUsagePercent 系统 CPU 使用率：Linux 走 /proc/stat 增量，
// Windows 等平台退回进程 CPU 时间近似。
func cpuUsagePercent() float64 {
	if sysCPU != nil {
		return sysCPU()
	}
	return processCPUPercent()
}

var (
	cpuMu       sync.Mutex
	prevCPUTime time.Duration
	prevAt      time.Time
)

// processCPUPercent 用进程累计 CPU 时间增量估算占用率。
func processCPUPercent() float64 {
	cpuMu.Lock()
	defer cpuMu.Unlock()
	now := time.Now()
	usage := processCPUTime()
	if prevAt.IsZero() {
		prevCPUTime, prevAt = usage, now
		return 0
	}
	elapsed := now.Sub(prevAt)
	if elapsed <= 0 {
		return 0
	}
	delta := usage - prevCPUTime
	prevCPUTime, prevAt = usage, now
	pct := float64(delta) / float64(elapsed) / float64(runtime.NumCPU()) * 100
	return clampPct(pct)
}

func clampPct(v float64) float64 {
	if v < 0 {
		return 0
	}
	if v > 100 {
		return 100
	}
	return v
}

func mathMin(a, b float64) float64 {
	if a < b {
		return a
	}
	return b
}

func splitLines(s string) []string {
	var out []string
	cur := make([]byte, 0, 128)
	for i := 0; i < len(s); i++ {
		if s[i] == '\n' {
			out = append(out, string(cur))
			cur = cur[:0]
			continue
		}
		cur = append(cur, s[i])
	}
	if len(cur) > 0 {
		out = append(out, string(cur))
	}
	return out
}

func fieldsOf(s string) []string {
	var out []string
	cur := make([]byte, 0, 32)
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == ' ' || c == '\t' || c == '\r' {
			if len(cur) > 0 {
				out = append(out, string(cur))
				cur = cur[:0]
			}
			continue
		}
		cur = append(cur, c)
	}
	if len(cur) > 0 {
		out = append(out, string(cur))
	}
	return out
}

func parseFloat(s string) float64 {
	var v float64
	var frac float64
	inFrac := false
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == '.' {
			inFrac = true
			frac = 0.1
			continue
		}
		if c < '0' || c > '9' {
			return v
		}
		d := float64(c - '0')
		if inFrac {
			v += d * frac
			frac /= 10
		} else {
			v = v*10 + d
		}
	}
	return v
}
