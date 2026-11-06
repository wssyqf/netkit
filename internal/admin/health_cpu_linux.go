//go:build linux

package admin

import (
	"os"
	"strconv"
	"strings"
	"time"
)

// processCPUTime 读 /proc/self/stat 的 utime+stime（单位 tick，按 100Hz 折算）。
func processCPUTime() time.Duration {
	b, err := os.ReadFile("/proc/self/stat")
	if err != nil {
		return 0
	}
	// 第 14、15 字段为 utime、stime；comm 可能含空格，先截到最后一个 ')' 之后
	s := string(b)
	i := strings.LastIndex(s, ")")
	if i < 0 {
		return 0
	}
	f := strings.Fields(s[i+1:])
	if len(f) < 13 {
		return 0
	}
	ut, _ := strconv.ParseInt(f[11], 10, 64)
	st, _ := strconv.ParseInt(f[12], 10, 64)
	return time.Duration(ut+st) * (time.Second / 100)
}
