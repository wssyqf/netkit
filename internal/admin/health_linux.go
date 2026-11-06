//go:build linux

package admin

import (
	"os"
	"strconv"
	"strings"
)

func init() {
	sysCPU = linuxCPUPercent
	sysMem = linuxMemPercent
}

// linuxCPUPercent 读 /proc/stat 计算系统 CPU 使用率。
func linuxCPUPercent() float64 {
	b, err := os.ReadFile("/proc/stat")
	if err != nil {
		return processCPUPercent()
	}
	line := strings.SplitN(string(b), "\n", 2)[0]
	f := fieldsOf(line)
	if len(f) < 5 || f[0] != "cpu" {
		return processCPUPercent()
	}
	var total, idle uint64
	for i := 1; i < len(f) && i <= 8; i++ {
		v, err := strconv.ParseUint(f[i], 10, 64)
		if err != nil {
			continue
		}
		total += v
		if i == 4 || i == 5 { // idle + iowait
			idle += v
		}
	}
	if total == 0 {
		return processCPUPercent()
	}
	cpuMu.Lock()
	defer cpuMu.Unlock()
	dt := total - lastCPUTotal
	di := idle - lastCPUIdle
	lastCPUTotal, lastCPUIdle = total, idle
	if dt == 0 {
		return 0
	}
	return clampPct(float64(dt-di) / float64(dt) * 100)
}

// linuxMemPercent 读取 /proc/meminfo 计算内存使用率。
func linuxMemPercent() float64 {
	b, err := os.ReadFile("/proc/meminfo")
	if err != nil {
		return 0
	}
	var total, avail float64
	for _, line := range strings.Split(string(b), "\n") {
		f := strings.Fields(line)
		if len(f) < 2 {
			continue
		}
		switch f[0] {
		case "MemTotal:":
			total = parseFloat(f[1])
		case "MemAvailable:":
			avail = parseFloat(f[1])
		}
	}
	if total <= 0 {
		return 0
	}
	return clampPct((total - avail) / total * 100)
}
