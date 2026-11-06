// Package cron 内置 5 段 cron（分 时 日 月 周）解析与计划任务调度。
package cron

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

// Schedule 一个解析后的 cron 表达式。
type Schedule struct {
	minute, hour, dom, month, dow map[int]bool
	anyDOM, anyDOW                bool
}

// Parse 解析 5 段 cron 表达式，支持 * , - / 。
func Parse(expr string) (*Schedule, error) {
	fields := strings.Fields(strings.TrimSpace(expr))
	if len(fields) != 5 {
		return nil, fmt.Errorf("cron 表达式需要 5 段（分 时 日 月 周），当前 %d 段", len(fields))
	}
	s := &Schedule{}
	var err error
	if s.minute, err = parseField(fields[0], 0, 59); err != nil {
		return nil, fmt.Errorf("分钟字段: %w", err)
	}
	if s.hour, err = parseField(fields[1], 0, 23); err != nil {
		return nil, fmt.Errorf("小时字段: %w", err)
	}
	if s.dom, err = parseField(fields[2], 1, 31); err != nil {
		return nil, fmt.Errorf("日字段: %w", err)
	}
	if s.month, err = parseField(fields[3], 1, 12); err != nil {
		return nil, fmt.Errorf("月字段: %w", err)
	}
	if s.dow, err = parseField(strings.ReplaceAll(fields[4], "7", "0"), 0, 6); err != nil {
		return nil, fmt.Errorf("周字段: %w", err)
	}
	s.anyDOM = fields[2] == "*"
	s.anyDOW = fields[4] == "*"
	return s, nil
}

func parseField(f string, min, max int) (map[int]bool, error) {
	set := map[int]bool{}
	for _, part := range strings.Split(f, ",") {
		step := 1
		if i := strings.Index(part, "/"); i >= 0 {
			v, err := strconv.Atoi(part[i+1:])
			if err != nil || v <= 0 {
				return nil, fmt.Errorf("步长无效: %s", part)
			}
			step = v
			part = part[:i]
		}
		lo, hi := min, max
		if part != "*" {
			if i := strings.Index(part, "-"); i >= 0 {
				a, err1 := strconv.Atoi(part[:i])
				b, err2 := strconv.Atoi(part[i+1:])
				if err1 != nil || err2 != nil || a > b {
					return nil, fmt.Errorf("范围无效: %s", part)
				}
				lo, hi = a, b
			} else {
				v, err := strconv.Atoi(part)
				if err != nil {
					return nil, fmt.Errorf("数值无效: %s", part)
				}
				lo, hi = v, v
			}
		}
		if lo < min || hi > max {
			return nil, fmt.Errorf("超出范围 [%d,%d]: %s", min, max, part)
		}
		for v := lo; v <= hi; v += step {
			set[v] = true
		}
	}
	return set, nil
}

// Match 判断指定时刻是否命中（按本地时间，分钟精度）。
func (s *Schedule) Match(t time.Time) bool {
	if !s.minute[t.Minute()] || !s.hour[t.Hour()] || !s.month[int(t.Month())] {
		return false
	}
	domOK := s.dom[t.Day()]
	dowOK := s.dow[int(t.Weekday())]
	// 标准 cron 语义：日与周都指定时满足其一即可
	if !s.anyDOM && !s.anyDOW {
		return domOK || dowOK
	}
	return domOK && dowOK
}
