package config

import (
	"fmt"
	"strconv"
	"strings"
)

// ParsePortSpec 解析端口规格字符串，兼容 lucky 的写法：
//
//	"22"                 单个端口
//	"80,443,2222"        多个端口（逗号/空格/换行分隔）
//	"20000-20010"        连续端口范围
//	"80,443,8000-8005"   混合
//
// 返回展开后的端口列表，保持输入顺序。
func ParsePortSpec(s string) ([]int, error) {
	fields := strings.FieldsFunc(s, func(r rune) bool {
		return r == ',' || r == '，' || r == ' ' || r == '\n' || r == '\t' || r == ';'
	})
	out := make([]int, 0, len(fields))
	for _, f := range fields {
		f = strings.TrimSpace(f)
		if f == "" {
			continue
		}
		if i := strings.Index(f, "-"); i > 0 {
			lo, err1 := strconv.Atoi(strings.TrimSpace(f[:i]))
			hi, err2 := strconv.Atoi(strings.TrimSpace(f[i+1:]))
			if err1 != nil || err2 != nil {
				return nil, fmt.Errorf("端口范围格式错误: %s", f)
			}
			if lo < 1 || hi > 65535 {
				return nil, fmt.Errorf("端口超出范围 1-65535: %s", f)
			}
			if lo > hi {
				return nil, fmt.Errorf("端口范围起始大于结束: %s", f)
			}
			if hi-lo > 2000 {
				return nil, fmt.Errorf("单个端口范围过大（最多 2000 个）: %s", f)
			}
			for p := lo; p <= hi; p++ {
				out = append(out, p)
			}
			continue
		}
		p, err := strconv.Atoi(f)
		if err != nil {
			return nil, fmt.Errorf("端口格式错误: %s", f)
		}
		if p < 1 || p > 65535 {
			return nil, fmt.Errorf("端口超出范围 1-65535: %s", f)
		}
		out = append(out, p)
	}
	return out, nil
}

// FormatPortSpec 把端口列表压回紧凑写法（连续段用 a-b 表示）。
func FormatPortSpec(ports []int) string {
	if len(ports) == 0 {
		return ""
	}
	var parts []string
	i := 0
	for i < len(ports) {
		j := i
		for j+1 < len(ports) && ports[j+1] == ports[j]+1 {
			j++
		}
		if j-i >= 2 {
			parts = append(parts, fmt.Sprintf("%d-%d", ports[i], ports[j]))
		} else {
			for k := i; k <= j; k++ {
				parts = append(parts, strconv.Itoa(ports[k]))
			}
		}
		i = j + 1
	}
	return strings.Join(parts, ",")
}

// MapTargetPorts 把监听端口映射为目标端口：
//   - 目标只有 1 个端口：所有监听端口都转发到它
//   - 目标数量与监听数量相同：按序一一对应
//   - 否则取第一个并报错给上层
func MapTargetPorts(listen, target []int) ([]int, error) {
	if len(target) == 0 {
		return nil, fmt.Errorf("目标端口不能为空")
	}
	if len(target) == 1 {
		out := make([]int, len(listen))
		for i := range out {
			out[i] = target[0]
		}
		return out, nil
	}
	if len(target) != len(listen) {
		return nil, fmt.Errorf("监听端口 %d 个、目标端口 %d 个，数量需一致（或目标只填 1 个）",
			len(listen), len(target))
	}
	return target, nil
}
