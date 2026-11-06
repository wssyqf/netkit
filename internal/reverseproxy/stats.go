package reverseproxy

import (
	"sort"
	"sync"
	"time"
)

// Stats 单条 Web 规则的流量统计。
// 所有计数均为累计值，进程重启后清零；通过快照对外暴露。
type Stats struct {
	mu sync.Mutex

	// 总量
	Requests   uint64 // 总请求数
	BytesIn    uint64 // 请求体总字节
	BytesOut   uint64 // 响应体总字节
	Status2xx  uint64
	Status3xx  uint64
	Status4xx  uint64
	Status5xx  uint64
	Blocked    uint64 // 被拦截（IP过滤/认证/全局过滤）
	Redirected uint64 // 被跳转（HTTP→HTTPS）
	Errors     uint64 // 后端错误

	// 耗时（累计纳秒，用于算平均）
	TotalDuration time.Duration
	DurCount      uint64

	// 按子规则维度的请求数
	byRule map[string]*ruleStat

	// 按路径前缀统计（取前 N 热的路径）
	byPath map[string]*pathStat

	// 按状态码精确统计
	byStatus map[int]uint64

	// 按小时统计最近 24 小时请求量（环形）
	hourly [24]hourBucket

	// 首次与最近活动时间
	StartAt  time.Time
	LastAt   time.Time
	LastPath string

	// 慢请求记录（最近 N 条超过阈值的）
	slow []SlowReq
}

type ruleStat struct {
	Name     string
	Requests uint64
	BytesIn  uint64
	BytesOut uint64
	Errors   uint64
}

type pathStat struct {
	Path     string
	Requests uint64
	BytesOut uint64
	Latency  time.Duration
}

type hourBucket struct {
	Hour     int64 // unix 小时时间戳
	Requests uint64
}

// SlowReq 一条慢请求记录。
type SlowReq struct {
	Time     string
	Method   string
	Path     string
	Status   int
	Elapsed  int64 // 毫秒
	BytesOut int64
	Backend  string
}

// StatsConfig 统计相关配置。
type StatsConfig struct {
	MaxPaths     int   // 保留多少条路径统计，默认 200
	MaxSlow      int   // 保留多少条慢请求，默认 50
	SlowThreshMS int64 // 慢请求阈值（毫秒），默认 500
}

func NewStats() *Stats {
	return &Stats{
		byRule:   map[string]*ruleStat{},
		byPath:   map[string]*pathStat{},
		byStatus: map[int]uint64{},
		StartAt:  time.Now(),
	}
}

// Record 记录一次请求。
type RecordInput struct {
	RuleID   string
	RuleName string
	Method   string
	Path     string
	Status   int
	BytesIn  int64
	BytesOut int64
	Elapsed  time.Duration
	Blocked  bool
	Redirect bool
	Error    bool
	Backend  string
	Cfg      StatsConfig
}

// Record 累计一次请求统计（并发安全）。
func (s *Stats) Record(in RecordInput) {
	now := time.Now()
	s.mu.Lock()
	defer s.mu.Unlock()

	s.Requests++
	if in.BytesIn > 0 {
		s.BytesIn += uint64(in.BytesIn)
	}
	if in.BytesOut > 0 {
		s.BytesOut += uint64(in.BytesOut)
	}
	switch {
	case in.Status >= 500:
		s.Status5xx++
	case in.Status >= 400:
		s.Status4xx++
	case in.Status >= 300:
		s.Status3xx++
	case in.Status >= 200:
		s.Status2xx++
	}
	if in.Blocked {
		s.Blocked++
	}
	if in.Redirect {
		s.Redirected++
	}
	if in.Error {
		s.Errors++
	}
	if in.Elapsed > 0 {
		s.TotalDuration += in.Elapsed
		s.DurCount++
	}
	s.LastAt = now
	s.LastPath = in.Path
	s.byStatus[in.Status]++

	// 子规则维度
	if in.RuleID != "" {
		rs := s.byRule[in.RuleID]
		if rs == nil {
			rs = &ruleStat{Name: in.RuleName}
			s.byRule[in.RuleID] = rs
		}
		rs.Requests++
		if in.BytesIn > 0 {
			rs.BytesIn += uint64(in.BytesIn)
		}
		if in.BytesOut > 0 {
			rs.BytesOut += uint64(in.BytesOut)
		}
		if in.Error {
			rs.Errors++
		}
	}

	// 路径维度（限制条目数，避免无界增长）
	if in.Path != "" {
		ps := s.byPath[in.Path]
		if ps == nil {
			maxPaths := in.Cfg.MaxPaths
			if maxPaths <= 0 {
				maxPaths = 200
			}
			// 超过上限时按请求数淘汰最冷门的，避免内存无限增长
			if len(s.byPath) >= maxPaths {
				s.evictColdestPath()
			}
			ps = &pathStat{Path: in.Path}
			s.byPath[in.Path] = ps
		}
		ps.Requests++
		if in.BytesOut > 0 {
			ps.BytesOut += uint64(in.BytesOut)
		}
		ps.Latency += in.Elapsed
	}

	// 按小时
	hr := now.Truncate(time.Hour).Unix()
	idx := int(now.Hour())
	if s.hourly[idx].Hour != hr {
		s.hourly[idx] = hourBucket{Hour: hr, Requests: 0}
	}
	s.hourly[idx].Requests++

	// 慢请求
	thresh := in.Cfg.SlowThreshMS
	if thresh <= 0 {
		thresh = 500
	}
	if in.Elapsed.Milliseconds() >= thresh {
		maxSlow := in.Cfg.MaxSlow
		if maxSlow <= 0 {
			maxSlow = 50
		}
		s.slow = append(s.slow, SlowReq{
			Time:     now.Format("2006-01-02 15:04:05"),
			Method:   in.Method,
			Path:     in.Path,
			Status:   in.Status,
			Elapsed:  in.Elapsed.Milliseconds(),
			BytesOut: in.BytesOut,
			Backend:  in.Backend,
		})
		if len(s.slow) > maxSlow {
			s.slow = s.slow[len(s.slow)-maxSlow:]
		}
	}
}

// evictColdestPath 淘汰请求数最少的路径条目，保持内存有界。
func (s *Stats) evictColdestPath() {
	var coldest string
	var min uint64 = ^uint64(0)
	for p, st := range s.byPath {
		if st.Requests < min {
			min = st.Requests
			coldest = p
		}
	}
	if coldest != "" {
		delete(s.byPath, coldest)
	}
}

// StatsSnapshot 对外输出的快照（可直接 JSON 序列化）。
type StatsSnapshot struct {
	Requests   uint64  `json:"requests"`
	BytesIn    uint64  `json:"bytesIn"`
	BytesOut   uint64  `json:"bytesOut"`
	Status2xx  uint64  `json:"status2xx"`
	Status3xx  uint64  `json:"status3xx"`
	Status4xx  uint64  `json:"status4xx"`
	Status5xx  uint64  `json:"status5xx"`
	Blocked    uint64  `json:"blocked"`
	Redirected uint64  `json:"redirected"`
	Errors     uint64  `json:"errors"`
	AvgMs      float64 `json:"avgMs"`
	QPS        float64 `json:"qps"`
	StartAt    string  `json:"startAt"`
	LastAt     string  `json:"lastAt"`
	LastPath   string  `json:"lastPath"`
	UptimeSec  int64   `json:"uptimeSec"`

	ByRule   []RuleStats  `json:"byRule"`
	TopPaths []PathStats  `json:"topPaths"`
	Statuses []StatusCnt  `json:"statuses"`
	Hourly   []HourBucket `json:"hourly"`
	Slow     []SlowReq    `json:"slow"`
}

type RuleStats struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Requests uint64 `json:"requests"`
	BytesIn  uint64 `json:"bytesIn"`
	BytesOut uint64 `json:"bytesOut"`
	Errors   uint64 `json:"errors"`
}

type PathStats struct {
	Path     string  `json:"path"`
	Requests uint64  `json:"requests"`
	BytesOut uint64  `json:"bytesOut"`
	AvgMs    float64 `json:"avgMs"`
}

type StatusCnt struct {
	Code  int    `json:"code"`
	Count uint64 `json:"count"`
}

type HourBucket struct {
	Hour     string `json:"hour"`
	Requests uint64 `json:"requests"`
}

// Snapshot 生成统计快照。
func (s *Stats) Snapshot(topN int) StatsSnapshot {
	s.mu.Lock()
	defer s.mu.Unlock()
	if topN <= 0 {
		topN = 10
	}

	snap := StatsSnapshot{
		Requests: s.Requests, BytesIn: s.BytesIn, BytesOut: s.BytesOut,
		Status2xx: s.Status2xx, Status3xx: s.Status3xx,
		Status4xx: s.Status4xx, Status5xx: s.Status5xx,
		Blocked: s.Blocked, Redirected: s.Redirected, Errors: s.Errors,
		StartAt:  s.StartAt.Format("2006-01-02 15:04:05"),
		LastPath: s.LastPath,
	}
	if !s.LastAt.IsZero() {
		snap.LastAt = s.LastAt.Format("2006-01-02 15:04:05")
	}
	snap.UptimeSec = int64(time.Since(s.StartAt).Seconds())
	if s.DurCount > 0 {
		snap.AvgMs = float64(s.TotalDuration.Milliseconds()) / float64(s.DurCount)
	}
	if snap.UptimeSec > 0 {
		snap.QPS = float64(s.Requests) / float64(snap.UptimeSec)
	}

	// 子规则
	rules := make([]RuleStats, 0, len(s.byRule))
	for id, rs := range s.byRule {
		rules = append(rules, RuleStats{ID: id, Name: rs.Name, Requests: rs.Requests,
			BytesIn: rs.BytesIn, BytesOut: rs.BytesOut, Errors: rs.Errors})
	}
	sort.Slice(rules, func(i, j int) bool { return rules[i].Requests > rules[j].Requests })
	snap.ByRule = rules

	// 热门路径
	paths := make([]PathStats, 0, len(s.byPath))
	for _, ps := range s.byPath {
		avg := 0.0
		if ps.Requests > 0 {
			avg = float64(ps.Latency.Milliseconds()) / float64(ps.Requests)
		}
		paths = append(paths, PathStats{Path: ps.Path, Requests: ps.Requests, BytesOut: ps.BytesOut, AvgMs: avg})
	}
	sort.Slice(paths, func(i, j int) bool { return paths[i].Requests > paths[j].Requests })
	if len(paths) > topN {
		paths = paths[:topN]
	}
	snap.TopPaths = paths

	// 状态码
	for code, cnt := range s.byStatus {
		snap.Statuses = append(snap.Statuses, StatusCnt{Code: code, Count: cnt})
	}
	sort.Slice(snap.Statuses, func(i, j int) bool { return snap.Statuses[i].Code < snap.Statuses[j].Code })

	// 近 24 小时（按时间正序）
	for off := 23; off >= 0; off-- {
		t := time.Now().Add(-time.Duration(off) * time.Hour)
		idx := t.Hour()
		h := s.hourly[idx]
		cnt := uint64(0)
		// 只统计同一小时的桶，避免跨天污染
		if h.Hour == t.Truncate(time.Hour).Unix() {
			cnt = h.Requests
		}
		snap.Hourly = append(snap.Hourly, HourBucket{Hour: t.Format("01-02 15:00"), Requests: cnt})
	}

	// 慢请求（最近在前）
	slow := make([]SlowReq, len(s.slow))
	copy(slow, s.slow)
	for i, j := 0, len(slow)-1; i < j; i, j = i+1, j-1 {
		slow[i], slow[j] = slow[j], slow[i]
	}
	snap.Slow = slow

	return snap
}

// Reset 清零统计。
func (s *Stats) Reset() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.Requests, s.BytesIn, s.BytesOut = 0, 0, 0
	s.Status2xx, s.Status3xx, s.Status4xx, s.Status5xx = 0, 0, 0, 0
	s.Blocked, s.Redirected, s.Errors = 0, 0, 0
	s.TotalDuration, s.DurCount = 0, 0
	s.byRule = map[string]*ruleStat{}
	s.byPath = map[string]*pathStat{}
	s.byStatus = map[int]uint64{}
	s.hourly = [24]hourBucket{}
	s.slow = nil
	s.StartAt = time.Now()
	s.LastAt = time.Time{}
	s.LastPath = ""
}
