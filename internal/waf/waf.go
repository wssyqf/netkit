// Package waf 基于 Coraza v3 的 Web 应用防火墙封装，规则集与模式可运行时配置。
package waf

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	coraza "github.com/corazawaf/coraza/v3"
	"github.com/corazawaf/coraza/v3/types"

	"netkit/internal/config"
	"netkit/internal/geoip"
	"netkit/internal/ipvisitors"
	"netkit/internal/logcenter"
)

// ruleSet 一条内置规则集的元数据。
type ruleSet struct {
	Key  string
	Name string
	Desc string
	Rule string // SecRule 语句
	Get  func(config.WAFRulesets) bool
}

var ruleSets = []ruleSet{
	{
		Key: "sqli", Name: "SQL 注入防护", Desc: "使用 libinjection 检测 SQL 注入语句",
		Get:  func(r config.WAFRulesets) bool { return r.SQLi },
		Rule: `SecRule ARGS|REQUEST_URI|REQUEST_BODY "@detectSQLi" "id:1001,phase:2,deny,status:403,log,msg:'SQL注入攻击'"`,
	},
	{
		Key: "xss", Name: "XSS 跨站脚本防护", Desc: "使用 libinjection 检测 XSS 攻击载荷",
		Get:  func(r config.WAFRulesets) bool { return r.XSS },
		Rule: `SecRule ARGS|REQUEST_URI|REQUEST_BODY "@detectXSS" "id:1002,phase:2,deny,status:403,log,msg:'XSS攻击'"`,
	},
	{
		Key: "pathTraversal", Name: "路径穿越防护", Desc: "拦截 ../ 及多重编码/反斜杠绕过形式的目录穿越",
		Get:  func(r config.WAFRulesets) bool { return r.PathTraversal },
		// 穿越对：字面 `..` 或 2+ 连续的编码 %2e/%252e/%25252e；分隔符：/ \ 或 %2f/%5c/%252f 等编码
		// 形式（编码前缀是 % 后接 0-2 个 25，如 %2e= 0 个、%252e=1 个、%25252e=2 个）
		Rule: `SecRule REQUEST_URI|REQUEST_BODY "@rx (?i)(((\.\.)|(%(25){0,2}2e){2,})((/|\\)|%(25){0,2}(2f|5c)))|(/etc/(passwd|shadow))|(/proc/self/environ)" "id:1003,phase:2,deny,status:403,log,msg:'路径穿越攻击'"`,
	},
	{
		Key: "sensitiveFile", Name: "敏感文件探测防护", Desc: "拦截 .git/.env/passwd 等敏感文件访问",
		Get:  func(r config.WAFRulesets) bool { return r.SensitiveFile },
		Rule: `SecRule REQUEST_URI "(?i)(/\.git/|/\.env$|/\.htaccess|/\.aws/credentials|/etc/passwd|/\.svn/|web\.config$)" "id:1004,phase:1,deny,status:403,log,msg:'敏感文件探测'"`,
	},
	{
		Key: "exploitPath", Name: "漏洞利用路径防护", Desc: "拦截 phpMyAdmin/actuator/phpunit 等常见利用路径",
		Get:  func(r config.WAFRulesets) bool { return r.ExploitPath },
		Rule: `SecRule REQUEST_URI "(?i)(phpMyAdmin|/actuator/|/cgi-bin/|/vendor/phpunit|/solr/|/console/|/jmx-console)" "id:1005,phase:1,deny,status:403,log,msg:'漏洞利用扫描'"`,
	},
	{
		Key: "scannerUA", Name: "恶意扫描器 UA 防护", Desc: "拦截 sqlmap/nikto/nmap 等扫描工具（词边界，避免 nmap-monitor 类误拦）",
		Get:  func(r config.WAFRulesets) bool { return r.ScannerUA },
		// 词 + 界定符（/ 空格 ; : 或结尾）：命中 "Nikto/2.1.6"、"sqlmap/1.7.2"，不命中 "nmap-monitor"
		Rule: `SecRule REQUEST_HEADERS:User-Agent "(?i)(sqlmap|nikto|nmap|masscan|acunetix|nessus|dirbuster|wpscan|havij|zgrab|nuclei|w3af|arachni|hydra)(/|[\s;:]|$)" "id:1006,phase:1,deny,status:403,log,msg:'恶意扫描器UA'"`,
	},
	{
		Key: "badBot", Name: "恶意爬虫防护", Desc: "拦截常见垃圾爬虫与采集器标识",
		Get:  func(r config.WAFRulesets) bool { return r.BadBot },
		Rule: `SecRule REQUEST_HEADERS:User-Agent "(?i)(semrushbot|ahrefsbot|mj12bot|dotbot|petalbot|bytespider|gptbot|ccbot|scrapy)(/|[\s;:]|$)" "id:1007,phase:1,deny,status:403,log,msg:'恶意爬虫'"`,
	},
	{
		Key: "cmdi", Name: "命令注入防护", Desc: "拦截 ; | && ` $( /bin/sh -c 后接系统命令等注入特征",
		Get:  func(r config.WAFRulesets) bool { return r.CmdInjection },
		// 分隔符(分号/管道/&&/反引号/子shell) + 可选绝对路径 + 常见系统命令词，或 /bin/sh -c 形式
		Rule: `SecRule ARGS|REQUEST_URI|REQUEST_BODY "@rx (?i)(;|\||&&|\$\(|\x60)\s*(/usr/bin/|/bin/)?(cat|id|whoami|uname|wget|curl|nc|ncat|netcat|bash|sh|zsh|python[0-9.]*|perl|ruby|powershell|pwsh|chmod|chown|rm|mv|cp|kill|ping|ifconfig|netstat|ps|env|printenv|base64|eval|exec)\b|/(usr/)?bin/(sh|bash|zsh|dash)\s+-c" "id:1008,phase:2,deny,status:403,log,msg:'命令注入攻击'"`,
	},
}

// RuleSetInfo 供后台展示的规则集信息。
type RuleSetInfo struct {
	Key  string `json:"key"`
	Name string `json:"name"`
	Desc string `json:"desc"`
	On   bool   `json:"on"`
}

// Hit 一次 WAF 命中记录。
type Hit struct {
	Time   string `json:"time"`
	RuleID int    `json:"ruleID"`
	Msg    string `json:"msg"`
	URI    string `json:"uri"`
	Method string `json:"method"`
	IP     string `json:"ip"`
	Geo    string `json:"geo"`             // 命中 IP 的国家码（addHit 时填充）
	Action string `json:"action"` // deny / detect
}

// Manager WAF 引擎管理器。
type Manager struct {
	mu      sync.RWMutex
	engine  coraza.WAF
	cfg     config.WAFConfig
	initErr error
	hits    []Hit
	maxHits int
	stats   map[string]int // 规则集 -> 命中次数

	// 频率限制（固定窗口，每 IP 每分钟）
	rateMu sync.Mutex
	wins   map[string]*rateWin
}

// rateWin 单个 IP 的当前分钟窗口计数。
type rateWin struct {
	minute int64 // unix 分钟
	count  int
	logged bool // 本窗口是否已记过 hit（防刷日志）
}

var defaultMgr = newManager()

// Default 返回 WAF 单例。
func Default() *Manager { return defaultMgr }

func newManager() *Manager {
	m := &Manager{maxHits: 500, stats: map[string]int{}, wins: map[string]*rateWin{}}
	m.cfg = config.WAFConfig{
		Enabled: true, Mode: "block",
		Rulesets: config.WAFRulesets{
			SQLi: true, XSS: true, PathTraversal: true,
			SensitiveFile: true, ExploitPath: true, ScannerUA: true, BadBot: false,
			CmdInjection: true,
		},
		MaxBodyKB: 128,
	}
	if err := m.rebuild(); err != nil {
		m.initErr = err
	}
	return m
}

// Enabled 引擎是否就绪。
func (m *Manager) Enabled() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.engine != nil
}

// InitError 初始化错误。
func (m *Manager) InitError() error {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.initErr
}

// Config 当前配置。
func (m *Manager) Config() config.WAFConfig {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.cfg
}

// Apply 应用新配置并重建引擎。
func (m *Manager) Apply(c config.WAFConfig) error {
	m.mu.Lock()
	m.cfg = c
	m.mu.Unlock()
	return m.rebuild()
}

// RuleSets 返回内置规则集清单及启用状态。
func (m *Manager) RuleSets() []RuleSetInfo {
	c := m.Config()
	out := make([]RuleSetInfo, 0, len(ruleSets))
	for _, rs := range ruleSets {
		out = append(out, RuleSetInfo{Key: rs.Key, Name: rs.Name, Desc: rs.Desc, On: rs.Get(c.Rulesets)})
	}
	return out
}

// buildDirectives 按配置生成 Coraza 指令集。
func buildDirectives(c config.WAFConfig) string {
	engineMode := "On"
	if !c.Enabled {
		engineMode = "Off"
	} else if c.Mode == "detect" {
		engineMode = "DetectionOnly"
	}
	maxBody := c.MaxBodyKB
	if maxBody <= 0 {
		maxBody = 128
	}

	var sb strings.Builder
	fmt.Fprintf(&sb, "SecRuleEngine %s\n", engineMode)
	fmt.Fprintf(&sb, "SecRequestBodyAccess On\n")
	fmt.Fprintf(&sb, "SecResponseBodyAccess Off\n")
	fmt.Fprintf(&sb, "SecRequestBodyLimit %d\n", maxBody*1024*1024)
	fmt.Fprintf(&sb, "SecRequestBodyNoFilesLimit %d\n", maxBody*1024)
	// 请求体处理器选择（phase:1 前置）：Coraza 仅对 URLENCODED/MULTIPART 按 Content-Type
	// 自动选处理器，JSON 必须用 ctl 强制，未知/缺失类型用 RAW（写入 REQUEST_BODY），
	// 否则 phase:2 规则只能看到 ARGS，JSON/纯文本请求体里的攻击载荷会整体漏拦。
	sb.WriteString("SecRule REQUEST_HEADERS:Content-Type \"@rx (?i)^\\s*application/json\" \"id:9901,phase:1,pass,nolog,ctl:requestBodyProcessor=JSON\"\n")
	sb.WriteString("SecRule REQUEST_HEADERS:Content-Type \"!@rx (?i)^\\s*(application/x-www-form-urlencoded|multipart/form-data|application/json|text/xml|application/xml)\" \"id:9902,phase:1,pass,nolog,ctl:requestBodyProcessor=RAW\"\n")
	sb.WriteString("SecRule &REQUEST_HEADERS:Content-Type \"@eq 0\" \"id:9903,phase:1,pass,nolog,ctl:requestBodyProcessor=RAW\"\n")
	sb.WriteString("\n")

	for _, rs := range ruleSets {
		if rs.Get(c.Rulesets) {
			sb.WriteString(rs.Rule)
			sb.WriteString("\n")
		}
	}
	if strings.TrimSpace(c.RemoteRules) != "" {
		sb.WriteString("\n# 远程规则源（自动更新）\n")
		sb.WriteString(c.RemoteRules)
		sb.WriteString("\n")
	}
	if strings.TrimSpace(c.ExtraRules) != "" {
		sb.WriteString("\n# 自定义规则\n")
		sb.WriteString(c.ExtraRules)
		sb.WriteString("\n")
	}
	return sb.String()
}

// FetchRemoteRules 从 URL 下载兼容 Coraza 语法的规则文件（上限 4MB）。
func FetchRemoteRules(rawURL string) (string, error) {
	rawURL = strings.TrimSpace(rawURL)
	if rawURL == "" {
		return "", fmt.Errorf("规则源地址为空")
	}
	u, err := url.Parse(rawURL)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") {
		return "", fmt.Errorf("规则源地址无效，仅支持 http/https")
	}
	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Get(rawURL)
	if err != nil {
		return "", fmt.Errorf("拉取规则失败: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("拉取规则失败: HTTP %d", resp.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return "", fmt.Errorf("读取规则失败: %w", err)
	}
	if len(data) >= 4<<20 {
		return "", fmt.Errorf("规则文件超过 4MB 上限")
	}
	rules := strings.TrimSpace(string(data))
	if rules == "" {
		return "", fmt.Errorf("规则文件内容为空")
	}
	return rules, nil
}

// ValidateRemoteRules 用远程规则试建引擎，校验其 Coraza 语法。
func ValidateRemoteRules(c config.WAFConfig, remote string) error {
	c.RemoteRules = remote
	_, err := coraza.NewWAF(coraza.NewWAFConfig().WithDirectives(buildDirectives(c)))
	if err != nil {
		return fmt.Errorf("规则语法校验失败: %w", err)
	}
	return nil
}

// rebuild 按当前配置重建引擎。
func (m *Manager) rebuild() error {
	m.mu.RLock()
	c := m.cfg
	m.mu.RUnlock()

	directives := buildDirectives(c)
	w, err := coraza.NewWAF(coraza.NewWAFConfig().WithDirectives(directives))
	m.mu.Lock()
	defer m.mu.Unlock()
	if err != nil {
		m.engine = nil
		m.initErr = err
		return err
	}
	m.engine = w
	m.initErr = nil
	return nil
}

// WrapHandler 用 WAF 包装 HTTP 处理器，自行处理请求以便拿到命中详情并记日志。
func (m *Manager) WrapHandler(h http.Handler) (http.Handler, error) {
	// 启动时校验一次，避免配置错误静默失效
	m.mu.RLock()
	initErr := m.initErr
	hasEngine := m.engine != nil
	m.mu.RUnlock()
	if initErr != nil {
		return nil, fmt.Errorf("WAF 引擎初始化失败: %w", initErr)
	}
	if !hasEngine {
		return nil, fmt.Errorf("WAF 引擎未初始化")
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// 每次请求取当前引擎与配置，保证后台改配置后立即生效
		m.mu.RLock()
		engine := m.engine
		cfg := m.cfg
		m.mu.RUnlock()
		if engine == nil || !cfg.Enabled {
			h.ServeHTTP(w, r)
			return
		}
		// 对端在可信名单内才采信 XFF，否则直接用对端地址（防伪造）
		ip := clientIP(r, cfg.TrustedIPs)
		// 信任 IP 跳过检测
		if peerIn(ip, cfg.TrustedIPs) {
			h.ServeHTTP(w, r)
			return
		}

		// 频率限制：每 IP 每分钟上限（rateLimit>0 时启用），block 模式返回 429
		if rl := cfg.RateLimit; rl > 0 {
			if over, first := m.rateCheck(ip, rl); over {
				if first {
					deny := cfg.Mode != "detect"
					m.addHit(Hit{
						Time: nowStr(), RuleID: 0,
						Msg:    "频率限制：单IP每分钟超过" + itoa(rl) + "次",
						URI:    r.URL.RequestURI(), Method: r.Method, IP: ip,
						Action: map[bool]string{true: "deny", false: "detect"}[deny],
					})
					logcenter.Default().Add("WAF", logcenter.LevelWarn, "%s %s 来自 %s — %s",
						map[bool]string{true: "拦截", false: "仅记录"}[deny],
						r.Method, r.URL.RequestURI(), ip)
				}
				if cfg.Mode != "detect" {
					w.Header().Set("X-Blocked-By", "NetKit-WAF")
					w.Header().Set("X-Block-Reason", url.QueryEscape("频率限制"))
					w.WriteHeader(http.StatusTooManyRequests)
					return
				}
			}
		}

		tx := engine.NewTransaction()
		defer tx.Close()

		host, port := splitHostPort(r.Host)
		tx.ProcessConnection(ip, 0, host, port)
		tx.ProcessURI(r.URL.RequestURI(), r.Method, r.Proto)
		for k, vs := range r.Header {
			for _, v := range vs {
				tx.AddRequestHeader(k, v)
			}
		}
		if r.Host != "" {
			tx.AddRequestHeader("Host", r.Host)
			tx.SetServerName(r.Host)
		}

		// 阶段 1-2：请求头
		if it := tx.ProcessRequestHeaders(); it != nil {
			m.handleInterruption(it, w, r, ip, cfg)
			return
		}
		// 阶段 2：请求体。
		// 注意：phase:2 的规则（SQLi/XSS 等）必须调用 ProcessRequestBody 才会执行，
		// 即使 GET 没有 body 也要调用，否则这部分规则完全不生效。
		// 关键：读到的 body 必须用 WriteRequestBody 写入 tx——Coraza 只对内部
		// body 缓冲做检测，不写入则表单/JSON 请求体里的攻击载荷会被整体漏掉。
		// 检测只读前 maxBodyKB 字节，但转发必须是完整请求体（replayBody：
		// 已读检测段 + 底层剩余流），否则超过上限的上传会被截断，上游收不全
		// 导致 Content-Length 不匹配、连接重置或 502。
		limit := int64(maxBodyBytes(cfg))
		if limit < 1 {
			limit = 1
		}
		buf := make([]byte, limit)
		n, readErr := io.ReadFull(r.Body, buf)
		body := buf[:n]
		r.Body = &replayBody{Reader: io.MultiReader(bytes.NewReader(body), r.Body), rc: r.Body}
		if readErr == nil || readErr == io.EOF || readErr == io.ErrUnexpectedEOF {
			if len(body) > 0 && tx.IsRequestBodyAccessible() {
				if it, _, err := tx.WriteRequestBody(body); err != nil {
					m.logHit(ip, r, 0, "请求体写入失败："+err.Error(), "error")
				} else if it != nil {
					m.handleInterruption(it, w, r, ip, cfg)
					return
				}
			}
			if it, err := tx.ProcessRequestBody(); err != nil {
				m.logHit(ip, r, 0, "请求体解析失败："+err.Error(), "error")
			} else if it != nil {
				m.handleInterruption(it, w, r, ip, cfg)
				return
			}
		}
		// 其它读取错误（客户端中断等）：跳过检测直接放行，透传已读数据

		// detect 模式下 Coraza 不会返回 interruption，命中信息在 MatchedRules 中，
		// 需要单独读取并记录，否则"仅记录模式"什么都不会记。
		if cfg.Mode == "detect" {
			for _, mr := range tx.MatchedRules() {
				ruleID := 0
				if mr.Rule() != nil {
					ruleID = mr.Rule().ID()
				}
				msg := "命中规则 " + itoa(ruleID)
				if mr.Message() != "" {
					msg = mr.Message()
				}
				m.addHit(Hit{
					Time: nowStr(), RuleID: ruleID, Msg: msg,
					URI: r.URL.RequestURI(), Method: r.Method, IP: ip, Action: "detect",
				})
				logcenter.Default().Add("WAF", logcenter.LevelWarn,
					"仅记录 %s %s 来自 %s — %s", r.Method, r.URL.RequestURI(), ip, msg)
			}
		}

		// 阶段 3-4
		tx.ProcessLogging()
		h.ServeHTTP(w, r)
	}), nil
}

// handleInterruption 处理命中的拦截动作：按模式记录并决定是否阻断。
func (m *Manager) handleInterruption(it *types.Interruption, w http.ResponseWriter, r *http.Request, ip string, cfg config.WAFConfig) {
	msg := describeInterruption(it)
	deny := isDeny(it) && cfg.Mode != "detect"

	level := "warn"
	action := "detect"
	if deny {
		action = "deny"
		level = "error"
	}

	m.addHit(Hit{
		Time:   nowStr(),
		RuleID: it.RuleID,
		Msg:    msg,
		URI:    r.URL.RequestURI(),
		Method: r.Method,
		IP:     ip,
		Action: action,
	})
	logcenter.Default().Add("WAF", level, "%s %s %s 来自 %s — %s",
		map[bool]string{true: "拦截", false: "仅记录"}[deny], r.Method, r.URL.RequestURI(), ip, msg)

	if deny {
		w.Header().Set("X-Blocked-By", "NetKit-WAF")
		w.Header().Set("X-Block-Reason", url.QueryEscape(msg))
		w.WriteHeader(http.StatusForbidden)
	}
}

// logHit 记录一条非中断类的 WAF 事件。
func (m *Manager) logHit(ip string, r *http.Request, ruleID int, msg, level string) {
	m.addHit(Hit{Time: nowStr(), RuleID: ruleID, Msg: msg,
		URI: r.URL.RequestURI(), Method: r.Method, IP: ip, Action: "error"})
	logcenter.Default().Add("WAF", logcenter.LevelError, "%s %s 来自 %s — %s", r.Method, r.URL.RequestURI(), ip, msg)
}

// rateCheck 频率检查（固定窗口，每 IP 每分钟）。返回 (是否超限, 是否本窗口首次超限)。
func (m *Manager) rateCheck(ip string, limit int) (over bool, first bool) {
	m.rateMu.Lock()
	defer m.rateMu.Unlock()
	nowMin := time.Now().Unix() / 60
	if len(m.wins) > 4096 { // 防 map 无界增长：顺带清理过期窗口
		for k, w := range m.wins {
			if w.minute != nowMin {
				delete(m.wins, k)
			}
		}
	}
	w := m.wins[ip]
	if w == nil || w.minute != nowMin {
		m.wins[ip] = &rateWin{minute: nowMin, count: 1}
		return false, false
	}
	w.count++
	if w.count > limit {
		if !w.logged {
			w.logged = true
			return true, true
		}
		return true, false
	}
	return false, false
}

// replayBody 检测读取部分请求体后仍完整转发：已读字节 + 底层剩余流。
type replayBody struct {
	io.Reader
	rc io.Closer
}

func (b *replayBody) Close() error { return b.rc.Close() }

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	neg := n < 0
	if neg {
		n = -n
	}
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		b[i] = '-'
	}
	return string(b[i:])
}

func maxBodyBytes(c config.WAFConfig) int {
	kb := c.MaxBodyKB
	if kb <= 0 {
		kb = 128
	}
	return kb * 1024
}

func splitHostPort(host string) (string, int) {
	if h, p, err := net.SplitHostPort(host); err == nil {
		if port, err := strconv.Atoi(p); err == nil {
			return h, port
		}
		return h, 80
	}
	return host, 80
}

func (m *Manager) addHit(h Hit) {
	if h.Geo == "" {
		h.Geo = geoip.Country(h.IP)
	}
	ipvisitors.Default().Record(h.IP, "WAF")
	m.mu.Lock()
	defer m.mu.Unlock()
	m.hits = append(m.hits, h)
	if len(m.hits) > m.maxHits {
		m.hits = m.hits[len(m.hits)-m.maxHits:]
	}
}

// AddHit 外部（如 Coraza 日志回调）记录命中。
func (m *Manager) AddHit(h Hit) { m.addHit(h) }

// Hits 返回命中记录（倒序）。
func (m *Manager) Hits(limit int) []Hit {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]Hit, 0, limit)
	for i := len(m.hits) - 1; i >= 0 && len(out) < limit; i-- {
		out = append(out, m.hits[i])
	}
	return out
}

// ClearHits 清空命中记录。
func (m *Manager) ClearHits() {
	m.mu.Lock()
	m.hits = nil
	m.stats = map[string]int{}
	m.mu.Unlock()
}

// Test 用一条构造请求试跑规则，返回是否被拦截。
func (m *Manager) Test(uri, ua string) (bool, string) {
	m.mu.RLock()
	engine := m.engine
	m.mu.RUnlock()
	if engine == nil {
		return false, "WAF 引擎未初始化"
	}
	tx := engine.NewTransaction()
	defer tx.Close()

	tx.ProcessConnection("127.0.0.1", 12345, "127.0.0.1", 80)
	tx.ProcessURI(uri, "GET", "HTTP/1.1")
	if ua != "" {
		tx.AddRequestHeader("User-Agent", ua)
	}
	tx.AddRequestHeader("Host", "localhost")
	if it := tx.ProcessRequestHeaders(); it != nil {
		return isDeny(it), describeInterruption(it)
	}
	if it, err := tx.ProcessRequestBody(); err != nil {
		return false, err.Error()
	} else if it != nil {
		return isDeny(it), describeInterruption(it)
	}
	return false, "未命中任何规则"
}

// isDeny 判断中断动作是否为拦截。
func isDeny(it *types.Interruption) bool {
	return it.Action == "deny" || it.Action == "drop"
}

func describeInterruption(it *types.Interruption) string {
	switch it.RuleID {
	case 1001:
		return "命中：SQL 注入攻击"
	case 1002:
		return "命中：XSS 攻击"
	case 1003:
		return "命中：路径穿越"
	case 1004:
		return "命中：敏感文件探测"
	case 1005:
		return "命中：漏洞利用路径"
	case 1006:
		return "命中：恶意扫描器 UA"
	case 1007:
		return "命中：恶意爬虫"
	}
	return fmt.Sprintf("命中规则 %d（%s）", it.RuleID, it.Action)
}
