package admin

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"log"
	"math"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"netkit/internal/acme"
	"netkit/internal/ai"
	"netkit/internal/config"
	"netkit/internal/cron"
	"netkit/internal/ddns"
	"netkit/internal/geoip"
	"netkit/internal/honeypot"
	"netkit/internal/ipvisitors"
	"netkit/internal/logcenter"
	"netkit/internal/portforward"
	"netkit/internal/reverseproxy"
	"netkit/internal/safe"
	"netkit/internal/totp"
	"netkit/internal/waf"
	"netkit/web"
)

// Server 管理后台：登录认证 + 各模块配置/日志 API + 静态页面。
type Server struct {
	store    *config.Store
	filter   func(ip string) bool // 后台访问的全局 IP 过滤
	wafGuard func(http.Handler) http.Handler
	mu       sync.Mutex
	sessions map[string]sessInfo
	startAt  time.Time
	mux      *http.ServeMux
}

// sessInfo 会话信息：过期时间 + 角色（admin 主账号 / backup 后备账号）。
type sessInfo struct {
	exp  time.Time
	role string
}

// SetFilter 设置后台访问的全局 IP 过滤函数。
func (s *Server) SetFilter(f func(ip string) bool) { s.filter = f }

// SetWAFGuard 设置后台自身的 WAF 包装器（可为 nil）。
func (s *Server) SetWAFGuard(g func(http.Handler) http.Handler) { s.wafGuard = g }

// Handler 返回带全局过滤的根处理器。
func (s *Server) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if s.filter != nil {
			ip, _, _ := net.SplitHostPort(r.RemoteAddr)
			if !s.filter(ip) {
				logcenter.Default().Add("后台", logcenter.LevelWarn, "全局IP过滤拦截 %s %s", ip, r.URL.Path)
				http.Error(w, "Forbidden", http.StatusForbidden)
				return
			}
		}
		if s.wafGuard != nil {
			s.wafGuard(s.mux).ServeHTTP(w, r)
			return
		}
		s.mux.ServeHTTP(w, r)
	})
}

func NewServer(store *config.Store) *Server {
	s := &Server{
		store:    store,
		sessions: map[string]sessInfo{},
		startAt:  time.Now(),
	}
	m := http.NewServeMux()
	m.HandleFunc("/api/login", s.handleLogin)
	m.HandleFunc("/api/logout", s.authAny(s.handleLogout))
	m.HandleFunc("/api/me", s.authAny(func(w http.ResponseWriter, r *http.Request) {
		role, _ := s.sessionRole(r)
		writeJSON(w, map[string]string{"role": role})
	}))
	m.HandleFunc("/api/status", s.auth(s.handleStatus))
	m.HandleFunc("/api/settings", s.auth(s.handleSettings))
	m.HandleFunc("/api/webhook/test", s.auth(s.handleWebhookTest))
	m.HandleFunc("/api/settings/webhook", s.auth(s.handleGlobalWebhook))
	m.HandleFunc("/api/groups", s.auth(s.handleGroups))
	m.HandleFunc("/api/backup", s.authAny(s.handleBackup))
	m.HandleFunc("/api/backup/list", s.authAny(s.handleBackupList))
	m.HandleFunc("/api/2fa/status", s.auth(s.handle2FAStatus))
	m.HandleFunc("/api/2fa/qrcode", s.auth(s.handle2FAQRRCode))
	m.HandleFunc("/api/2fa/setup", s.auth(s.handle2FASetup))
	m.HandleFunc("/api/2fa/enable", s.auth(s.handle2FAEnable))
	m.HandleFunc("/api/2fa/disable", s.auth(s.handle2FADisable))

	// AI 大模型维护（仅 admin，backup 账号经 s.auth 自动 403）
	ai.SetHealth(func() map[string]any {
		h := collectHealth()
		return map[string]any{"score": h.Score, "cpu": h.CPU, "mem": h.Mem}
	})
	ai.SetMeta("v0.3.0", s.startAt)
	m.HandleFunc("/api/ai/config", s.auth(s.handleAIConfig))
	m.HandleFunc("/api/ai/test", s.auth(s.handleAIConnTest))
	m.HandleFunc("/api/ai/checkup", s.auth(s.handleAICheckup))
	m.HandleFunc("/api/ai/chat", s.auth(s.handleAIChat))

	m.HandleFunc("/api/portforward", s.auth(moduleAPI(s, storePortForward)))
	m.HandleFunc("/api/portforward/logs", s.auth(s.handlePFLogs))
	m.HandleFunc("/api/portforward/status", s.auth(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, portforward.Default().Status())
	}))
	m.HandleFunc("/api/webrules", s.auth(moduleAPI(s, storeWebRule)))
	m.HandleFunc("/api/webrules/logs", s.auth(s.handleWebLogs))
	m.HandleFunc("/api/webrules/status", s.auth(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, reverseproxy.Default().Status())
	}))
	// 流量统计：?id=xxx 查单条，不带 id 返回全部；?sub=xxx 查该子规则的独立统计
	m.HandleFunc("/api/webrules/stats", s.auth(func(w http.ResponseWriter, r *http.Request) {
		id := r.URL.Query().Get("id")
		sub := r.URL.Query().Get("sub")
		topN := atoiDefault(r.URL.Query().Get("top"), 10)
		if id == "" {
			writeJSON(w, reverseproxy.Default().AllStats(topN))
			return
		}
		snap, ok := reverseproxy.Default().StatsOf(id, sub, topN)
		if !ok {
			jsonError(w, http.StatusNotFound, "规则/子规则未运行或不存在")
			return
		}
		writeJSON(w, snap)
	}))
	m.HandleFunc("/api/webrules/stats/reset", s.auth(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			jsonError(w, http.StatusMethodNotAllowed, "仅支持 POST")
			return
		}
		var req struct {
			ID  string `json:"id"`
			Sub string `json:"sub"`
		}
		json.NewDecoder(r.Body).Decode(&req)
		if !reverseproxy.Default().ResetStats(req.ID, req.Sub) {
			jsonError(w, http.StatusNotFound, "规则/子规则未运行或不存在")
			return
		}
		if req.Sub != "" {
			logcenter.Default().Add("Web服务", logcenter.LevelInfo, "已清零子规则 %s 的流量统计", req.Sub)
		} else {
			logcenter.Default().Add("Web服务", logcenter.LevelInfo, "已清零规则 %s 的流量统计", req.ID)
		}
		writeJSON(w, map[string]any{"ok": true})
	}))
	m.HandleFunc("/api/webrules/health", s.auth(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, reverseproxy.Default().HealthDetail())
	}))
	m.HandleFunc("/api/ddns", s.auth(moduleAPI(s, storeDDNS)))
	m.HandleFunc("/api/ddns/status", s.auth(s.handleDDNSStatus))
	m.HandleFunc("/api/ddns/logs", s.auth(func(w http.ResponseWriter, r *http.Request) {
		logs := ddns.Default().Logs(r.URL.Query().Get("id"))
		if logs == nil {
			logs = []string{}
		}
		writeJSON(w, logs)
	}))
	m.HandleFunc("/api/ddns/dnshe/domains", s.auth(func(w http.ResponseWriter, r *http.Request) {
		key := r.URL.Query().Get("key")
		secret := r.URL.Query().Get("secret")
		names, err := ddns.Default().ListDNSHEDomains(key, secret)
		if err != nil {
			jsonError(w, http.StatusBadRequest, err.Error())
			return
		}
		writeJSON(w, map[string]any{"domains": names, "count": len(names)})
	}))

	m.HandleFunc("/api/logcenter", s.auth(s.handleLogCenter))
	m.HandleFunc("/api/logcenter/modules", s.auth(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, logcenter.Default().Modules())
	}))

	m.HandleFunc("/api/ipdb", s.auth(moduleAPI(s, storeIPDB)))
	m.HandleFunc("/api/securitygroups", s.auth(moduleAPI(s, storeSecGroup)))
	m.HandleFunc("/api/ipfilter", s.auth(s.handleIPFilter))

	m.HandleFunc("/api/honeypot", s.auth(s.handleHoneypot))
	m.HandleFunc("/api/honeypot/logs", s.auth(s.handleHoneypotLogs))
	m.HandleFunc("/api/ipvisitors", s.auth(s.handleIPVisitors))

	m.HandleFunc("/api/crons", s.auth(moduleAPI(s, storeCron)))
	m.HandleFunc("/api/crons/status", s.auth(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, cron.Default().Status())
	}))
	m.HandleFunc("/api/crons/logs", s.auth(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, cron.Default().Logs(r.URL.Query().Get("id")))
	}))
	m.HandleFunc("/api/crons/run", s.auth(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			ID string `json:"id"`
		}
		json.NewDecoder(r.Body).Decode(&req)
		if err := cron.Default().RunNow(req.ID); err != nil {
			jsonError(w, http.StatusBadRequest, err.Error())
			return
		}
		writeJSON(w, map[string]any{"ok": true})
	}))

	m.HandleFunc("/api/crons/system", s.auth(s.handleSystemCrons))

	m.HandleFunc("/api/sslcerts", s.auth(moduleAPI(s, storeSSLCert)))
	m.HandleFunc("/api/waf", s.auth(s.handleWAF))
	m.HandleFunc("/api/waf/update-rules", s.auth(s.handleWAFUpdateRules))
	m.HandleFunc("/api/waf/rulesets", s.auth(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, waf.Default().RuleSets())
	}))
	m.HandleFunc("/api/waf/hits", s.auth(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, waf.Default().Hits(atoiDefault(r.URL.Query().Get("limit"), 200)))
	}))
	m.HandleFunc("/api/waf/test", s.auth(s.handleWAFTest))
	m.HandleFunc("/api/sslcerts/logs", s.auth(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, acme.Default().Logs(r.URL.Query().Get("id")))
	}))
	m.HandleFunc("/api/sslcerts/running", s.auth(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, map[string]any{"running": acme.Default().IsRunning(r.URL.Query().Get("id"))})
	}))
	m.HandleFunc("/api/sslcerts/apply", s.auth(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			ID string `json:"id"`
		}
		json.NewDecoder(r.Body).Decode(&req)
		if err := acme.Default().Request(req.ID); err != nil {
			jsonError(w, http.StatusBadRequest, err.Error())
			return
		}
		writeJSON(w, map[string]any{"ok": true})
	}))

	m.HandleFunc("/", s.handleStatic)
	s.mux = m
	go s.loopWAFRuleUpdate()
	return s
}

// ---- 会话 ----

func (s *Server) newSession(role string) string {
	b := make([]byte, 16)
	rand.Read(b)
	tok := hex.EncodeToString(b)
	s.mu.Lock()
	s.sessions[tok] = sessInfo{exp: time.Now().Add(24 * time.Hour), role: role}
	s.mu.Unlock()
	return tok
}

// sessionRole 返回当前请求会话的角色（如未登录返回 ok=false）。
func (s *Server) sessionRole(r *http.Request) (role string, ok bool) {
	c, err := r.Cookie("netkit_session")
	if err != nil {
		return "", false
	}
	s.mu.Lock()
	si, found := s.sessions[c.Value]
	s.mu.Unlock()
	if !found || time.Now().After(si.exp) {
		return "", false
	}
	return si.role, true
}

func (s *Server) validSession(r *http.Request) bool {
	_, ok := s.sessionRole(r)
	return ok
}

// auth 仅主账号（admin）可用的接口包装；后备账号访问返回 403。
func (s *Server) auth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		role, ok := s.sessionRole(r)
		if !ok {
			jsonError(w, http.StatusUnauthorized, "未登录或会话已过期")
			return
		}
		if role == "backup" {
			jsonError(w, http.StatusForbidden, "后备账号仅可使用配置备份与还原")
			return
		}
		next(w, r)
	}
}

// authAny 任意已登录角色可用（登出、备份还原、身份查询）。
func (s *Server) authAny(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !s.validSession(r) {
			jsonError(w, http.StatusUnauthorized, "未登录或会话已过期")
			return
		}
		next(w, r)
	}
}

// ---- 登录/登出 ----

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		jsonError(w, http.StatusMethodNotAllowed, "仅支持 POST")
		return
	}
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
		Code     string `json:"code"`     // 2FA 验证码
		Recovery string `json:"recovery"` // 恢复码
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, http.StatusBadRequest, "请求格式错误")
		return
	}
	base := s.store.GetBase()
	isBackup := false
	switch {
	case req.Username == base.Username && req.Password == base.Password:
		// 主账号
	case base.BackupUsername != "" && base.BackupPassword != "" &&
		req.Username == base.BackupUsername && req.Password == base.BackupPassword:
		// 后备账号（仅备份与还原权限）
		isBackup = true
	default:
		log.Printf("[后台] 登录失败: %s 来自 %s", req.Username, r.RemoteAddr)
		ip, _, _ := net.SplitHostPort(r.RemoteAddr)
		logcenter.Default().Add("后台", logcenter.LevelWarn, "登录失败: %s 来自 %s", req.Username, ip)
		jsonError(w, http.StatusUnauthorized, "用户名或密码错误")
		return
	}

	// 2FA：密码正确后还需校验动态验证码，未通过时不建立会话
	if base.TFA.Enabled && base.TFA.Secret != "" {
		code := strings.TrimSpace(req.Code)
		recovery := strings.TrimSpace(req.Recovery)
		if code == "" && recovery == "" {
			// 密码已通过，提示前端进入第二步
			writeJSON(w, map[string]any{"need2FA": true})
			return
		}
		ok := false
		if recovery != "" {
			ok = s.consumeRecoveryCode(recovery)
			if !ok {
				ip, _, _ := net.SplitHostPort(r.RemoteAddr)
				logcenter.Default().Add("后台", logcenter.LevelWarn, "2FA 恢复码无效: %s", ip)
			}
		} else {
			win, matched := totp.MatchedWindow(base.TFA.Secret, code, time.Now())
			if matched {
				// 防重放：同一时间窗口的验证码只能用一次
				if base.TFA.LastUsedWindow != 0 && win <= base.TFA.LastUsedWindow {
					ok = false
					ip, _, _ := net.SplitHostPort(r.RemoteAddr)
					logcenter.Default().Add("后台", logcenter.LevelWarn, "2FA 验证码已使用过（疑似重放）: %s", ip)
				} else {
					ok = true
					s.store.Update(func(c *config.Config) { c.Base.TFA.LastUsedWindow = win })
				}
			}
		}
		if !ok {
			ip, _, _ := net.SplitHostPort(r.RemoteAddr)
			logcenter.Default().Add("后台", logcenter.LevelWarn, "2FA 验证失败: %s", ip)
			jsonError(w, http.StatusUnauthorized, "两步验证码错误或已过期")
			return
		}
	}

	ip, _, _ := net.SplitHostPort(r.RemoteAddr)
	who := req.Username
	role := "admin"
	if isBackup {
		who = "后备账号 " + req.Username
		role = "backup"
	}
	logcenter.Default().Add("后台", logcenter.LevelInfo, "用户 %s 登录成功 (来自 %s)", who, ip)
	http.SetCookie(w, &http.Cookie{
		Name: "netkit_session", Value: s.newSession(role),
		Path: "/", HttpOnly: true, SameSite: http.SameSiteLaxMode,
	})
	writeJSON(w, map[string]any{"ok": true, "role": role})
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie("netkit_session"); err == nil {
		s.mu.Lock()
		delete(s.sessions, c.Value)
		s.mu.Unlock()
	}
	writeJSON(w, map[string]any{"ok": true})
}

// ---- 状态 ----

func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	cfg := s.store.Get()
	pfStatus := portforward.Default().Status()
	pfRunning := 0
	for _, st := range pfStatus {
		if strings.HasPrefix(st, "运行中") {
			pfRunning++
		}
	}
	webRunning := len(reverseproxy.Default().Status())
	health := collectHealth()
	writeJSON(w, map[string]any{
		"health":       health,
		"version":      "v0.3.0",
		"uptime":       time.Since(s.startAt).Round(time.Second).String(),
		"portforward":  len(cfg.PortForwards),
		"pfRunning":    pfRunning,
		"webrules":     len(cfg.WebRules),
		"webRunning":   webRunning,
		"ddns":         len(cfg.DDNS),
		"ipdb":         len(cfg.IPDB),
		"secgroups":    len(cfg.SecurityGroups),
		"crons":        len(cfg.CronTasks),
		"sslcerts":     len(cfg.SSLCerts),
		"wafEnabled":   waf.Default().Enabled(),
		"wafMode":      waf.Default().Config().Mode,
		"wafHits":      len(waf.Default().Hits(1000)),
		"ipfilterMode": cfg.IPFilter.Mode,
		"adminPort":    cfg.Base.AdminPort,
		// 蜜罐诱捕与 IP 访客：总览卡片与数据大屏数据源
		"honeypotEnabled": cfg.Honeypot.Enabled,
		"honeypotPorts":   len(honeypot.Default().Status()),
		"honeypotRecs":    len(honeypot.Default().Records(2000)),
		"ipvisitors":      ipvisitors.Default().Count(),
	})
}

func (s *Server) handleSettings(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		base := s.store.GetBase()
		writeJSON(w, map[string]any{
			"username":       base.Username,
			"backupUsername": base.BackupUsername,
			"adminPort":      base.AdminPort,
			"configPath":     s.store.Path(),
		})
		return
	}
	if r.Method != http.MethodPost {
		jsonError(w, http.StatusMethodNotAllowed, "不支持的方法")
		return
	}
	var req struct {
		Username    string `json:"username"`
		OldPassword string `json:"oldPassword"`
		NewPassword string `json:"newPassword"`
		// 后备账号：显式传入才更新（空=禁用），密码非空时才更新
		BackupUsername *string `json:"backupUsername"`
		BackupPassword string  `json:"backupPassword"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, http.StatusBadRequest, "请求格式错误")
		return
	}
	// 禁止通过 Web API 修改账号密码（测试机锁定，只能通过直接编辑配置文件修改）
	if req.Username != "" || req.NewPassword != "" || req.BackupPassword != "" ||
		(req.BackupUsername != nil && *req.BackupUsername != "") {
		jsonError(w, http.StatusForbidden, "账号密码已锁定，不可通过界面修改")
		return
	}
	base := s.store.GetBase()
	if req.OldPassword != base.Password {
		jsonError(w, http.StatusBadRequest, "旧密码不正确")
		return
	}
	err := s.store.Update(func(c *config.Config) {
		// 账号密码字段已锁定，不通过 Web API 修改
	})
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "保存失败: "+err.Error())
		return
	}
	writeJSON(w, map[string]any{"ok": true})
}

// ---- 各模块配置 API：GET 读列表，POST 整体替换 ----

type moduleSpec[T any] struct {
	get   func(c *config.Config) *[]T
	apply func([]T)
	name  string
}

var storePortForward = moduleSpec[config.PortForwardRule]{
	name:  "端口转发",
	get:   func(c *config.Config) *[]config.PortForwardRule { return &c.PortForwards },
	apply: func(v []config.PortForwardRule) { portforward.Default().Apply(v) },
}

var storeWebRule = moduleSpec[config.WebRule]{
	name:  "Web服务",
	get:   func(c *config.Config) *[]config.WebRule { return &c.WebRules },
	apply: func(v []config.WebRule) { reverseproxy.Default().Apply(v) },
}

var storeDDNS = moduleSpec[config.DDNSTask]{
	name:  "动态域名",
	get:   func(c *config.Config) *[]config.DDNSTask { return &c.DDNS },
	apply: func(v []config.DDNSTask) { ddns.Default().Apply(v) },
}

var storeIPDB = moduleSpec[config.IPDBEntry]{
	name:  "IP地址库",
	get:   func(c *config.Config) *[]config.IPDBEntry { return &c.IPDB },
	apply: func(v []config.IPDBEntry) {},
}

var storeSecGroup = moduleSpec[config.SecurityGroup]{
	name:  "安全组",
	get:   func(c *config.Config) *[]config.SecurityGroup { return &c.SecurityGroups },
	apply: func(v []config.SecurityGroup) {},
}

var storeCron = moduleSpec[config.CronTask]{
	name:  "计划任务",
	get:   func(c *config.Config) *[]config.CronTask { return &c.CronTasks },
	apply: func(v []config.CronTask) { cron.Default().Apply(v) },
}

var storeSSLCert = moduleSpec[config.SSLCert]{
	name:  "证书",
	get:   func(c *config.Config) *[]config.SSLCert { return &c.SSLCerts },
	apply: func(v []config.SSLCert) {},
}

// handleLogCenter 日志中心查询 / 清空。
func (s *Server) handleLogCenter(w http.ResponseWriter, r *http.Request) {
	lc := logcenter.Default()
	switch r.Method {
	case http.MethodGet:
		q := r.URL.Query()
		writeJSON(w, lc.Query(q.Get("module"), q.Get("level"), q.Get("keyword"), atoiDefault(q.Get("limit"), 500)))
	case http.MethodDelete:
		lc.Clear()
		writeJSON(w, map[string]any{"ok": true})
	default:
		jsonError(w, http.StatusMethodNotAllowed, "不支持的方法")
	}
}

// ReservedPorts 汇总已被占用的端口（管理端口 + 端口转发监听 + Web 服务监听），
// 供蜜罐启动前做冲突预检。值为归属描述。
func ReservedPorts(cfg config.Config, adminPort int) map[int]string {
	out := map[int]string{}
	if adminPort > 0 {
		out[adminPort] = "管理后台端口"
	}
	for _, r := range cfg.PortForwards {
		if !r.Enabled {
			continue
		}
		for _, p := range r.ListenPorts {
			if _, ok := out[p]; !ok {
				out[p] = "端口转发规则[" + r.Name + "]"
			}
		}
	}
	for _, r := range cfg.WebRules {
		if !r.Enabled || r.Port <= 0 {
			continue
		}
		if _, ok := out[r.Port]; !ok {
			out[r.Port] = "Web服务[" + r.Name + "]"
		}
	}
	return out
}

// handleHoneypot 蜜罐配置读写。
func (s *Server) handleHoneypot(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		cfg := s.store.Get()
		// 状态里带上各端口的冲突/监听错误（running 之外的失败端口）
		writeJSON(w, map[string]any{
			"config":    cfg.Honeypot,
			"status":    honeypot.Default().Status(),
			"reserved":  ReservedPorts(cfg, cfg.Base.AdminPort),
			"services":  honeypot.Templates(),
			"geoStatus": geoip.Status(),
		})
	case http.MethodPost:
		var hc config.HoneypotConfig
		if err := json.NewDecoder(r.Body).Decode(&hc); err != nil {
			jsonError(w, http.StatusBadRequest, "请求格式错误")
			return
		}
		if err := s.store.Update(func(c *config.Config) { c.Honeypot = hc }); err != nil {
			jsonError(w, http.StatusInternalServerError, "保存失败: "+err.Error())
			return
		}
		cfg := s.store.Get()
		honeypot.Default().SetReservedPorts(ReservedPorts(cfg, cfg.Base.AdminPort))
		honeypot.Default().Apply(hc)
		logcenter.Default().Add("蜜罐", logcenter.LevelInfo, "配置已保存（启用=%v，诱饵端口 %d 个）", hc.Enabled, len(hc.Ports))
		writeJSON(w, map[string]any{"ok": true, "status": honeypot.Default().Status()})
	default:
		jsonError(w, http.StatusMethodNotAllowed, "不支持的方法")
	}
}

// handleHoneypotLogs 蜜罐诱捕记录：GET 读取，DELETE 清空。
func (s *Server) handleHoneypotLogs(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		limit := atoiDefault(r.URL.Query().Get("limit"), 200)
		writeJSON(w, map[string]any{
			"records": honeypot.Default().Records(limit),
			"logs":    honeypot.Default().Ring(),
		})
	case http.MethodDelete:
		honeypot.Default().Clear()
		writeJSON(w, map[string]any{"ok": true})
	default:
		jsonError(w, http.StatusMethodNotAllowed, "不支持的方法")
	}
}

// ipvRow 访客行 + 按当前全局过滤规则的判定标记。
type ipvRow struct {
	ipvisitors.Entry
	Allowed bool `json:"allowed"` // true=放行，false=拦截
}

// handleIPVisitors IP 访客列表（含地区与放行/拦截标记）。
func (s *Server) handleIPVisitors(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		q := r.URL.Query()
		cfg := s.store.Get()
		rows := ipvisitors.Default().Query(q.Get("cc"), q.Get("kw"), atoiDefault(q.Get("limit"), 500))
		list := make([]ipvRow, 0, len(rows))
		for _, e := range rows {
			list = append(list, ipvRow{Entry: e, Allowed: evalIPFilter(cfg, e.IP, false)})
		}
		writeJSON(w, map[string]any{
			"list":      list,
			"total":     ipvisitors.Default().Count(),
			"geoStatus": geoip.Status(),
		})
	case http.MethodDelete:
		ipvisitors.Default().Clear()
		writeJSON(w, map[string]any{"ok": true})
	default:
		jsonError(w, http.StatusMethodNotAllowed, "不支持的方法")
	}
}

// handleIPFilter 全局 IP 过滤配置。
func (s *Server) handleIPFilter(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		f := s.store.Get().IPFilter
		writeJSON(w, struct {
			config.GlobalIPFilter
			GeoStatus map[string]any `json:"geoStatus"`
		}{f, geoip.Status()})
	case http.MethodPost:
		var f config.GlobalIPFilter
		if err := json.NewDecoder(r.Body).Decode(&f); err != nil {
			jsonError(w, http.StatusBadRequest, "请求格式错误")
			return
		}
		if err := s.store.Update(func(c *config.Config) { c.IPFilter = f }); err != nil {
			jsonError(w, http.StatusInternalServerError, "保存失败: "+err.Error())
			return
		}
		writeJSON(w, map[string]any{"ok": true})
	default:
		jsonError(w, http.StatusMethodNotAllowed, "不支持的方法")
	}
}

func atoiDefault(s string, def int) int {
	n := 0
	for _, ch := range s {
		if ch < '0' || ch > '9' {
			return def
		}
		n = n*10 + int(ch-'0')
	}
	if n == 0 {
		return def
	}
	return n
}

// evalIPFilter 判定 IP 在当前全局 IP 过滤规则下是否放行（纯判定，不登记访客、不写日志）。
// withLog=true 时把拒绝原因写入日志中心（供真实过滤链路使用）。
func evalIPFilter(cfg config.Config, ip string, withLog bool) bool {
	f := cfg.IPFilter
	if ip == "127.0.0.1" || ip == "::1" {
		return true // 本机回环始终放行
	}
	// 区域（GeoIP 国家）过滤：独立于黑白名单生效，mode=none 时也生效
	if f.GeoMode != "" && len(f.GeoCountries) > 0 {
		cc := geoip.Country(ip)
		switch f.GeoMode {
		case "allow":
			// 放行白名单：仅名单内国家可访问，其余拦截；查不到国家（私网/未知）不拦截
			if cc == "" {
				break
			}
			if geoHit(f.GeoCountries, cc) {
				return true // 白名单国家直接放行，不再走黑白名单
			}
			if withLog {
				logcenter.Default().Add("IP过滤", logcenter.LevelWarn, "区域放行白名单拒绝 %s 国家=%s", ip, cc)
			}
			return false
		case "block":
			if cc != "" && geoHit(f.GeoCountries, cc) {
				if withLog {
					logcenter.Default().Add("IP过滤", logcenter.LevelWarn, "区域拦截 %s 国家=%s", ip, cc)
				}
				return false
			}
		case "detect":
			if cc != "" && geoHit(f.GeoCountries, cc) && withLog {
				logcenter.Default().Add("IP过滤", logcenter.LevelWarn, "区域命中(仅记录) %s 国家=%s", ip, cc)
			}
		}
	}
	if f.Mode == "" || f.Mode == "none" {
		return true
	}
	groups := safe.ResolveGroups(cfg.SecurityGroups, cfg.IPDB)
	var ips []string
	for _, gid := range f.GroupIDs {
		if g, ok := groups[gid]; ok {
			ips = append(ips, g.IPs...)
		}
	}
	return safe.CheckIP(f.Mode, ips, ip)
}

// BuildGlobalFilter 由当前配置组装全局 IP 过滤函数（登记访客并记录拒绝日志）。
func BuildGlobalFilter(store *config.Store) func(ip string) bool {
	return func(ip string) bool {
		cfg := store.Get()
		if ip == "127.0.0.1" || ip == "::1" {
			return true // 本机回环始终放行
		}
		ipvisitors.Default().Record(ip, "IP过滤")
		return evalIPFilter(cfg, ip, true)
	}
}

// geoHit 判断国家码是否命中拦截名单（大小写不敏感）。
func geoHit(list []string, cc string) bool {
	for _, c := range list {
		if strings.EqualFold(strings.TrimSpace(c), cc) {
			return true
		}
	}
	return false
}

func moduleAPI[T any](s *Server, m moduleSpec[T]) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			cfg := s.store.Get()
			list := *m.get(&cfg)
			if list == nil {
				var zero []T
				list = zero
			}
			writeJSON(w, list)
		case http.MethodPost:
			var list []T
			if err := json.NewDecoder(r.Body).Decode(&list); err != nil {
				jsonError(w, http.StatusBadRequest, "请求格式错误")
				return
			}
			if err := s.store.Update(func(c *config.Config) { *m.get(c) = list }); err != nil {
				jsonError(w, http.StatusInternalServerError, "保存失败: "+err.Error())
				return
			}
			m.apply(list)
			writeJSON(w, map[string]any{"ok": true})
		default:
			jsonError(w, http.StatusMethodNotAllowed, "不支持的方法")
		}
	}
}

func (s *Server) handlePFLogs(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, portforward.Default().Logs(r.URL.Query().Get("id")))
}

// 访问日志：?id= 规则ID，?sub= 子规则ID（非空时返回子规则的独立日志环）
func (s *Server) handleWebLogs(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, reverseproxy.Default().Logs(r.URL.Query().Get("id"), r.URL.Query().Get("sub")))
}

func (s *Server) handleDDNSStatus(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, ddns.Default().Status())
}

// ---- 静态页面 ----

func (s *Server) handleStatic(w http.ResponseWriter, r *http.Request) {
	if strings.HasPrefix(r.URL.Path, "/api/") {
		jsonError(w, http.StatusNotFound, "接口不存在")
		return
	}
	web.Handler().ServeHTTP(w, r)
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	json.NewEncoder(w).Encode(v)
}

func jsonError(w http.ResponseWriter, code int, msg string) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(map[string]string{"error": msg})
}

// handleWAF WAF 配置读写。
func (s *Server) handleWAF(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		cfg := s.store.Get()
		writeJSON(w, map[string]any{
			"config":   cfg.WAF,
			"engineOK": waf.Default().Enabled(),
			"initErr":  errString(waf.Default().InitError()),
			"ruleSets": waf.Default().RuleSets(),
		})
	case http.MethodPost:
		var c config.WAFConfig
		if err := json.NewDecoder(r.Body).Decode(&c); err != nil {
			jsonError(w, http.StatusBadRequest, "请求格式错误")
			return
		}
		// 远程规则内容与更新时间由 /api/waf/update-rules 维护，
		// 前端整体保存时不携带这三个字段，此处保留旧值防止被清空。
		old := s.store.Get().WAF
		c.RemoteRules = old.RemoteRules
		c.LastRulesUpdate = old.LastRulesUpdate
		c.LastRulesMsg = old.LastRulesMsg
		if c.RulesUpdateHours <= 0 {
			c.RulesUpdateHours = 24
		}
		if err := s.store.Update(func(cfg *config.Config) { cfg.WAF = c }); err != nil {
			jsonError(w, http.StatusInternalServerError, "保存失败: "+err.Error())
			return
		}
		if err := waf.Default().Apply(c); err != nil {
			jsonError(w, http.StatusBadRequest, "规则编译失败，已保留旧引擎: "+err.Error())
			return
		}
		logcenter.Default().Add("WAF", logcenter.LevelInfo, "WAF 配置已更新（%s）", map[bool]string{true: "开启", false: "关闭"}[c.Enabled])
		writeJSON(w, map[string]any{"ok": true})
	case http.MethodDelete:
		waf.Default().ClearHits()
		writeJSON(w, map[string]any{"ok": true})
	default:
		jsonError(w, http.StatusMethodNotAllowed, "不支持的方法")
	}
}

// handleWAFTest 用构造请求测试规则是否命中。
func (s *Server) handleWAFTest(w http.ResponseWriter, r *http.Request) {
	var req struct {
		URI string `json:"uri"`
		UA  string `json:"ua"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, http.StatusBadRequest, "请求格式错误")
		return
	}
	if req.URI == "" {
		req.URI = "/"
	}
	blocked, msg := waf.Default().Test(req.URI, req.UA)
	writeJSON(w, map[string]any{"blocked": blocked, "msg": msg})
}

func errString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

// healthInfo 系统健康度（对齐 lucky 的评分公式）。
type healthInfo struct {
	Score float64 `json:"score"`
	CPU   float64 `json:"cpu"`
	Mem   float64 `json:"mem"`
}

// healthPrev 上次采样，用于计算 CPU 使用率增量。
var (
	healthMu     sync.Mutex
	lastCPUTotal uint64
	lastCPUIdle  uint64
	lastSampleAt time.Time
	cachedHealth healthInfo
)

// collectHealth 采样 CPU/内存占用并计算健康评分：
// 评分 = 100 - (CPU% × 0.35 + 内存% × 0.45)，限制在 0-100。
func collectHealth() healthInfo {
	healthMu.Lock()
	defer healthMu.Unlock()

	mem := memUsagePercent()
	cpu := cpuUsagePercent()
	score := 100 - (cpu*0.35 + mem*0.45)
	if score < 0 {
		score = 0
	}
	if score > 100 {
		score = 100
	}
	cachedHealth = healthInfo{
		Score: math.Round(score),
		CPU:   math.Round(cpu*10) / 10,
		Mem:   math.Round(mem*10) / 10,
	}
	return cachedHealth
}
