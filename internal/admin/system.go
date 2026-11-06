package admin

// system.go 系统级内置计划任务展示 + WAF 远程规则自动更新接口与循环。

import (
	"encoding/json"
	"net/http"
	"os"
	"runtime"
	"strconv"
	"strings"
	"time"

	"netkit/internal/config"
	"netkit/internal/logcenter"
	"netkit/internal/waf"
)

// systemCron 系统内置任务（只读展示，不可编辑/删除）。
type systemCron struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Schedule string `json:"schedule"`
	Desc     string `json:"desc"`
	Enabled  bool   `json:"enabled"`
	Status   string `json:"status"` // ok / off / na
	Detail   string `json:"detail"`
}

// handleSystemCrons 返回内置系统任务的当前状态（GET）。
func (s *Server) handleSystemCrons(w http.ResponseWriter, r *http.Request) {
	bootEnabled, autoRecover, detail := systemTaskState()
	na := detail == ""
	out := []systemCron{
		{
			ID:       "sys-boot",
			Name:     "开机启动",
			Schedule: "系统启动时",
			Desc:     "操作系统启动后自动拉起 NetKit 服务",
			Enabled:  bootEnabled,
			Status:   taskStatus(bootEnabled, na),
			Detail:   detail,
		},
		{
			ID:       "sys-recover",
			Name:     "项目崩溃自动恢复",
			Schedule: "进程异常退出时",
			Desc:     "NetKit 进程崩溃或被终止后由服务守护自动重新拉起",
			Enabled:  autoRecover,
			Status:   taskStatus(autoRecover, na),
			Detail:   detail,
		},
	}
	writeJSON(w, out)
}

func taskStatus(ok, na bool) string {
	switch {
	case na:
		return "na"
	case ok:
		return "ok"
	default:
		return "off"
	}
}

// systemTaskState 检测开机启动与崩溃守护状态（仅 Linux/OpenRC 环境可判定）。
func systemTaskState() (boot, recover bool, detail string) {
	if runtime.GOOS != "linux" {
		return false, false, ""
	}
	if _, err := os.Stat("/etc/runlevels/default/netkit"); err == nil {
		boot = true
	}
	initScript, _ := os.ReadFile("/etc/init.d/netkit")
	if strings.Contains(string(initScript), "supervisor=supervise-daemon") {
		recover = true
	}
	var parts []string
	if boot {
		parts = append(parts, "开机启动：已加入 OpenRC default 运行级")
	} else {
		parts = append(parts, "开机启动：未检测到运行级链接")
	}
	if recover {
		parts = append(parts, "崩溃恢复：守护模式 supervise-daemon 已启用")
	} else {
		parts = append(parts, "崩溃恢复：init 脚本未启用 supervise-daemon")
	}
	return boot, recover, strings.Join(parts, " ｜ ")
}

// handleWAFUpdateRules 立即拉取远程规则并应用（POST，body 可选 {"url":"..."}）。
func (s *Server) handleWAFUpdateRules(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		jsonError(w, http.StatusMethodNotAllowed, "仅支持 POST")
		return
	}
	var req struct {
		URL string `json:"url"`
	}
	json.NewDecoder(r.Body).Decode(&req)

	cfg := s.store.Get().WAF
	feedURL := strings.TrimSpace(req.URL)
	if feedURL == "" {
		feedURL = strings.TrimSpace(cfg.RulesFeedURL)
	}
	remote, err := waf.FetchRemoteRules(feedURL)
	if err != nil {
		s.recordWAFUpdate(feedURL, "", 0, err.Error(), false)
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := waf.ValidateRemoteRules(cfg, remote); err != nil {
		s.recordWAFUpdate(feedURL, "", 0, err.Error(), false)
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	s.recordWAFUpdate(feedURL, remote, len(remote), "", true)
	logcenter.Default().Add("WAF", logcenter.LevelInfo, "远程规则已更新（%d 字节）源: %s", len(remote), feedURL)
	writeJSON(w, map[string]any{"ok": true, "bytes": len(remote)})
}

// recordWAFUpdate 持久化规则更新结果并让引擎立即生效。
// 成功时推进时间戳；失败只记录消息，以便自动循环尽快重试。
func (s *Server) recordWAFUpdate(feedURL, remote string, bytes int, errMsg string, ok bool) {
	_ = s.store.Update(func(c *config.Config) {
		if feedURL != "" {
			c.WAF.RulesFeedURL = feedURL
		}
		if c.WAF.RulesUpdateHours <= 0 {
			c.WAF.RulesUpdateHours = 24
		}
		if ok {
			c.WAF.RemoteRules = remote
			c.WAF.LastRulesUpdate = time.Now().Unix()
			c.WAF.LastRulesMsg = "更新成功（" + strconv.Itoa(bytes) + " 字节）"
		} else {
			// 失败时保留旧规则继续生效，只记录错误消息
			c.WAF.LastRulesMsg = "更新失败：" + errMsg
		}
	})
	if err := waf.Default().Apply(s.store.Get().WAF); err != nil {
		logcenter.Default().Add("WAF", logcenter.LevelError, "应用远程规则失败: %s", err.Error())
	}
}

// loopWAFRuleUpdate 启动后台循环，按间隔自动拉取远程规则。
func (s *Server) loopWAFRuleUpdate() {
	ticker := time.NewTicker(10 * time.Minute)
	defer ticker.Stop()
	for range ticker.C {
		s.maybeUpdateWAFRules()
	}
}

// maybeUpdateWAFRules 到期则拉取远程规则（失败不推进时间戳，下轮重试）。
func (s *Server) maybeUpdateWAFRules() {
	cfg := s.store.Get().WAF
	if !cfg.RulesAutoUpdate || strings.TrimSpace(cfg.RulesFeedURL) == "" {
		return
	}
	hours := cfg.RulesUpdateHours
	if hours <= 0 {
		hours = 24
	}
	if cfg.LastRulesUpdate > 0 && time.Since(time.Unix(cfg.LastRulesUpdate, 0)) < time.Duration(hours)*time.Hour {
		return
	}
	remote, err := waf.FetchRemoteRules(cfg.RulesFeedURL)
	if err == nil {
		err = waf.ValidateRemoteRules(cfg, remote)
	}
	if err != nil {
		s.recordWAFUpdate(cfg.RulesFeedURL, "", 0, err.Error(), false)
		logcenter.Default().Add("WAF", logcenter.LevelWarn, "自动更新规则失败，稍后重试: %s", err.Error())
		return
	}
	s.recordWAFUpdate(cfg.RulesFeedURL, remote, len(remote), "", true)
	logcenter.Default().Add("WAF", logcenter.LevelInfo, "规则源自动更新成功（%d 字节）", len(remote))
}
