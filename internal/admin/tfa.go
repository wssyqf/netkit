package admin

import (
	"encoding/json"
	"net"
	"net/http"
	"strings"
	"time"

	"netkit/internal/config"
	"netkit/internal/logcenter"
	"netkit/internal/totp"
)

// handle2FAStatus 返回 2FA 当前状态（不含密钥）。
func (s *Server) handle2FAStatus(w http.ResponseWriter, r *http.Request) {
	base := s.store.GetBase()
	remaining := len(base.TFA.RecoveryCodes)
	writeJSON(w, map[string]any{
		"enabled":      base.TFA.Enabled,
		"recoveryLeft": remaining,
		"issuer":       "NetKit",
		"account":      base.Username,
	})
}

// handle2FASetup 生成新的 TOTP 密钥（尚未启用），返回密钥与 otpauth 链接。
// 用户需用 App 扫码后输入验证码调用 /enable 才真正生效。
func (s *Server) handle2FASetup(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		jsonError(w, http.StatusMethodNotAllowed, "仅支持 POST")
		return
	}
	base := s.store.GetBase()
	if base.TFA.Enabled {
		jsonError(w, http.StatusBadRequest, "两步验证已启用，请先停用再重新设置")
		return
	}
	secret, err := totp.GenerateSecret()
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "生成密钥失败: "+err.Error())
		return
	}
	// 暂存密钥（Enabled 仍为 false），等待用户验证
	if err := s.store.Update(func(c *config.Config) {
		c.Base.TFA.Secret = secret
		c.Base.TFA.Enabled = false
		c.Base.TFA.RecoveryCodes = nil
		c.Base.TFA.LastUsedWindow = 0
	}); err != nil {
		jsonError(w, http.StatusInternalServerError, "保存失败: "+err.Error())
		return
	}
	writeJSON(w, map[string]any{
		"secret":  secret,
		"otpauth": totp.OtpauthURL("NetKit", base.Username, secret),
		"digits":  totp.Digits,
		"period":  totp.Period,
	})
}

// handle2FAEnable 用用户输入的验证码激活 2FA，并一次性返回恢复码。
func (s *Server) handle2FAEnable(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		jsonError(w, http.StatusMethodNotAllowed, "仅支持 POST")
		return
	}
	var req struct {
		Code string `json:"code"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, http.StatusBadRequest, "请求格式错误")
		return
	}
	base := s.store.GetBase()
	if base.TFA.Secret == "" {
		jsonError(w, http.StatusBadRequest, "请先生成密钥")
		return
	}
	code := strings.ReplaceAll(strings.TrimSpace(req.Code), " ", "")
	win, ok := totp.MatchedWindow(base.TFA.Secret, code, time.Now())
	if !ok {
		jsonError(w, http.StatusBadRequest, "验证码不正确，请确认手机时间准确后重试")
		return
	}

	codes, err := totp.GenerateRecoveryCodes(8)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "生成恢复码失败: "+err.Error())
		return
	}
	if err := s.store.Update(func(c *config.Config) {
		c.Base.TFA.Enabled = true
		c.Base.TFA.RecoveryCodes = codes
		c.Base.TFA.LastUsedWindow = win
	}); err != nil {
		jsonError(w, http.StatusInternalServerError, "保存失败: "+err.Error())
		return
	}
	ip, _, _ := net.SplitHostPort(r.RemoteAddr)
	logcenter.Default().Add("后台", logcenter.LevelInfo, "已启用两步验证 (来自 %s)", ip)
	writeJSON(w, map[string]any{"ok": true, "recoveryCodes": codes})
}

// handle2FADisable 停用 2FA。需要当前密码 + 有效验证码（或恢复码）双重确认，
// 避免会话被盗后直接关闭防护。
func (s *Server) handle2FADisable(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		jsonError(w, http.StatusMethodNotAllowed, "仅支持 POST")
		return
	}
	var req struct {
		Password string `json:"password"`
		Code     string `json:"code"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, http.StatusBadRequest, "请求格式错误")
		return
	}
	base := s.store.GetBase()
	if req.Password != base.Password {
		jsonError(w, http.StatusUnauthorized, "密码不正确")
		return
	}
	if base.TFA.Enabled {
		if !totp.Verify(base.TFA.Secret, req.Code, time.Now()) {
			jsonError(w, http.StatusUnauthorized, "两步验证码不正确")
			return
		}
	}
	if err := s.store.Update(func(c *config.Config) {
		c.Base.TFA = config.TFAConfig{}
	}); err != nil {
		jsonError(w, http.StatusInternalServerError, "保存失败: "+err.Error())
		return
	}
	ip, _, _ := net.SplitHostPort(r.RemoteAddr)
	logcenter.Default().Add("后台", logcenter.LevelWarn, "已停用两步验证 (来自 %s)", ip)
	writeJSON(w, map[string]any{"ok": true})
}

// consumeRecoveryCode 校验并消耗一个恢复码（用后即失效）。
func (s *Server) consumeRecoveryCode(code string) bool {
	code = strings.ToUpper(strings.TrimSpace(code))
	if code == "" {
		return false
	}
	base := s.store.GetBase()
	idx := -1
	for i, c := range base.TFA.RecoveryCodes {
		if strings.EqualFold(c, code) {
			idx = i
			break
		}
	}
	if idx < 0 {
		return false
	}
	remaining := append([]string{}, base.TFA.RecoveryCodes[:idx]...)
	remaining = append(remaining, base.TFA.RecoveryCodes[idx+1:]...)
	if err := s.store.Update(func(c *config.Config) {
		c.Base.TFA.RecoveryCodes = remaining
	}); err != nil {
		return false
	}
	ip := ""
	_ = ip
	logcenter.Default().Add("后台", logcenter.LevelWarn, "使用恢复码登录，剩余 %d 个", len(remaining))
	return true
}
