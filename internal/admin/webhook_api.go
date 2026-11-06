package admin

import (
	"encoding/json"
	"net/http"

	"netkit/internal/config"
	"netkit/internal/logcenter"
	"netkit/internal/webhook"
)

// handleWebhookTest 用当前填写的配置发送一条测试通知，便于在保存前验证。
// 请求体为 Webhook 配置对象，返回发送结果（状态码、耗时、尝试次数、响应片段）。
func (s *Server) handleWebhookTest(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		jsonError(w, http.StatusMethodNotAllowed, "仅支持 POST")
		return
	}
	var wh config.Webhook
	if err := json.NewDecoder(r.Body).Decode(&wh); err != nil {
		jsonError(w, http.StatusBadRequest, "请求格式错误")
		return
	}
	if wh.URL == "" {
		jsonError(w, http.StatusBadRequest, "请先填写 Webhook 地址")
		return
	}
	// 测试事件强制放行事件过滤
	wh.Events = nil

	res := webhook.NewClient().Send(wh, webhook.Payload{
		Event:  webhook.EventTest,
		Module: "测试",
		Target: "netkit.test",
		IP:     "203.0.113.10",
		Result: "这是一条来自 NetKit 的测试通知",
		OK:     true,
		Extra: map[string]string{
			"test":      "1",
			"ipv4":      "203.0.113.10",
			"ipv6":      "2001:db8::10",
			"ruleCount": "3",
		},
	})

	level := logcenter.LevelInfo
	if !res.OK {
		level = logcenter.LevelWarn
	}
	logcenter.Default().Add("Webhook", level, "测试通知：%s（HTTP %d，%d 次尝试，耗时 %s）",
		res.Message, res.Status, res.Attempts, res.Elapsed.Round(10_000_000))

	writeJSON(w, map[string]any{
		"ok":       res.OK,
		"status":   res.Status,
		"attempts": res.Attempts,
		"elapsed":  res.Elapsed.Milliseconds(),
		"message":  res.Message,
		"response": res.RespBody,
	})
}

// handleGlobalWebhook 读写全局通知配置。
func (s *Server) handleGlobalWebhook(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, s.store.Get().GlobalWebhook)
	case http.MethodPost:
		var wh config.Webhook
		if err := json.NewDecoder(r.Body).Decode(&wh); err != nil {
			jsonError(w, http.StatusBadRequest, "请求格式错误")
			return
		}
		if err := s.store.Update(func(c *config.Config) { c.GlobalWebhook = wh }); err != nil {
			jsonError(w, http.StatusInternalServerError, "保存失败: "+err.Error())
			return
		}
		logcenter.Default().Add("Webhook", logcenter.LevelInfo, "全局通知配置已更新（%s）",
			map[bool]string{true: "已启用", false: "已关闭"}[wh.Enabled])
		writeJSON(w, map[string]any{"ok": true})
	default:
		jsonError(w, http.StatusMethodNotAllowed, "不支持的方法")
	}
}
