package admin

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"netkit/internal/ai"
	"netkit/internal/config"
	"netkit/internal/logcenter"
)

// handleAIConfig 读写 AI 大模型维护配置。
// GET 不回传 APIKey（只给 apiKeySet），POST 时 key 为空表示保留旧值。
func (s *Server) handleAIConfig(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		c := s.store.Get().AI
		writeJSON(w, map[string]any{
			"enabled":   c.Enabled,
			"baseURL":   c.BaseURL,
			"model":     c.Model,
			"proxy":     c.Proxy,
			"apiKeySet": c.APIKey != "",
		})
	case http.MethodPost:
		var req config.AIConfig
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			jsonError(w, http.StatusBadRequest, "请求格式错误")
			return
		}
		req.BaseURL = strings.TrimSpace(req.BaseURL)
		req.Model = strings.TrimSpace(req.Model)
		req.Proxy = strings.TrimSpace(req.Proxy)
		if req.Enabled && req.BaseURL == "" {
			jsonError(w, http.StatusBadRequest, "启用前请先填写模型服务地址（BaseURL）")
			return
		}
		err := s.store.Update(func(c *config.Config) {
			if req.APIKey != "" {
				c.AI.APIKey = req.APIKey
			}
			c.AI.Enabled = req.Enabled
			c.AI.BaseURL = req.BaseURL
			c.AI.Model = req.Model
			c.AI.Proxy = req.Proxy
		})
		if err != nil {
			jsonError(w, http.StatusInternalServerError, "保存失败: "+err.Error())
			return
		}
		logcenter.Default().Add("AI维护", logcenter.LevelInfo, "AI 大模型配置已更新（%s，模型 %s）",
			map[bool]string{true: "已启用", false: "已关闭"}[req.Enabled], orDash(req.Model))
		writeJSON(w, map[string]any{"ok": true})
	default:
		jsonError(w, http.StatusMethodNotAllowed, "不支持的方法")
	}
}

// handleAIConnTest 用当前填写（或已保存）的配置发一条极短 prompt 测连通。
func (s *Server) handleAIConnTest(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		jsonError(w, http.StatusMethodNotAllowed, "仅支持 POST")
		return
	}
	cfg, err := s.aiCfgFromBody(r)
	if err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	if cfg.BaseURL == "" {
		jsonError(w, http.StatusBadRequest, "请先填写模型服务地址（BaseURL）")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()
	t0 := time.Now()
	reply, err := ai.Chat(ctx, cfg, []ai.Msg{{Role: "user", Content: "请只回复：连接成功"}})
	elapsed := time.Since(t0).Round(time.Millisecond)
	if err != nil {
		logcenter.Default().Add("AI维护", logcenter.LevelWarn, "连接测试失败：%v", err)
		writeJSON(w, map[string]any{"ok": false, "elapsed": elapsed.Milliseconds(), "error": err.Error()})
		return
	}
	logcenter.Default().Add("AI维护", logcenter.LevelInfo, "连接测试成功（模型 %s，耗时 %s）", orDash(cfg.Model), elapsed)
	writeJSON(w, map[string]any{
		"ok":      true,
		"elapsed": elapsed.Milliseconds(),
		"reply":   clipStr(reply, 200),
	})
}

// handleAICheckup 一键体检：注入系统上下文 + 体检提示词，生成维护建议报告。
func (s *Server) handleAICheckup(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		jsonError(w, http.StatusMethodNotAllowed, "仅支持 POST")
		return
	}
	cfg := s.store.Get()
	if !cfg.AI.Enabled {
		jsonError(w, http.StatusBadRequest, "AI 大模型维护未启用，请先在下方完成配置")
		return
	}
	if cfg.AI.BaseURL == "" {
		jsonError(w, http.StatusBadRequest, "未配置模型服务地址（BaseURL）")
		return
	}
	ctxText := ai.BuildContext(cfg)
	system := "你是 NetKit 网络工具箱的运维助手。根据下面的系统实时上下文做一次体检，" +
		"用简体中文输出 Markdown 报告，包含：总评（一句话）、健康指标解读、风险项（如有，按严重程度排序）、" +
		"建议的维护动作（每条给出在面板中的具体操作路径）。不要编造上下文中没有的数据。\n\n【系统上下文】\n" + ctxText
	ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
	defer cancel()
	report, err := ai.Chat(ctx, cfg.AI, []ai.Msg{{Role: "system", Content: system}, {Role: "user", Content: "开始体检"}})
	if err != nil {
		logcenter.Default().Add("AI维护", logcenter.LevelWarn, "一键体检失败：%v", err)
		// 降级：返回上下文预览，保证功能可见
		writeJSON(w, map[string]any{"ok": false, "error": err.Error(), "context": clipStr(ctxText, 4000)})
		return
	}
	logcenter.Default().Add("AI维护", logcenter.LevelInfo, "一键体检完成（模型 %s，报告 %d 字）",
		orDash(cfg.AI.Model), len(report))
	writeJSON(w, map[string]any{"ok": true, "report": report})
}

// handleAIChat 多轮对话：注入系统上下文，限制最近 20 条、45s 超时。
func (s *Server) handleAIChat(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		jsonError(w, http.StatusMethodNotAllowed, "仅支持 POST")
		return
	}
	cfg := s.store.Get()
	if !cfg.AI.Enabled || cfg.AI.BaseURL == "" {
		jsonError(w, http.StatusBadRequest, "AI 大模型维护未启用或未配置服务地址")
		return
	}
	var req struct {
		Messages []ai.Msg `json:"messages"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || len(req.Messages) == 0 {
		jsonError(w, http.StatusBadRequest, "请求格式错误或消息为空")
		return
	}
	if len(req.Messages) > 20 {
		req.Messages = req.Messages[len(req.Messages)-20:]
	}
	// 注入系统上下文（始终置于最前）
	msgs := append([]ai.Msg{{
		Role: "system",
		Content: "你是 NetKit 网络工具箱的运维助手，用简体中文简洁回答，基于系统上下文作答，" +
			"不编造数据；涉及面板操作时给出具体页面路径。\n\n【系统上下文】\n" + ai.BuildContext(cfg),
	}}, req.Messages...)

	ctx, cancel := context.WithTimeout(r.Context(), 45*time.Second)
	defer cancel()
	reply, err := ai.Chat(ctx, cfg.AI, msgs)
	if err != nil {
		logcenter.Default().Add("AI维护", logcenter.LevelWarn, "对话失败：%v", err)
		jsonError(w, http.StatusBadGateway, err.Error())
		return
	}
	writeJSON(w, map[string]any{"ok": true, "reply": reply})
}

// aiCfgFromBody 优先用请求体里的临时配置（未保存即可测试），否则用已保存配置。
func (s *Server) aiCfgFromBody(r *http.Request) (config.AIConfig, error) {
	saved := s.store.Get().AI
	if r.Body == nil || r.ContentLength == 0 {
		return saved, nil
	}
	var req *config.AIConfig
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req == nil {
		return saved, nil
	}
	c := *req
	if c.BaseURL == "" {
		c.BaseURL = saved.BaseURL
	}
	if c.Model == "" {
		c.Model = saved.Model
	}
	if c.APIKey == "" {
		c.APIKey = saved.APIKey
	}
	if c.Proxy == "" {
		c.Proxy = saved.Proxy
	}
	return c, nil
}

func orDash(s string) string {
	if strings.TrimSpace(s) == "" {
		return "-"
	}
	return s
}

func clipStr(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
