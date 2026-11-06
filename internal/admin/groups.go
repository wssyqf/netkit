package admin

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"strings"

	"netkit/internal/config"
	"netkit/internal/logcenter"
)

// newGroupID 生成短随机 ID。
func newGroupID() string {
	b := make([]byte, 8)
	rand.Read(b)
	return "g_" + hex.EncodeToString(b)
}

// handleGroups 分组 CRUD。
//
//	GET    /api/groups            列出全部分组
//	POST   /api/groups            新建或更新（请求体为单个 Group，含 id 则更新）
//	DELETE /api/groups?id=xxx     删除（同时把引用该分组的规则解绑）
func (s *Server) handleGroups(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, s.store.Get().Groups)

	case http.MethodPost:
		var g config.Group
		if err := json.NewDecoder(r.Body).Decode(&g); err != nil {
			jsonError(w, http.StatusBadRequest, "请求格式错误")
			return
		}
		g.Name = strings.TrimSpace(g.Name)
		if g.Name == "" {
			jsonError(w, http.StatusBadRequest, "分组名称不能为空")
			return
		}
		if g.ID == "" {
			g.ID = newGroupID()
		}
		err := s.store.Update(func(c *config.Config) {
			replaced := false
			for i := range c.Groups {
				if c.Groups[i].ID == g.ID {
					c.Groups[i] = g
					replaced = true
					break
				}
			}
			if !replaced {
				c.Groups = append(c.Groups, g)
			}
		})
		if err != nil {
			jsonError(w, http.StatusInternalServerError, "保存失败: "+err.Error())
			return
		}
		logcenter.Default().Add("分组", logcenter.LevelInfo, "保存分组 %s", g.Name)
		writeJSON(w, map[string]any{"ok": true, "id": g.ID})

	case http.MethodDelete:
		id := r.URL.Query().Get("id")
		if id == "" {
			jsonError(w, http.StatusBadRequest, "缺少 id")
			return
		}
		var name string
		err := s.store.Update(func(c *config.Config) {
			kept := make([]config.Group, 0, len(c.Groups))
			for _, g := range c.Groups {
				if g.ID == id {
					name = g.Name
					continue
				}
				kept = append(kept, g)
			}
			c.Groups = kept
			// 解绑引用该分组的规则
			for i := range c.PortForwards {
				if c.PortForwards[i].GroupTag == id {
					c.PortForwards[i].GroupTag = ""
				}
			}
			for i := range c.WebRules {
				if c.WebRules[i].GroupID == id {
					c.WebRules[i].GroupID = ""
				}
			}
			for i := range c.DDNS {
				if c.DDNS[i].GroupTag == id {
					c.DDNS[i].GroupTag = ""
				}
			}
		})
		if err != nil {
			jsonError(w, http.StatusInternalServerError, "删除失败: "+err.Error())
			return
		}
		logcenter.Default().Add("分组", logcenter.LevelInfo, "删除分组 %s", name)
		writeJSON(w, map[string]any{"ok": true})

	default:
		jsonError(w, http.StatusMethodNotAllowed, "不支持的方法")
	}
}
