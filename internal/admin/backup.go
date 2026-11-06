package admin

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"netkit/internal/config"
	"netkit/internal/cron"
	"netkit/internal/ddns"
	"netkit/internal/logcenter"
	"netkit/internal/portforward"
	"netkit/internal/reverseproxy"
	"netkit/internal/waf"
)

// backupMeta 备份文件头信息，便于识别版本与来源。
type backupMeta struct {
	Product   string `json:"product"`
	Version   string `json:"version"`
	CreatedAt string `json:"createdAt"`
	Comment   string `json:"comment"`
}

type backupFile struct {
	Meta   backupMeta    `json:"_meta"`
	Config config.Config `json:"config"`
}

// handleBackup 导出 / 导入配置。
//
//	GET  /api/backup          下载完整配置 JSON
//	POST /api/backup          上传配置 JSON 并还原（?mode=merge 合并，默认覆盖）
func (s *Server) handleBackup(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		cfg := s.store.Get()
		b := backupFile{
			Meta: backupMeta{
				Product:   "NetKit",
				Version:   "v0.3.0",
				CreatedAt: time.Now().Format("2006-01-02 15:04:05"),
				Comment:   "NetKit 配置备份，含账号密码、TOTP 密钥与证书私钥，请妥善保管",
			},
			Config: cfg,
		}
		data, err := json.MarshalIndent(b, "", "  ")
		if err != nil {
			jsonError(w, http.StatusInternalServerError, "序列化失败: "+err.Error())
			return
		}
		name := "netkit-backup-" + time.Now().Format("20060102-150405") + ".json"
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.Header().Set("Content-Disposition", `attachment; filename="`+name+`"`)
		w.Write(data)
		logcenter.Default().Add("备份", logcenter.LevelInfo, "导出配置备份 %s", name)

	case http.MethodPost:
		var bf backupFile
		dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 32<<20)) // 上限 32MB
		if err := dec.Decode(&bf); err != nil {
			jsonError(w, http.StatusBadRequest, "备份文件格式无效: "+err.Error())
			return
		}
		// 兼容直接上传裸 Config（无 _meta 包装）
		cfg := bf.Config
		if cfg.Base.Username == "" && len(bf.Meta.Product) == 0 {
			var raw config.Config
			if err := json.Unmarshal(mustMarshal(bf), &raw); err == nil && raw.Base.Username != "" {
				cfg = raw
			}
		}
		if cfg.Base.Username == "" {
			jsonError(w, http.StatusBadRequest, "备份内容缺少 base 配置，无法识别")
			return
		}

		// 先备份当前配置，便于回滚
		oldPath := s.store.Path()
		bakPath := oldPath + ".before-restore-" + time.Now().Format("20060102-150405")
		if old, err := os.ReadFile(oldPath); err == nil {
			if err := os.WriteFile(bakPath, old, 0o600); err != nil {
				logcenter.Default().Add("备份", logcenter.LevelWarn, "旧配置备份失败: %v", err)
			}
		}

		// 整体替换
		if err := s.store.Update(func(c *config.Config) {
			*c = cfg
		}); err != nil {
			jsonError(w, http.StatusInternalServerError, "写入配置失败: "+err.Error())
			return
		}

		// 重载所有模块
		cur := s.store.Get()
		portforward.Default().Apply(cur.PortForwards)
		reverseproxy.Default().Apply(cur.WebRules)
		ddns.Default().Apply(cur.DDNS)
		cron.Default().Apply(cur.CronTasks)
		if err := waf.Default().Apply(cur.WAF); err != nil {
			logcenter.Default().Add("备份", logcenter.LevelWarn, "WAF 规则重载失败: %v", err)
		}

		ip, _, _ := net.SplitHostPort(r.RemoteAddr)
		logcenter.Default().Add("备份", logcenter.LevelInfo,
			"已从备份还原配置 (来自 %s)，旧配置留存于 %s", ip, filepath.Base(bakPath))
		writeJSON(w, map[string]any{
			"ok":       true,
			"backupOf": filepath.Base(bakPath),
			"note":     "配置已还原并生效；若登录账号/密码或 2FA 有变化，请重新登录",
		})

	default:
		jsonError(w, http.StatusMethodNotAllowed, "不支持的方法")
	}
}

func mustMarshal(v any) []byte {
	b, _ := json.Marshal(v)
	return b
}

// handleBackupList 列出本地已有的自动备份文件。
func (s *Server) handleBackupList(w http.ResponseWriter, r *http.Request) {
	dir := filepath.Dir(s.store.Path())
	base := filepath.Base(s.store.Path())
	entries, err := os.ReadDir(dir)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, err.Error())
		return
	}
	type item struct {
		Name string `json:"name"`
		Size int64  `json:"size"`
		Time string `json:"time"`
	}
	out := []item{}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		n := e.Name()
		if !strings.HasPrefix(n, base+".before-restore-") {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		out = append(out, item{Name: n, Size: info.Size(), Time: info.ModTime().Format("2006-01-02 15:04:05")})
	}
	writeJSON(w, out)
}

var _ = fmt.Sprintf
