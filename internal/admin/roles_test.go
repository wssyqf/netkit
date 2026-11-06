package admin

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"netkit/internal/config"
)

// 验证后备账号：可登录、只能访问备份还原相关接口，主账号全功能。
func TestBackupRolePermissions(t *testing.T) {
	store := config.NewStore(filepath.Join(t.TempDir(), "netkit.conf"))
	if err := store.Update(func(c *config.Config) {
		c.Base.Username = "syqf"
		c.Base.Password = "pw-admin"
		c.Base.BackupUsername = "backup"
		c.Base.BackupPassword = "pw-backup"
	}); err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(NewServer(store).Handler())
	defer srv.Close()

	login := func(user, pass string) *http.Cookie {
		t.Helper()
		body, _ := json.Marshal(map[string]string{"username": user, "password": pass})
		resp, err := http.Post(srv.URL+"/api/login", "application/json", bytes.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("登录 %s 期望 200 实际 %d", user, resp.StatusCode)
		}
		var r struct {
			Role string `json:"role"`
		}
		json.NewDecoder(resp.Body).Decode(&r)
		want := "admin"
		if user == "backup" {
			want = "backup"
		}
		if r.Role != want {
			t.Fatalf("登录 %s 角色期望 %s 实际 %q", user, want, r.Role)
		}
		for _, c := range resp.Cookies() {
			if c.Name == "netkit_session" {
				return c
			}
		}
		t.Fatalf("登录 %s 未返回会话 Cookie", user)
		return nil
	}
	get := func(path string, ck *http.Cookie) (int, string) {
		t.Helper()
		req, _ := http.NewRequest(http.MethodGet, srv.URL+path, nil)
		if ck != nil {
			req.AddCookie(ck)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		buf := new(bytes.Buffer)
		buf.ReadFrom(resp.Body)
		return resp.StatusCode, buf.String()
	}

	// 错误凭据
	badBody, _ := json.Marshal(map[string]string{"username": "syqf", "password": "nope"})
	if resp, _ := http.Post(srv.URL+"/api/login", "application/json", bytes.NewReader(badBody)); resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("错误密码期望 401 实际 %d", resp.StatusCode)
	}

	adminCK := login("syqf", "pw-admin")
	backupCK := login("backup", "pw-backup")

	// 后备账号允许的接口
	for _, p := range []string{"/api/me", "/api/backup", "/api/backup/list"} {
		if code, _ := get(p, backupCK); code != http.StatusOK {
			t.Fatalf("后备账号访问 %s 期望 200 实际 %d", p, code)
		}
	}
	// /api/me 返回角色
	if _, body := get("/api/me", backupCK); !bytes.Contains([]byte(body), []byte(`"backup"`)) {
		t.Fatalf("/api/me 未返回 backup 角色: %s", body)
	}
	// 后备账号访问其余接口必须 403
	for _, p := range []string{"/api/settings", "/api/status", "/api/portforward", "/api/webrules", "/api/logcenter", "/api/2fa/status"} {
		if code, _ := get(p, backupCK); code != http.StatusForbidden {
			t.Fatalf("后备账号访问 %s 期望 403 实际 %d", p, code)
		}
	}
	// 主账号全功能
	for _, p := range []string{"/api/me", "/api/status", "/api/settings"} {
		if code, _ := get(p, adminCK); code != http.StatusOK {
			t.Fatalf("主账号访问 %s 期望 200 实际 %d", p, code)
		}
	}
	// 未登录 401
	if code, _ := get("/api/settings", nil); code != http.StatusUnauthorized {
		t.Fatalf("未登录访问 /api/settings 期望 401 实际 %d", code)
	}
}

// 验证设置接口对后备账号字段的读写：显式传入才更新，空用户名禁用。
func TestSettingsBackupAccountFields(t *testing.T) {
	store := config.NewStore(filepath.Join(t.TempDir(), "netkit.conf"))
	if err := store.Update(func(c *config.Config) {
		c.Base.Username = "syqf"
		c.Base.Password = "pw-admin"
		c.Base.BackupUsername = "backup"
		c.Base.BackupPassword = "pw-backup"
	}); err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(NewServer(store).Handler())
	defer srv.Close()

	// 主账号登录拿会话
	body, _ := json.Marshal(map[string]string{"username": "syqf", "password": "pw-admin"})
	resp, err := http.Post(srv.URL+"/api/login", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	var ck *http.Cookie
	for _, c := range resp.Cookies() {
		if c.Name == "netkit_session" {
			ck = c
		}
	}
	resp.Body.Close()
	if ck == nil {
		t.Fatal("未获取会话")
	}

	postSettings := func(payload map[string]any) int {
		b, _ := json.Marshal(payload)
		req, _ := http.NewRequest(http.MethodPost, srv.URL+"/api/settings", bytes.NewReader(b))
		req.Header.Set("Content-Type", "application/json")
		req.AddCookie(ck)
		r, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		r.Body.Close()
		return r.StatusCode
	}

	// 修改后备账号名 + 密码
	if code := postSettings(map[string]any{
		"oldPassword": "pw-admin", "backupUsername": "newbk", "backupPassword": "pw-new",
	}); code != http.StatusOK {
		t.Fatalf("保存后备账号期望 200 实际 %d", code)
	}
	if b := store.GetBase(); b.BackupUsername != "newbk" || b.BackupPassword != "pw-new" {
		t.Fatalf("后备账号未更新: %q / %q", b.BackupUsername, b.BackupPassword)
	}

	// 不带 backupUsername 字段（旧客户端）不清空已配置的后备账号
	if code := postSettings(map[string]any{"oldPassword": "pw-admin", "username": "syqf"}); code != http.StatusOK {
		t.Fatalf("保存主账号期望 200 实际 %d", code)
	}
	if b := store.GetBase(); b.BackupUsername != "newbk" {
		t.Fatalf("未传 backupUsername 不应清空，实际 %q", b.BackupUsername)
	}

	// 显式传空用户名 = 禁用后备账号；密码保持不变
	if code := postSettings(map[string]any{"oldPassword": "pw-admin", "backupUsername": ""}); code != http.StatusOK {
		t.Fatalf("禁用后备账号期望 200 实际 %d", code)
	}
	b := store.GetBase()
	if b.BackupUsername != "" {
		t.Fatalf("空用户名应禁用，实际 %q", b.BackupUsername)
	}
	if b.BackupPassword != "pw-new" {
		t.Fatalf("密码未修改时不应被清空，实际 %q", b.BackupPassword)
	}
	// 禁用后后备账号无法登录
	lb, _ := json.Marshal(map[string]string{"username": "newbk", "password": "pw-new"})
	if r, _ := http.Post(srv.URL+"/api/login", "application/json", bytes.NewReader(lb)); r.StatusCode != http.StatusUnauthorized {
		t.Fatalf("禁用后登录期望 401 实际 %d", r.StatusCode)
	}
}
