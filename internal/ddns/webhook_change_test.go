package ddns

import (
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"netkit/internal/config"
	"netkit/internal/safe"
)

// 验证 Webhook 仅在 IP 相比上一次同步发生变动时发送：
// IP 不变的每轮同步不再推送（修复"每分钟推送一条无需更新"刷屏）。
func TestWebhookOnlyOnIPChange(t *testing.T) {
	var mu sync.Mutex
	whCount := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/wh" {
			mu.Lock()
			whCount++
			mu.Unlock()
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()

	task := config.DDNSTask{
		ID: "t1", Name: "测试任务", Enabled: true,
		Provider:    "callback",
		CallbackURL: srv.URL + "/dns?ip=#{ip}",
		Domains:     []string{"test.example.com"},
		IPv4:        true,
		IPSource:    "cmd",
		IPCmd:       "echo 1.2.3.4", // 模拟取到公网 IP
		IntervalSec: 60,
		Webhook:     config.Webhook{URL: srv.URL + "/wh"},
	}
	m := NewManager()
	rt := &runningTask{
		stop: make(chan struct{}), done: make(chan struct{}),
		task: task, logs: safe.NewLogRing(20),
	}
	get := func() int { mu.Lock(); defer mu.Unlock(); return whCount }

	m.runOnce(rt) // 首次同步视为变动 → 发送
	if get() != 1 {
		t.Fatalf("首轮应发送 1 次，实际 %d", get())
	}

	m.runOnce(rt) // IP 未变 → 跳过
	if get() != 1 {
		t.Fatalf("IP 未变时不应发送，实际 %d", get())
	}

	rt.task.IPCmd = "echo 5.6.7.8" // IP 变动
	m.runOnce(rt)
	if get() != 2 {
		t.Fatalf("IP 变动后应累计 2 次，实际 %d", get())
	}

	m.runOnce(rt) // IP 再次未变 → 跳过
	if get() != 2 {
		t.Fatalf("IP 再次未变时不应发送，实际 %d", get())
	}
}

// 验证失败提醒：新失败推送一次、同一失败不重复刷屏、恢复后重置、再次失败重新提醒。
func TestWebhookOnFailureOnce(t *testing.T) {
	var mu sync.Mutex
	whCount := 0
	failMode := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/wh":
			mu.Lock()
			whCount++
			mu.Unlock()
		case "/dns":
			if failMode {
				w.WriteHeader(http.StatusInternalServerError)
				_, _ = w.Write([]byte("server error"))
				return
			}
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()

	task := config.DDNSTask{
		ID: "t2", Name: "失败提醒任务", Enabled: true,
		Provider:    "callback",
		CallbackURL: srv.URL + "/dns?ip=#{ip}",
		Domains:     []string{"test.example.com"},
		IPv4:        true,
		IPSource:    "cmd",
		IPCmd:       "echo 1.2.3.4",
		IntervalSec: 60,
		Webhook:     config.Webhook{URL: srv.URL + "/wh"},
	}
	m := NewManager()
	rt := &runningTask{
		stop: make(chan struct{}), done: make(chan struct{}),
		task: task, logs: safe.NewLogRing(20),
	}
	get := func() int { mu.Lock(); defer mu.Unlock(); return whCount }

	m.runOnce(rt) // 首次同步（成功）→ 发送
	if get() != 1 {
		t.Fatalf("首轮应发送 1 次，实际 %d", get())
	}
	m.runOnce(rt) // IP 未变且成功 → 跳过
	if get() != 1 {
		t.Fatalf("正常轮不应发送，实际 %d", get())
	}

	failMode = true
	m.runOnce(rt) // 新失败 → 推送提醒
	if get() != 2 {
		t.Fatalf("首次失败应推送，实际 %d", get())
	}
	m.runOnce(rt) // 同一失败 → 去重
	if get() != 2 {
		t.Fatalf("同一失败不应重复推送，实际 %d", get())
	}
	m.runOnce(rt) // 同一失败 → 去重
	if get() != 2 {
		t.Fatalf("同一失败不应重复推送，实际 %d", get())
	}

	failMode = false
	m.runOnce(rt) // 恢复 → 不推送，但重置去重状态
	if get() != 2 {
		t.Fatalf("恢复轮不应推送，实际 %d", get())
	}
	m.runOnce(rt)
	if get() != 2 {
		t.Fatalf("恢复后正常轮不应推送，实际 %d", get())
	}

	failMode = true
	m.runOnce(rt) // 恢复后再次失败 → 重新提醒
	if get() != 3 {
		t.Fatalf("再次失败应重新推送，实际 %d", get())
	}
}
