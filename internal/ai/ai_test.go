package ai

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"netkit/internal/config"
)

// TestChatOK 验证 OpenAI 兼容请求头、URL 拼接与响应解析。
func TestChatOK(t *testing.T) {
	var gotPath, gotAuth, gotModel string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotAuth = r.Header.Get("Authorization")
		var body struct {
			Model    string `json:"model"`
			Messages []Msg  `json:"messages"`
			Stream   bool   `json:"stream"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		gotModel = body.Model
		_ = json.NewEncoder(w).Encode(map[string]any{
			"choices": []map[string]any{{"message": map[string]string{"role": "assistant", "content": "连接成功"}}},
		})
	}))
	defer srv.Close()

	cfg := config.AIConfig{BaseURL: srv.URL + "/v1/", APIKey: "sk-test", Model: "demo-model"}
	reply, err := Chat(context.Background(), cfg, []Msg{{Role: "user", Content: "hi"}})
	if err != nil {
		t.Fatalf("Chat 失败: %v", err)
	}
	if reply != "连接成功" {
		t.Fatalf("回复不符: %q", reply)
	}
	if gotPath != "/v1/chat/completions" {
		t.Fatalf("路径拼接错误: %s", gotPath)
	}
	if gotAuth != "Bearer sk-test" {
		t.Fatalf("鉴权头错误: %q", gotAuth)
	}
	if gotModel != "demo-model" {
		t.Fatalf("模型未透传: %q", gotModel)
	}
}

// TestChatHTTPError 上游非 2xx 时返回含状态码的错误。
func TestChatHTTPError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, `{"error":{"message":"invalid api key"}}`, http.StatusUnauthorized)
	}))
	defer srv.Close()
	_, err := Chat(context.Background(), config.AIConfig{BaseURL: srv.URL, Model: "m"}, []Msg{{Role: "user", Content: "x"}})
	if err == nil || !strings.Contains(err.Error(), "401") {
		t.Fatalf("期望 401 错误，得到: %v", err)
	}
}

// TestChatTimeout ctx 超时应快速失败。
func TestChatTimeout(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(500 * time.Millisecond)
	}))
	defer srv.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	_, err := Chat(ctx, config.AIConfig{BaseURL: srv.URL, Model: "m"}, []Msg{{Role: "user", Content: "x"}})
	if err == nil {
		t.Fatal("期望超时错误")
	}
}

// TestChatBadProxy 非 http/https 代理应被拒绝。
func TestChatBadProxy(t *testing.T) {
	_, err := Chat(context.Background(), config.AIConfig{BaseURL: "http://x/v1", Proxy: "socks5://127.0.0.1:1080"}, nil)
	if err == nil || !strings.Contains(err.Error(), "代理") {
		t.Fatalf("期望代理错误，得到: %v", err)
	}
}

// TestBuildContext 上下文能聚合并截断到 6KB 内。
func TestBuildContext(t *testing.T) {
	SetMeta("v0.3.0", time.Now().Add(-time.Hour))
	SetHealth(func() map[string]any { return map[string]any{"score": 97.0, "cpu": 3.1, "mem": 22.5} })
	got := BuildContext(config.Config{})
	if !strings.Contains(got, "版本: v0.3.0") {
		t.Fatalf("缺少版本信息:\n%s", got)
	}
	if !strings.Contains(got, "WAF:") || !strings.Contains(got, "蜜罐诱捕:") {
		t.Fatalf("缺少模块状态:\n%s", got)
	}
	if len(got) > 6*1024 {
		t.Fatalf("上下文超限: %d", len(got))
	}
}
