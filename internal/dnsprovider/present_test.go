package dnsprovider

import (
	"os"
	"testing"
)

// 真实调用 DNSHE API 验证 Provider 实现（需要环境变量提供凭据）
func TestDNSHEPresentReal(t *testing.T) {
	key := os.Getenv("DNSHE_KEY")
	secret := os.Getenv("DNSHE_SECRET")
	if key == "" || secret == "" {
		t.Skip("未设置 DNSHE_KEY/DNSHE_SECRET，跳过真实 API 测试")
	}
	p, err := New(Credentials{Provider: "dnshe", Key: key, Secret: secret})
	if err != nil {
		t.Fatal(err)
	}
	if p.Name() != "DNSHE" {
		t.Errorf("Name() = %q", p.Name())
	}
	const val = "netkit-test-txt-value-abc123"
	cleanup, err := p.Present("_acme-challenge.ziuzu.cc.cd", val)
	if err != nil {
		t.Fatalf("Present 失败: %v", err)
	}
	if cleanup == nil {
		t.Fatal("cleanup 为空")
	}
	// 清理
	if err := cleanup(); err != nil {
		t.Errorf("cleanup 失败: %v", err)
	}
}
