package totp

import (
	"testing"
	"time"
)

// RFC 6238 官方测试向量（SHA1，密钥 "12345678901234567890"）
func TestRFC6238Vectors(t *testing.T) {
	secret := b32.EncodeToString([]byte("12345678901234567890"))
	cases := []struct {
		unix int64
		want string
	}{
		{59, "287082"},
		{1111111109, "081804"},
		{1111111111, "050471"},
		{1234567890, "005924"},
		{2000000000, "279037"},
	}
	for _, c := range cases {
		got, err := Code(secret, time.Unix(c.unix, 0))
		if err != nil {
			t.Fatalf("unix=%d 计算失败: %v", c.unix, err)
		}
		if got != c.want {
			t.Errorf("unix=%d 期望 %s 实际 %s", c.unix, c.want, got)
		}
	}
}

func TestVerifyWindowTolerance(t *testing.T) {
	secret, _ := GenerateSecret()
	now := time.Unix(1700000000, 0)
	code, _ := Code(secret, now)
	if !Verify(secret, code, now) {
		t.Error("当前时刻验证码应通过")
	}
	if !Verify(secret, code, now.Add(25*time.Second)) {
		t.Error("±1 窗口内应通过")
	}
	if Verify(secret, "000000", now) && code != "000000" {
		t.Error("错误验证码不应通过")
	}
	if Verify(secret, "123", now) {
		t.Error("位数不足不应通过")
	}
}

func TestSpaceTolerance(t *testing.T) {
	secret, _ := GenerateSecret()
	now := time.Unix(1700000000, 0)
	code, _ := Code(secret, now)
	spaced := code[0:3] + " " + code[3:]
	if !Verify(secret, spaced, now) {
		t.Error("带空格的验证码应通过")
	}
}
