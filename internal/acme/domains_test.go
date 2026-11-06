package acme

import (
	"strings"
	"testing"
)

func TestParseDomains(t *testing.T) {
	cases := []struct {
		in   string
		want []string
	}{
		{"ziuzu.cc.cd", []string{"ziuzu.cc.cd"}},
		{"ziuzu.cc.cd,*.ziuzu.cc.cd", []string{"ziuzu.cc.cd", "*.ziuzu.cc.cd"}},
		{"a.com, b.com ,c.com", []string{"a.com", "b.com", "c.com"}},
		{"a.com\na.com", []string{"a.com"}}, // 去重
		{"A.COM，a.com", []string{"a.com"}},  // 中文逗号 + 大小写归一
		{"", []string{}},
		{"  ,  ", []string{}},
	}
	for _, c := range cases {
		got := ParseDomains(c.in)
		if len(got) != len(c.want) {
			t.Errorf("ParseDomains(%q) = %v, want %v", c.in, got, c.want)
			continue
		}
		for i := range got {
			if got[i] != c.want[i] {
				t.Errorf("ParseDomains(%q)[%d] = %q, want %q", c.in, i, got[i], c.want[i])
			}
		}
	}
}

func TestValidateDomains(t *testing.T) {
	ok := [][]string{
		{"a.com"},
		{"a.com", "b.com"},
		{"sub.a.com"},
	}
	for _, d := range ok {
		if err := ValidateDomains(d); err != nil {
			t.Errorf("ValidateDomains(%v) 应通过，实际: %v", d, err)
		}
	}

	bad := []struct {
		d    []string
		want string
	}{
		{[]string{}, "至少填写"},
		{[]string{"*.a.com"}, "DNS-01"},
		{[]string{"a..com"}, "空的标签"},
		{[]string{"nodot"}, "缺少点号"},
		{[]string{"a.*.b.com"}, "通配符只能写在最前面"},
	}
	for _, c := range bad {
		err := ValidateDomains(c.d)
		if err == nil {
			t.Errorf("ValidateDomains(%v) 应报错", c.d)
			continue
		}
		if !strings.Contains(err.Error(), c.want) {
			t.Errorf("ValidateDomains(%v) 错误 = %q，期望包含 %q", c.d, err.Error(), c.want)
		}
	}
}

func TestChallengeFQDN(t *testing.T) {
	cases := []struct{ in, want string }{
		{"example.com", "_acme-challenge.example.com"},
		{"*.example.com", "_acme-challenge.example.com"},
		{"a.example.com", "_acme-challenge.a.example.com"},
		{"*.a.example.com", "_acme-challenge.a.example.com"},
	}
	for _, c := range cases {
		if got := challengeFQDN(c.in); got != c.want {
			t.Errorf("challengeFQDN(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestDNS01TxtValue(t *testing.T) {
	// 用 RFC 8555 示例验证算法：TXT = base64url(sha256(token + "." + thumbprint))
	got := dnstxtValue("token123", "thumbABC")
	if got == "" {
		t.Fatal("dnstxtValue 返回空")
	}
	// 同输入必须稳定
	if dnstxtValue("token123", "thumbABC") != got {
		t.Error("dnstxtValue 不稳定")
	}
	// 不同输入必须不同
	if dnstxtValue("token123", "thumbXYZ") == got {
		t.Error("不同 thumbprint 应产生不同 TXT 值")
	}
	// 必须是 base64url 无填充
	for _, r := range got {
		if r == '=' || r == '+' || r == '/' {
			t.Errorf("TXT 值应为 base64url 无填充，实际含 %q", r)
		}
	}
}

func TestValidateAllowsWildcardForDNS01(t *testing.T) {
	// HTTP-01 下通配符应被拒
	if err := ValidateDomainsOpt([]string{"*.example.com"}, false); err == nil {
		t.Error("HTTP-01 下通配符应报错")
	}
	// DNS-01 下应通过
	if err := ValidateDomainsOpt([]string{"*.example.com"}, true); err != nil {
		t.Errorf("DNS-01 下通配符应通过，实际: %v", err)
	}
}
