// Package totp 实现 RFC 6238 的两步验证（TOTP），兼容 Google Authenticator、
// Microsoft Authenticator、1Password、Bitwarden 等主流 App。
// 仅使用标准库，无第三方依赖。
package totp

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"net/url"
	"strings"
	"time"
)

const (
	// Period 每个验证码的有效秒数（RFC 推荐 30 秒）。
	Period = 30
	// Digits 验证码位数。
	Digits = 6
	// SecretLen 密钥字节数（160 位，RFC 4226 推荐）。
	SecretLen = 20
)

var b32 = base32.StdEncoding.WithPadding(base32.NoPadding)

// GenerateSecret 生成一个新的随机密钥，返回 Base32 字符串（不含填充、大写）。
func GenerateSecret() (string, error) {
	b := make([]byte, SecretLen)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return b32.EncodeToString(b), nil
}

// hotp 计算指定计数器下的 HOTP 值（RFC 4226）。
func hotp(secret []byte, counter uint64) string {
	buf := make([]byte, 8)
	binary.BigEndian.PutUint64(buf, counter)

	mac := hmac.New(sha1.New, secret)
	mac.Write(buf)
	sum := mac.Sum(nil)

	// 动态截断：取最后一个字节的低 4 位作为偏移
	offset := sum[len(sum)-1] & 0x0f
	code := (uint32(sum[offset])&0x7f)<<24 |
		uint32(sum[offset+1])<<16 |
		uint32(sum[offset+2])<<8 |
		uint32(sum[offset+3])
	return fmt.Sprintf("%06d", code%1000000)
}

// decodeSecret 解析用户提供的 Base32 密钥（容忍空格、小写、填充）。
func decodeSecret(s string) ([]byte, error) {
	s = strings.ToUpper(strings.TrimSpace(s))
	s = strings.ReplaceAll(s, " ", "")
	s = strings.TrimRight(s, "=")
	return b32.DecodeString(s)
}

// Code 计算当前时刻的验证码，供校验自测使用。
func Code(secret string, t time.Time) (string, error) {
	key, err := decodeSecret(secret)
	if err != nil {
		return "", fmt.Errorf("密钥格式无效: %w", err)
	}
	return hotp(key, uint64(t.Unix()/Period)), nil
}

// Verify 校验用户输入的验证码。
// 允许 ±1 个时间窗口的时钟偏差，且拒绝重复使用同一验证码（由调用方负责记录已用窗口）。
func Verify(secret, code string, t time.Time) bool {
	code = strings.TrimSpace(code)
	// 允许用户输入带空格的形式，如 "123 456"
	code = strings.ReplaceAll(code, " ", "")
	if len(code) != Digits {
		return false
	}
	key, err := decodeSecret(secret)
	if err != nil {
		return false
	}
	counter := uint64(t.Unix() / Period)
	for _, delta := range []int64{0, -1, 1} {
		c := counter
		if delta < 0 {
			if counter == 0 {
				continue
			}
			c = counter - 1
		} else if delta > 0 {
			c = counter + 1
		}
		if subtleEqual(hotp(key, c), code) {
			return true
		}
	}
	return false
}

// MatchedWindow 返回命中的时间窗口序号；未命中返回 0 和 false。
// 调用方可用它实现"同一验证码不可重复使用"。
func MatchedWindow(secret, code string, t time.Time) (uint64, bool) {
	code = strings.ReplaceAll(strings.TrimSpace(code), " ", "")
	if len(code) != Digits {
		return 0, false
	}
	key, err := decodeSecret(secret)
	if err != nil {
		return 0, false
	}
	base := uint64(t.Unix() / Period)
	candidates := []uint64{base}
	if base > 0 {
		candidates = append(candidates, base-1)
	}
	candidates = append(candidates, base+1)
	for _, c := range candidates {
		if subtleEqual(hotp(key, c), code) {
			return c, true
		}
	}
	return 0, false
}

// subtleEqual 定长比较，避免时序侧信道。
func subtleEqual(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	var diff byte
	for i := 0; i < len(a); i++ {
		diff |= a[i] ^ b[i]
	}
	return diff == 0
}

// OtpauthURL 生成 otpauth:// 链接，用于二维码展示。
// 例：otpauth://totp/NetKit:666?secret=XXXX&issuer=NetKit&algorithm=SHA1&digits=6&period=30
func OtpauthURL(issuer, account, secret string) string {
	label := url.PathEscape(issuer + ":" + account)
	q := url.Values{}
	q.Set("secret", secret)
	q.Set("issuer", issuer)
	q.Set("algorithm", "SHA1")
	q.Set("digits", fmt.Sprint(Digits))
	q.Set("period", fmt.Sprint(Period))
	return "otpauth://totp/" + label + "?" + q.Encode()
}

// GenerateRecoveryCodes 生成一次性恢复码（当手机丢失时使用）。
func GenerateRecoveryCodes(n int) ([]string, error) {
	codes := make([]string, 0, n)
	for i := 0; i < n; i++ {
		b := make([]byte, 8)
		if _, err := rand.Read(b); err != nil {
			return nil, err
		}
		hex := fmt.Sprintf("%X", b)
		codes = append(codes, hex[0:4]+"-"+hex[4:8]+"-"+hex[8:12])
	}
	return codes, nil
}
