package admin

import (
	"encoding/base64"
	"net/http"

	qrcode "github.com/skip2/go-qrcode"
)

// handle2FAQRRCode 把 otpauth 链接渲染成 PNG，以 data URL 返回。
// 使用成熟的 go-qrcode 库，避免自实现编码器的正确性风险。
func (s *Server) handle2FAQRRCode(w http.ResponseWriter, r *http.Request) {
	text := r.URL.Query().Get("text")
	if text == "" {
		jsonError(w, http.StatusBadRequest, "缺少 text 参数")
		return
	}
	if len(text) > 1024 {
		jsonError(w, http.StatusBadRequest, "内容过长")
		return
	}
	// 中等纠错等级，尺寸 256px，便于手机扫描
	png, err := qrcode.Encode(text, qrcode.Medium, 256)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "生成二维码失败: "+err.Error())
		return
	}
	dataURL := "data:image/png;base64," + base64.StdEncoding.EncodeToString(png)
	writeJSON(w, map[string]any{"png": dataURL})
}
