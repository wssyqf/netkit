package reverseproxy

import (
	"bufio"
	"net"
	"net/http"
	"strconv"
)

// countingWriter 包装 ResponseWriter，统计状态码与写出字节数。
// 同时透传 Flusher / Hijacker，保证 SSE 与 WebSocket 正常工作。
type countingWriter struct {
	http.ResponseWriter
	status int
	bytes  int64
	wrote  bool
}

func (w *countingWriter) WriteHeader(code int) {
	if !w.wrote {
		w.status = code
		w.wrote = true
	}
	w.ResponseWriter.WriteHeader(code)
}

func (w *countingWriter) Write(p []byte) (int, error) {
	if !w.wrote {
		w.status = 200
		w.wrote = true
	}
	n, err := w.ResponseWriter.Write(p)
	w.bytes += int64(n)
	return n, err
}

// Flush 让 SSE / 流式响应能立即下发。
func (w *countingWriter) Flush() {
	if f, ok := w.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// Hijack 让 WebSocket 能接管连接。
func (w *countingWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	h, ok := w.ResponseWriter.(http.Hijacker)
	if !ok {
		return nil, nil, http.ErrNotSupported
	}
	return h.Hijack()
}

// requestBytes 估算请求体大小（优先 Content-Length，其次读到的长度）。
func requestBytes(r *http.Request) int64 {
	if r.ContentLength > 0 {
		return r.ContentLength
	}
	return 0
}

func itoaInt(n int) string { return strconv.Itoa(n) }
