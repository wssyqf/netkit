package reverseproxy

import (
	"bytes"
	"crypto/tls"
	"io"
	"net"
	"sync"
	"time"
)

// sniffConn 一个会在首次读取时嗅探协议类型的连接。
// 用于同一端口同时承载 HTTP 与 HTTPS：依据首字节判断是 TLS 握手还是明文 HTTP。
type sniffConn struct {
	net.Conn
	once     sync.Once
	buf      []byte
	isTLS    bool
	sniffErr error
}

// TLS 记录类型：0x16 = handshake，0x14 = change cipher spec，0x15 = alert，0x17 = application data
func looksLikeTLS(b []byte) bool {
	if len(b) < 3 {
		return false
	}
	// TLS 记录头：type(1) version_major(1)=0x03 version_minor(1)
	if b[1] != 0x03 {
		return false
	}
	switch b[0] {
	case 0x16, 0x14, 0x15, 0x17:
		return b[2] <= 0x04 // TLS 1.0 ~ 1.3
	}
	return false
}

func (c *sniffConn) sniff() {
	c.once.Do(func() {
		head := make([]byte, 3)
		c.Conn.SetReadDeadline(time.Now().Add(10 * time.Second))
		n, err := io.ReadAtLeast(c.Conn, head, 1)
		c.Conn.SetReadDeadline(time.Time{})
		if n > 0 {
			// 继续尽量读满 3 字节用于判定，但不阻塞
			if n < 3 {
				c.Conn.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
				extra := make([]byte, 3-n)
				if m, _ := io.ReadAtLeast(c.Conn, extra, 1); m > 0 {
					head = append(head[:n], extra[:m]...)
				}
				c.Conn.SetReadDeadline(time.Time{})
			}
			c.isTLS = looksLikeTLS(head)
			c.buf = head
		}
		if err != nil && n == 0 {
			c.sniffErr = err
		}
	})
}

func (c *sniffConn) Read(p []byte) (int, error) {
	c.sniff()
	if len(c.buf) > 0 {
		n := copy(p, c.buf)
		c.buf = c.buf[n:]
		return n, nil
	}
	if c.sniffErr != nil {
		return 0, c.sniffErr
	}
	return c.Conn.Read(p)
}

// samePortListener 在一个端口上同时接受 HTTP 与 HTTPS 连接。
// Accept 返回的连接的布尔值表示是否为 TLS 连接。
type samePortListener struct {
	net.Listener
	tlsCfg *tls.Config
}

// Accept 返回包装后的连接，调用方可据 conn.isTLS 决定后续处理。
func (l *samePortListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	return &sniffConn{Conn: c}, nil
}

// serveSamePort 在同一端口上根据嗅探结果分别交给 HTTP 或 HTTPS 处理器。
// 实现方式：为每个连接创建一次性 http.Server，把连接塞进各自通道。
func (l *samePortListener) split() (plainCh, tlsCh chan net.Conn) {
	plainCh = make(chan net.Conn, 64)
	tlsCh = make(chan net.Conn, 64)
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				close(plainCh)
				close(tlsCh)
				return
			}
			sc, ok := c.(*sniffConn)
			if !ok {
				continue
			}
			sc.sniff()
			if sc.isTLS {
				tlsCh <- sc
			} else {
				plainCh <- sc
			}
		}
	}()
	return
}

// oneShotListener 把通道里的连接包装成 net.Listener，供 http.Server 使用。
type oneShotListener struct {
	addr string
	ch   chan net.Conn
}

func (l *oneShotListener) Accept() (net.Conn, error) {
	c, ok := <-l.ch
	if !ok {
		return nil, io.EOF
	}
	return c, nil
}

func (l *oneShotListener) Close() error   { return nil }
func (l *oneShotListener) Addr() net.Addr { return dummyAddr(l.addr) }

type dummyAddr string

func (a dummyAddr) Network() string { return "tcp" }
func (a dummyAddr) String() string  { return string(a) }

// peekIsTLS 供外部判断一条连接是否为 TLS（用于日志/调试）。
func peekIsTLS(c net.Conn) bool {
	sc, ok := c.(*sniffConn)
	if !ok {
		return false
	}
	sc.sniff()
	return sc.isTLS
}

var _ = bytes.Equal
