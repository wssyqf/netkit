// 服务模板与交互逻辑：按诱饵端口配置的 service 分派到对应的低/中交互模拟，
// 在"看起来像真的服务"的同时捕获凭据、命令与请求特征。
package honeypot

import (
	"bufio"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// Template 蜜罐服务模板（下发给前端下拉；Banner 为空时由后端按模板兜底）。
type Template struct {
	Key    string `json:"key"`
	Name   string `json:"name"`
	Port   int    `json:"port"`   // 推荐诱饵端口
	Banner string `json:"banner"` // 默认 Banner（http/mysql 不用文本 Banner）
	Desc   string `json:"desc"`   // 能力说明
}

var templates = []Template{
	{Key: "custom", Name: "自定义（仅首包）", Port: 2323, Desc: "读取首包载荷后回写自定义 Banner，仅记录不交互"},
	{Key: "ssh", Name: "SSH 伪装", Port: 2222, Banner: "SSH-2.0-OpenSSH_8.9p1", Desc: "回写 SSH 服务端标识并读取客户端标识，低交互"},
	{Key: "ftp", Name: "FTP 伪登录", Port: 2121, Banner: "220 (vsFTPd 3.0.5)", Desc: "伪 FTP 登录流程，捕获 USER/PASS 明文凭据"},
	{Key: "telnet", Name: "Telnet 伪登录", Port: 2323, Banner: "", Desc: "回显 login/Password 提示，捕获账号密码"},
	{Key: "smtp", Name: "SMTP 伪服务", Port: 2525, Banner: "220 netkit ESMTP Postfix", Desc: "伪邮件服务器，捕获 AUTH LOGIN/PLAIN 凭据"},
	{Key: "pop3", Name: "POP3 伪登录", Port: 1110, Banner: "+OK POP3 server ready", Desc: "伪 POP3 登录，捕获 USER/PASS 明文凭据"},
	{Key: "http", Name: "Web 伪登录", Port: 8088, Desc: "返回伪造登录页/假 API，捕获表单凭据，识别 AI Agent 与扫描器 UA"},
	{Key: "redis", Name: "Redis 伪服务", Port: 6380, Desc: "应答 PING/AUTH/GET 等命令，捕获 AUTH 密码"},
	{Key: "mysql", Name: "MySQL 伪服务", Port: 3307, Desc: "回写握手包并读取认证包，捕获登录用户名（密码为散列不可还原）"},
	{Key: "rdp", Name: "RDP 伪服务", Port: 3390, Desc: "读取 X.224 连接请求中的 mstshash Cookie，捕获登录名"},
}

// Templates 返回服务模板清单。
func Templates() []Template { return templates }

// tmpl 查找模板，未命中返回自定义模板。
func tmpl(key string) Template {
	for _, t := range templates {
		if t.Key == key {
			return t
		}
	}
	return templates[0]
}

// sessResult 一次连接的会话捕获结果。
type sessResult struct {
	Payload string   // 首包/首条指令
	UA      string   // HTTP User-Agent
	Tag     string   // AI Agent / 扫描器
	Creds   []string // 捕获凭据，如 user=admin pass=123456
}

// runSession 按服务模板分派会话逻辑。
func runSession(conn net.Conn, svc, banner string) sessResult {
	if svc == "" {
		svc = "custom"
	}
	if banner == "" {
		banner = tmpl(svc).Banner
	}
	switch svc {
	case "http":
		return runHTTP(conn)
	case "mysql":
		return runMySQL(conn)
	case "rdp":
		return runRDP(conn)
	case "redis":
		return runRedis(conn, banner)
	case "ftp", "telnet", "smtp", "pop3":
		writeAll(conn, banner)
		return runLines(conn, svc)
	case "ssh":
		writeAll(conn, banner) // 服务端先发标识，诱使客户端回标识
		var r sessResult
		r.Payload = readLine(conn, 4*time.Second)
		return r
	default: // custom：先读首包再回写 Banner
		var r sessResult
		r.Payload = readLine(conn, 3*time.Second)
		writeAll(conn, banner)
		return r
	}
}

// ---- 通用小工具 ----

func writeAll(conn net.Conn, s string) {
	if s == "" {
		return
	}
	_ = conn.SetWriteDeadline(time.Now().Add(3 * time.Second))
	_, _ = conn.Write([]byte(s))
}

// readLine 限时读取一行（或首个块）并清洗为可打印文本。
func readLine(conn net.Conn, d time.Duration) string {
	_ = conn.SetReadDeadline(time.Now().Add(d))
	br := bufio.NewReaderSize(conn, 4096)
	line, err := br.ReadString('\n')
	if line == "" && err != nil {
		return ""
	}
	return printable(line)
}

func printable(s string) string {
	return cleanPayload([]byte(s))
}

// stripTelnetIAC 去除 Telnet IAC 协商序列，只留用户输入。
func stripTelnetIAC(s string) string {
	var b []byte
	for i := 0; i < len(s); i++ {
		if s[i] != 0xff {
			b = append(b, s[i])
			continue
		}
		if i+1 >= len(s) {
			break
		}
		switch s[i+1] {
		case 251, 252, 253, 254: // WILL/WONT/DO/DONT + option
			i += 2
		case 250: // SB ... IAC SE
			j := i + 2
			for j+1 < len(s) && !(s[j] == 0xff && s[j+1] == 240) {
				j++
			}
			i = j + 1
		default:
			i++
		}
	}
	return string(b)
}

// addCred 追加凭据（去重）。
func addCred(r *sessResult, c string) {
	if c == "" {
		return
	}
	for _, x := range r.Creds {
		if x == c {
			return
		}
	}
	r.Creds = append(r.Creds, c)
}

// ---- 行协议族：FTP / Telnet / SMTP / POP3 ----

func runLines(conn net.Conn, svc string) sessResult {
	var r sessResult
	_ = conn.SetDeadline(time.Now().Add(12 * time.Second))
	br := bufio.NewReaderSize(conn, 4096)
	if svc == "telnet" {
		// IAC WILL ECHO / WILL SGA + 登录提示
		writeAll(conn, "\xff\xfb\x01\xff\xfb\x03login: ")
	}
	var user, pass string
	authStage := 0 // SMTP AUTH LOGIN：1=已要用户名 2=已要密码
	for i := 0; i < 32; i++ {
		_ = conn.SetReadDeadline(time.Now().Add(12 * time.Second))
		line, err := br.ReadString('\n')
		if line == "" {
			if err != nil {
				break
			}
			continue
		}
		if svc == "telnet" {
			line = stripTelnetIAC(line)
		}
		text := printable(strings.TrimRight(line, "\r\n"))
		if strings.TrimSpace(text) == "" {
			continue
		}
		if r.Payload == "" {
			r.Payload = text
		}
		reply := handleLine(svc, text, &user, &pass, &authStage, &r)
		writeAll(conn, reply)
		if err != nil {
			break
		}
	}
	return r
}

// handleLine 解析一行输入，提取凭据并给出协议应答。
func handleLine(svc, line string, user, pass *string, authStage *int, r *sessResult) string {
	up := strings.ToUpper(line)
	arg := func(prefix string) string {
		if len(line) > len(prefix) {
			return strings.TrimSpace(line[len(prefix):])
		}
		return ""
	}
	pair := func() string {
		if *user != "" && *pass != "" {
			return fmt.Sprintf("user=%s pass=%s", *user, *pass)
		}
		if *pass != "" {
			return "pass=" + *pass
		}
		return "user=" + *user
	}

	switch svc {
	case "ftp":
		switch {
		case strings.HasPrefix(up, "USER "):
			*user = arg("USER ")
			addCred(r, "user="+*user)
			return "331 Please specify the password\r\n"
		case strings.HasPrefix(up, "PASS "):
			*pass = arg("PASS ")
			addCred(r, pair())
			return "530 Login incorrect\r\n"
		case up == "QUIT":
			return "221 Goodbye\r\n"
		}
		return "500 Command not understood\r\n"
	case "pop3":
		switch {
		case strings.HasPrefix(up, "USER "):
			*user = arg("USER ")
			addCred(r, "user="+*user)
			return "+OK\r\n"
		case strings.HasPrefix(up, "PASS "):
			*pass = arg("PASS ")
			addCred(r, pair())
			return "-ERR Authentication failed\r\n"
		case up == "QUIT":
			return "+OK\r\n"
		}
		return "-ERR\r\n"
	case "telnet":
		if *user == "" {
			*user = strings.TrimSpace(line)
			addCred(r, "user="+*user)
			return "\r\nPassword: "
		}
		if *pass == "" {
			*pass = strings.TrimSpace(line)
			addCred(r, pair())
			*user, *pass = "", "" // 允许继续捕获下一组尝试
			return "\r\nLogin incorrect\r\nlogin: "
		}
		return ""
	case "smtp":
		if strings.HasPrefix(up, "AUTH LOGIN") {
			if rest := arg("AUTH LOGIN"); rest != "" {
				if u := b64(rest); u != "" {
					*user = u
					addCred(r, "user="+u)
					*authStage = 2
					return "334 UGFzc3dvcmQ6\r\n"
				}
			}
			*authStage = 1
			return "334 VXNlcm5hbWU6\r\n"
		}
		if strings.HasPrefix(up, "AUTH PLAIN") {
			if raw := b64(arg("AUTH PLAIN")); raw != "" {
				parts := strings.Split(raw, "\x00")
				if len(parts) == 3 {
					*user, *pass = parts[0], parts[2]
				} else if len(parts) == 2 {
					*user, *pass = parts[0], parts[1]
				}
				addCred(r, pair())
			}
			return "235 2.7.0 Authentication successful\r\n"
		}
		if *authStage == 1 {
			*user = b64(strings.TrimSpace(line))
			addCred(r, "user="+*user)
			*authStage = 2
			return "334 UGFzc3dvcmQ6\r\n"
		}
		if *authStage == 2 {
			*pass = b64(strings.TrimSpace(line))
			addCred(r, pair())
			*authStage = 0
			return "235 2.7.0 Authentication successful\r\n"
		}
		switch {
		case strings.HasPrefix(up, "EHLO"), strings.HasPrefix(up, "HELO"):
			return "250-netkit\r\n250 AUTH PLAIN LOGIN\r\n"
		case strings.HasPrefix(up, "MAIL FROM"):
			return "250 2.1.0 Ok\r\n"
		case strings.HasPrefix(up, "RCPT TO"):
			return "250 2.1.5 Ok\r\n"
		case up == "DATA":
			return "354 End data with <CR><LF>.<CR><LF>\r\n"
		case up == "QUIT":
			return "221 2.0.0 Bye\r\n"
		}
		return "502 5.5.2 Error: command not recognized\r\n"
	}
	return ""
}

func b64(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return ""
	}
	return string(b)
}

// ---- Web 伪登录（同时识别 AI Agent / 扫描器 UA） ----

var aiUAKeys = []string{
	"claude", "anthropic", "codex", "gpt", "chatgpt", "openai", "perplexity",
	"gemini", "deepseek", "mistral", "cohere", "ccbot", "bytespider",
	"meta-externalagent", "amazonbot", "ai21", "moonshot",
}
var scanUAKeys = []string{
	"sqlmap", "nmap", "masscan", "zgrab", "nikto", "nuclei", "dirsearch",
	"gobuster", "feroxbuster", "wpscan", "acunetix", "nessus", "burp",
	"python-requests", "go-http-client", "curl/", "wget", "libwww", "scrapy",
	"httpx", "dirbuster", "whatweb", "havij", "appscan", "netsparker", "w3af",
}

// classifyUA 识别请求是否来自 AI Agent 或自动化扫描器。
func classifyUA(ua string) string {
	l := strings.ToLower(ua)
	if l == "" {
		return ""
	}
	for _, k := range aiUAKeys {
		if strings.Contains(l, k) {
			return "AI Agent"
		}
	}
	for _, k := range scanUAKeys {
		if strings.Contains(l, k) {
			return "扫描器"
		}
	}
	return ""
}

func runHTTP(conn net.Conn) sessResult {
	var r sessResult
	_ = conn.SetDeadline(time.Now().Add(12 * time.Second))
	br := bufio.NewReaderSize(conn, 64*1024)

	reqLine, err := br.ReadString('\n')
	if (err != nil && reqLine == "") || strings.TrimSpace(reqLine) == "" {
		return r
	}
	fields := strings.Fields(strings.TrimRight(reqLine, "\r\n"))
	if len(fields) < 2 {
		return r
	}
	method, path := fields[0], fields[1]
	r.Payload = method + " " + path

	hdr := map[string]string{}
	bodyLen := 0
	for {
		l, e := br.ReadString('\n')
		l = strings.TrimRight(l, "\r\n")
		if l == "" {
			if e != nil {
				break
			}
			break
		}
		if i := strings.Index(l, ":"); i > 0 {
			k := strings.ToLower(strings.TrimSpace(l[:i]))
			v := strings.TrimSpace(l[i+1:])
			hdr[k] = v
			if k == "content-length" {
				bodyLen, _ = strconv.Atoi(v)
			}
		}
		if e != nil {
			break
		}
	}
	r.UA = hdr["user-agent"]
	r.Tag = classifyUA(r.UA)

	if bodyLen > 0 {
		if bodyLen > 64*1024 {
			bodyLen = 64 * 1024
		}
		body := make([]byte, bodyLen)
		if _, e := io.ReadFull(br, body); e == nil {
			if c := parseFormCred(hdr["content-type"], string(body)); c != "" {
				addCred(&r, c)
			}
		}
	}

	writeAll(conn, httpResponse(method, path, r.Creds))
	return r
}

// parseFormCred 从表单/JSON 请求体里提取账号密码。
func parseFormCred(contentType, body string) string {
	if strings.TrimSpace(body) == "" {
		return ""
	}
	userKeys := []string{"username", "user", "account", "email", "login", "name", "mobile", "phone"}
	passKeys := []string{"password", "passwd", "pwd", "pass", "passcode"}
	get := func(m map[string]string, keys []string) string {
		for _, k := range keys {
			if v, ok := m[k]; ok && strings.TrimSpace(v) != "" {
				return strings.TrimSpace(v)
			}
			for mk, mv := range m {
				if strings.EqualFold(mk, k) && strings.TrimSpace(mv) != "" {
					return strings.TrimSpace(mv)
				}
			}
		}
		return ""
	}
	vals := map[string]string{}
	if strings.Contains(strings.ToLower(contentType), "json") {
		var m map[string]any
		if json.Unmarshal([]byte(body), &m) == nil {
			for k, v := range m {
				if s, ok := v.(string); ok {
					vals[k] = s
				}
			}
		}
	} else if q, e := url.ParseQuery(body); e == nil {
		for k, v := range q {
			if len(v) > 0 {
				vals[k] = v[0]
			}
		}
	}
	u, p := get(vals, userKeys), get(vals, passKeys)
	if u != "" && p != "" {
		return fmt.Sprintf("user=%s pass=%s", u, p)
	}
	if p != "" {
		return "pass=" + p
	}
	if u != "" {
		return "user=" + u
	}
	return ""
}

// httpResponse 伪造的 Web 登录页 / 假 API 响应。
func httpResponse(method, path string, creds []string) string {
	isAPI := strings.Contains(path, "/api")
	status, ctype, body := "200 OK", "text/html; charset=utf-8", ""
	token := fmt.Sprintf("hp_%d", time.Now().UnixNano())

	switch {
	case isAPI && method == "GET":
		status, ctype = "401 Unauthorized", "application/json; charset=utf-8"
		body = `{"code":401,"message":"unauthorized","data":null}`
	case isAPI:
		ctype = "application/json; charset=utf-8"
		// 金丝雀样式假令牌：真实环境中从未被使用，一旦被调用即暴露内网入侵
		body = fmt.Sprintf(`{"code":200,"message":"ok","token":"%s","session":"anonymous"}`, token)
	case len(creds) > 0:
		body = `<!doctype html><html lang="zh"><head><meta charset="utf-8"><title>控制台</title></head>` +
			`<body style="font-family:sans-serif;max-width:460px;margin:60px auto"><h2>登录成功</h2>` +
			`<p>欢迎回来，正在跳转到管理后台…</p><p style="color:#888;font-size:13px">session: ` + token + `</p></body></html>`
	default:
		body = `<!doctype html><html lang="zh"><head><meta charset="utf-8"><title>登录</title></head>` +
			`<body style="font-family:sans-serif;max-width:420px;margin:60px auto"><h2>管理后台登录</h2>` +
			`<form method="post" action="` + htmlAttr(path) + `">` +
			`<p><label>账号<br><input name="username" autocomplete="username"></label></p>` +
			`<p><label>密码<br><input name="password" type="password" autocomplete="current-password"></label></p>` +
			`<p><button type="submit">登 录</button></p></form></body></html>`
	}
	return fmt.Sprintf("HTTP/1.1 %s\r\nServer: nginx/1.24.0\r\nContent-Type: %s\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s",
		status, ctype, len(body), body)
}

func htmlAttr(s string) string {
	return strings.NewReplacer(`"`, "&quot;", `<`, "&lt;", `>`, "&gt;").Replace(s)
}

// ---- Redis 伪服务 ----

func runRedis(conn net.Conn, banner string) sessResult {
	var r sessResult
	writeAll(conn, banner)
	_ = conn.SetDeadline(time.Now().Add(12 * time.Second))
	br := bufio.NewReaderSize(conn, 4096)
	for i := 0; i < 24; i++ {
		args := readRespCmd(conn, br)
		if len(args) == 0 {
			break
		}
		cmd := strings.ToUpper(args[0])
		if r.Payload == "" {
			r.Payload = strings.Join(args, " ")
		}
		switch cmd {
		case "AUTH":
			if len(args) > 1 {
				addCred(&r, "pass="+args[1])
			}
			writeAll(conn, "+OK\r\n")
		case "HELLO":
			writeAll(conn, "-ERR unknown command 'HELLO'\r\n")
		case "PING":
			writeAll(conn, "+PONG\r\n")
		case "GET", "EXISTS", "TTL", "TYPE", "STRLEN", "LLEN", "HLEN", "SCARD", "ZCARD":
			writeAll(conn, "$-1\r\n")
		default:
			writeAll(conn, "+OK\r\n")
		}
	}
	return r
}

// readRespCmd 读取一个 Redis 命令（RESP 数组或行内协议），返回参数列表。
func readRespCmd(conn net.Conn, br *bufio.Reader) []string {
	_ = conn.SetReadDeadline(time.Now().Add(12 * time.Second))
	line, err := br.ReadString('\n')
	if err != nil && line == "" {
		return nil
	}
	line = strings.TrimRight(line, "\r\n")
	if strings.HasPrefix(line, "*") {
		n, e := strconv.Atoi(strings.TrimPrefix(line, "*"))
		if e != nil || n <= 0 || n > 32 {
			return nil
		}
		args := make([]string, 0, n)
		for i := 0; i < n; i++ {
			_ = conn.SetReadDeadline(time.Now().Add(12 * time.Second))
			if _, e := br.ReadString('\n'); e != nil { // $len 行
				break
			}
			_ = conn.SetReadDeadline(time.Now().Add(12 * time.Second))
			v, e := br.ReadString('\n')
			if e != nil && v == "" {
				break
			}
			args = append(args, printable(strings.TrimRight(v, "\r\n")))
		}
		return args
	}
	if line == "" {
		return nil
	}
	return strings.Fields(printable(line))
}

// ---- MySQL 伪握手（捕获登录用户名） ----

func runMySQL(conn net.Conn) sessResult {
	var r sessResult
	_ = conn.SetDeadline(time.Now().Add(12 * time.Second))
	if _, err := conn.Write(mysqlGreeting()); err != nil {
		return r
	}
	// 读取客户端认证包
	hdr := make([]byte, 4)
	if _, err := io.ReadFull(conn, hdr); err != nil {
		return r
	}
	plen := int(hdr[0]) | int(hdr[1])<<8 | int(hdr[2])<<16
	if plen <= 0 || plen > 4096 {
		return r
	}
	payload := make([]byte, plen)
	if _, err := io.ReadFull(conn, payload); err != nil {
		return r
	}
	r.Payload = fmt.Sprintf("MySQL 登录包 %d 字节", plen)
	// 认证包：能力4 + 最大包4 + 字符集1 + 保留23 = 32 字节后是 NUL 结尾的用户名
	if len(payload) > 34 {
		start := 32
		end := start
		for end < len(payload) && end-start < 64 && payload[end] != 0 {
			end++
		}
		name := string(payload[start:end])
		if isPrintASCII(name) && name != "" {
			addCred(&r, "user="+name)
			r.Payload = "MySQL 登录 user=" + name
		}
	}
	// 回写 Access denied 应答，保持会话真实感
	msg := fmt.Sprintf("Access denied for user '%s'@'127.0.0.1' (using password: YES)", lastUserOrUnknown(r))
	body := []byte{0xff, 0x15, 0x04, '#'}
	body = append(body, []byte("28000")...)
	body = append(body, []byte(msg)...)
	pkt := make([]byte, 0, len(body)+4)
	pkt = append(pkt, byte(len(body)), 0, 0, 2) // 长度 + 序号 2
	pkt = append(pkt, body...)
	_, _ = conn.Write(pkt)
	return r
}

func lastUserOrUnknown(r sessResult) string {
	for _, c := range r.Creds {
		if strings.HasPrefix(c, "user=") {
			return strings.TrimPrefix(c, "user=")
		}
	}
	return "root"
}

func isPrintASCII(s string) bool {
	for _, c := range s {
		if c < 0x20 || c > 0x7e {
			return false
		}
	}
	return true
}

// mysqlGreeting 构造 MySQL 8.0 伪握手包（seq=0）。
func mysqlGreeting() []byte {
	var p []byte
	p = append(p, 0x0a)                          // protocol version
	p = append(p, []byte("8.0.39\x00")...)       // server version
	p = append(p, 0x01, 0x00, 0x00, 0x00)        // connection id
	p = append(p, []byte("netkit01")...)         // auth-plugin-data-part-1 (8)
	p = append(p, 0x00)                          // filler
	p = append(p, 0xff, 0xf7)                    // capability flags (lower)
	p = append(p, 0x21)                          // charset utf8
	p = append(p, 0x02, 0x00)                    // status
	p = append(p, 0x00, 0x08)                    // capability flags (upper, PLUGIN_AUTH)
	p = append(p, 21)                            // auth plugin data len
	p = append(p, make([]byte, 10)...)           // reserved
	p = append(p, []byte("\x12\x34\x56\x78\x9a\xbc\xde\xf0\x11\x22\x33\x44\x00")...)
	p = append(p, []byte("mysql_native_password\x00")...)
	pkt := make([]byte, 0, len(p)+4)
	pkt = append(pkt, byte(len(p)), byte(len(p)>>8), byte(len(p)>>16), 0)
	return append(pkt, p...)
}

// ---- RDP 伪服务（捕获 mstshash Cookie 中的登录名） ----

var reMstshash = regexp.MustCompile(`(?i)mstshash\s*=\s*([^\s;\r\n]+)`)

func runRDP(conn net.Conn) sessResult {
	var r sessResult
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, 2048)
	n, _ := conn.Read(buf)
	if n == 0 {
		return r
	}
	r.Payload = printable(string(buf[:n]))
	if m := reMstshash.FindStringSubmatch(string(buf[:n])); len(m) == 2 {
		addCred(&r, "user="+m[1])
	}
	return r
}
