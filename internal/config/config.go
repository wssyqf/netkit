package config

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
)

// 全局配置结构。所有模块的持久化配置都放在同一个 JSON 文件里，
// 各模块持有自己的段落，风格与 lucky 的单配置文件一致。
type Config struct {
	Base           BaseConfig        `json:"base"`
	PortForwards   []PortForwardRule `json:"portforwards"`
	WebRules       []WebRule         `json:"webrules"`
	DDNS           []DDNSTask        `json:"ddns"`
	IPDB           []IPDBEntry       `json:"ipdb"`
	SecurityGroups []SecurityGroup   `json:"securitygroups"`
	IPFilter       GlobalIPFilter    `json:"ipfilter"`
	CronTasks      []CronTask        `json:"crons"`
	SSLCerts       []SSLCert         `json:"sslcerts"`
	WAF            WAFConfig         `json:"waf"`
	Honeypot       HoneypotConfig    `json:"honeypot"`
	Groups         []Group           `json:"groups"`
	GlobalWebhook  Webhook           `json:"globalWebhook"` // 全局通知，接收所有模块事件
	AI             AIConfig          `json:"ai"`            // AI 大模型维护
}

// AIConfig AI 大模型维护配置：OpenAI 兼容 /chat/completions 协议，
// BaseURL 如 https://api.deepseek.com/v1，覆盖 DeepSeek/通义/Kimi/OpenAI/Ollama。
type AIConfig struct {
	Enabled bool   `json:"enabled"`
	BaseURL string `json:"baseURL"`
	APIKey  string `json:"apiKey"`
	Model   string `json:"model"`
	Proxy   string `json:"proxy"` // 可选 http/https 代理，出网受限时使用
}

// Group 通用分组，可用于端口转发 / Web 服务 / DDNS 等模块归类。
type Group struct {
	ID    string `json:"id"`
	Name  string `json:"name"`
	Color string `json:"color"` // 可选：blue/green/amber/violet/red/teal
	Note  string `json:"note"`
}

// ---- WAF（Coraza） ----

type WAFConfig struct {
	Enabled    bool        `json:"enabled"`    // 全局总开关
	Mode       string      `json:"mode"`       // block（拦截）/ detect（仅记录）
	ApplyAdmin bool        `json:"applyAdmin"` // 是否防护后台自身
	Rulesets   WAFRulesets `json:"rulesets"`
	ExtraRules string      `json:"extraRules"` // 自定义 SecRule 追加规则
	TrustedIPs []string    `json:"trustedIPs"` // 跳过检测的 IP/CIDR
	MaxBodyKB  int         `json:"maxBodyKB"`  // 请求体检测上限（KB）
	RateLimit  int         `json:"rateLimit"`  // 频率限制：每 IP 每分钟请求数上限，0=不限制
	// 远程规则源自动更新
	RulesAutoUpdate  bool   `json:"rulesAutoUpdate"`  // 是否定时拉取远程规则
	RulesFeedURL     string `json:"rulesFeedURL"`     // 兼容 Coraza 语法的规则文件 URL
	RulesUpdateHours int    `json:"rulesUpdateHours"` // 检查间隔（小时），默认 24
	RemoteRules      string `json:"remoteRules"`      // 已下载的远程规则内容（持久化）
	LastRulesUpdate  int64  `json:"lastRulesUpdate"`  // 上次更新 unix 秒
	LastRulesMsg     string `json:"lastRulesMsg"`     // 上次更新结果描述
}

// ---- 蜜罐诱捕 ----

// HoneypotConfig 蜜罐全局配置：开放诱饵端口捕获扫描/入侵尝试。
type HoneypotConfig struct {
	Enabled bool           `json:"enabled"`
	Ports   []HoneypotPort `json:"ports"`
}

// HoneypotPort 一个诱饵端口。
type HoneypotPort struct {
	ID       string `json:"id"`
	ListenIP string `json:"listenIP"` // 空 = 0.0.0.0
	Port     int    `json:"port"`
	Banner   string `json:"banner"` // 连接后回写的欢迎语，空 = 只读不回
	Remark   string `json:"remark"`
	Enabled  bool   `json:"enabled"`
	Service  string `json:"service"` // 服务模板：custom/ssh/ftp/telnet/smtp/pop3/http/redis/mysql/rdp
}

// WAFRulesets 内置规则集开关。
type WAFRulesets struct {
	SQLi          bool `json:"sqli"`
	XSS           bool `json:"xss"`
	PathTraversal bool `json:"pathTraversal"`
	SensitiveFile bool `json:"sensitiveFile"`
	ExploitPath   bool `json:"exploitPath"`
	ScannerUA     bool `json:"scannerUA"`
	BadBot        bool `json:"badBot"`
	CmdInjection  bool `json:"cmdInjection"`
}

// ---- IP 地址库 ----

// IPDBEntry 一条 IP/CIDR 地址，可设置有效期（unix 秒，0 表示永久）。
type IPDBEntry struct {
	ID       string `json:"id"`
	Value    string `json:"value"` // IP 或 CIDR
	Remark   string `json:"remark"`
	ExpireAt int64  `json:"expireAt"` // 0 = 永久
}

// ---- 安全组 ----

// SecurityGroup 一组 IP 地址条目 + 过滤模式，可被反代子规则/全局过滤引用。
type SecurityGroup struct {
	ID      string   `json:"id"`
	Name    string   `json:"name"`
	Mode    string   `json:"mode"` // white / black
	ItemIDs []string `json:"itemIDs"`
}

// ---- 全局 IP 过滤 ----

type GlobalIPFilter struct {
	Mode         string   `json:"mode"`         // none / white / black
	GroupIDs     []string `json:"groupIDs"`     // 引用的安全组
	ApplyAdmin   bool     `json:"applyAdmin"`   // 应用于后台管理访问
	GeoMode      string   `json:"geoMode"`      // ""（停用）/ block 拦截 / detect 仅记录 / allow 放行白名单
	GeoCountries []string `json:"geoCountries"` // block/detect 时要拦截、allow 时要放行的 ISO 3166-1 二位国家码
}

// ---- 计划任务 ----

type CronTask struct {
	ID         string `json:"id"`
	Name       string `json:"name"`
	Cron       string `json:"cron"` // 5 段: 分 时 日 月 周
	Command    string `json:"command"`
	TimeoutSec int    `json:"timeoutSec"`
	Enabled    bool   `json:"enabled"`
}

// ---- SSL 证书 ----

type SSLCert struct {
	ID          string `json:"id"`
	Remark      string `json:"remark"`
	Domain      string `json:"domain"`
	Email       string `json:"email"`
	CA          string `json:"ca"`        // letsencrypt / 自定义
	Directory   string `json:"directory"` // 自定义 ACME 目录地址（留空用 Let's Encrypt）
	CertPEM     string `json:"certPem,omitempty"`
	KeyPEM      string `json:"keyPem,omitempty"`
	NotAfter    int64  `json:"notAfter"`
	Status      string `json:"status"` // ok / error / pending
	ErrMsg      string `json:"errMsg,omitempty"`
	AutoRenew   bool   `json:"autoRenew"`
	Disabled    bool   `json:"disabled,omitempty"` // 停用后不参与反代 TLS 下发、不自动续签（零值=启用，兼容旧配置）
	AdvanceDays int    `json:"advanceDays"` // 到期前多少天续签，默认 30
	// 验证方式：http-01（默认，需 80 端口公网可达）或 dns-01（支持泛域名）
	Challenge string `json:"challenge"`
	DNSSource string `json:"dnsSource"` // dns-01 时的服务商：dnshe / cloudflare
	DNSKey    string `json:"dnsKey"`    // DNSHE: API Key；Cloudflare: API Token
	DNSSecret string `json:"dnsSecret"` // DNSHE: API Secret
}

type BaseConfig struct {
	AdminPort int    `json:"adminPort"`
	Username  string `json:"username"`
	Password  string `json:"password"`
	// 后备账号：仅拥有配置备份与一键还原权限的应急账号，两者均非空才启用
	BackupUsername string    `json:"backupUsername"`
	BackupPassword string    `json:"backupPassword"`
	TFA            TFAConfig `json:"tfa"`
}

// TFAConfig 两步验证（TOTP）配置。
type TFAConfig struct {
	Enabled       bool     `json:"enabled"`
	Secret        string   `json:"secret"`        // Base32 密钥（启用后才有值）
	RecoveryCodes []string `json:"recoveryCodes"` // 一次性恢复码
	// LastUsedWindow 已使用过的时间窗口，防止同一验证码被重放
	LastUsedWindow uint64 `json:"lastUsedWindow"`
}

// ---- 端口转发 ----

type PortForwardRule struct {
	ID          string  `json:"id"`
	Name        string  `json:"name"`
	Proto       string  `json:"proto"` // tcp / udp / tcpudp
	ListenIP    string  `json:"listenIP"`
	ListenPorts []int   `json:"listenPorts"`
	TargetIP    string  `json:"targetIP"`
	TargetPorts []int   `json:"targetPorts"`
	MaxConns    int     `json:"maxConns"`   // 单规则最大并发连接数，0=不限
	FilterMode  string  `json:"filterMode"` // none / black / white
	GroupID     string  `json:"groupID"`    // 引用安全组
	GroupTag    string  `json:"groupTag"`   // 归属分组（仅归类展示）
	Remark      string  `json:"remark"`
	Webhook     Webhook `json:"webhook"` // 规则级通知（异常/恢复）
	Enabled     bool    `json:"enabled"`
}

// ---- Web 服务（反向代理） ----

type HealthCheck struct {
	Enabled   bool              `json:"enabled"`
	Type      string            `json:"type"` // http / tcp
	Path      string            `json:"path"`
	Interval  int               `json:"interval"` // 秒，默认 10
	Timeout   int               `json:"timeout"`  // 秒，默认 3
	MaxFailed int               `json:"maxFailed"`
	Headers   map[string]string `json:"headers"`
}

type LoadBalance struct {
	Policy        string `json:"policy"`        // roundrobin / weighted / iphash
	Sticky        bool   `json:"sticky"`        // 会话保持
	MaxActive     int    `json:"maxActive"`     // 单后端最大并发，0=不限
	RetryCount    int    `json:"retryCount"`    // 失败重试次数
	RetryInterval int    `json:"retryInterval"` // 重试间隔（毫秒）
}

type WebSubRule struct {
	ID         string      `json:"id"`
	Name       string      `json:"name"`
	Type       string      `json:"type"` // 服务类型：proxy（反向代理，默认）/ redirect（重定向）/ urljump（URL跳转）/ file（静态文件）
	Domains    []string    `json:"domains"`
	Backends   []string    `json:"backends"`
	Weights    []int       `json:"weights"`   // 与 Backends 对应的权重
	Locations  []string    `json:"locations"` // URL 路由前缀，空=全部
	BasicUser  string      `json:"basicUser"`
	BasicPass  string      `json:"basicPass"`
	FilterMode string      `json:"filterMode"` // none / black / white
	FilterIPs  []string    `json:"filterIPs"`
	GroupID    string      `json:"groupID"` // 引用安全组（优先于 FilterMode/FilterIPs）
	Health     HealthCheck `json:"health"`
	LB         LoadBalance `json:"lb"`

	// —— 服务类型相关（redirect / urljump / file）——
	Target     string `json:"target"`     // 跳转目标地址，支持 {host}{port}{path}{args} 等变量
	StatusCode int    `json:"statusCode"` // 重定向状态码：301/302/307/308（默认 302）
	DocRoot    string `json:"docRoot"`    // file 类型：静态文件根目录

	// —— 访问控制 ——
	UAMode      string   `json:"uaMode"`      // UserAgent 过滤：none / white / black
	UAList      []string `json:"uaList"`      // UA 关键字（包含匹配）
	CustomRobot bool     `json:"customRobot"` // 自定义 robots.txt
	RobotTxt    string   `json:"robotTxt"`    // robots.txt 内容

	// —— Header 控制 ——
	SetHeaders           map[string]string `json:"setHeaders"`           // 转发给后端的请求头（覆盖）
	HideHeaders          []string          `json:"hideHeaders"`          // 从后端响应中隐藏的头
	AddHeaders           map[string]string `json:"addHeaders"`           // 追加到客户端响应的头
	AppendClientIPHeader string            `json:"appendClientIPHeader"` // 追加客户端 IP 到指定请求头（如 X-Forwarded-Proto 场景）

	// —— 反代行为 ——
	InsecureSkipTLS bool `json:"insecureSkipTLS"` // 忽略后端 HTTPS 证书验证（自签证书）
	UseTargetHost   bool `json:"useTargetHost"`   // 使用目标地址作为转发请求的 Host（反代路由器管理页等场景）
}

type WebRule struct {
	ID              string   `json:"id"`
	Name            string   `json:"name"`
	ListenIP        string   `json:"listenIP"`
	Port            int      `json:"port"`
	TLSCertFile     string   `json:"tlsCertFile"`
	TLSKeyFile      string   `json:"tlsKeyFile"`
	CertID          string   `json:"certID"`          // 引用证书库中的证书（优先于文件路径）
	SamePortTLS     bool     `json:"samePortTLS"`     // 同一端口同时接受 HTTP 与 HTTPS
	RedirectToHTTPS bool     `json:"redirectToHTTPS"` // 明文请求自动跳转 HTTPS
	RedirectCode    int      `json:"redirectCode"`    // 301 / 302 / 308
	RedirectExclude []string `json:"redirectExclude"` // 不跳转的路径前缀（如 /.well-known/）
	GroupID         string   `json:"groupID"`
	Remark          string   `json:"remark"`
	WAFEnabled      bool     `json:"wafEnabled"`
	// 跨域支持
	CORSEnabled     bool         `json:"corsEnabled"`
	CORSOrigin      string       `json:"corsOrigin"`  // * 或具体域名
	CORSMethods     string       `json:"corsMethods"` // 默认 GET,POST,PUT,DELETE,OPTIONS
	CORSHeaders     string       `json:"corsHeaders"` // 允许的请求头
	CORSCredentials bool         `json:"corsCredentials"`
	TrustedCIDRs    []string     `json:"trustedCIDRs"` // 可信代理/CDN 网段，用于还原真实客户端 IP
	DefaultBackends []string     `json:"defaultBackends"`
	DefaultHealth   HealthCheck  `json:"defaultHealth"`
	DefaultLB       LoadBalance  `json:"defaultLB"`
	SubRules        []WebSubRule `json:"subRules"`
	Enabled         bool         `json:"enabled"`
}

// ---- DDNS ----

type DDNSTask struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Provider    string   `json:"provider"`    // cloudflare / dnspod / aliyun / dnshe / huaweicloud / godaddy / porkbun / namecheap / namesilo / callback
	Token       string   `json:"token"`       // cloudflare API Token / dnspod Token / DNSHE API Key
	AccessKeyID string   `json:"accessKeyID"` // aliyun AccessKeyID / huaweicloud AK
	AccessKey   string   `json:"accessKey"`   // aliyun AccessKey / DNSHE API Secret / huaweicloud SK
	Domains     []string `json:"domains"`
	IPv4        bool     `json:"ipv4"`
	IPv6        bool     `json:"ipv6"`
	IntervalSec int      `json:"intervalSec"`
	Proxy       string   `json:"proxy"` // http/https/socks5 代理，留空不启用
	Webhook     Webhook  `json:"webhook"`
	GroupTag    string   `json:"groupTag"`
	Remark      string   `json:"remark"`
	Enabled     bool     `json:"enabled"`

	// 获取公网 IP 方式（对齐 ddns-go：接口 / 网卡 / 指令）
	IPSource    string   `json:"ipSource"`    // api（默认）/ netiface / cmd
	IPURLs      []string `json:"ipUrls"`      // api 模式：自定义接口列表，留空用内置多源
	IPInterface string   `json:"ipInterface"` // netiface 模式：网卡名（如 eth0），留空自动选默认路由网卡
	IPCmd       string   `json:"ipCmd"`       // cmd 模式：执行命令，取 stdout 第一行作为 IP
	TTL         int      `json:"ttl"`         // DNS 记录 TTL（秒），0 = 服务商默认
	CacheTimes  int      `json:"cacheTimes"`  // 每 N 轮才与服务商比对一次（防限流），0 = 每轮比对

	// Callback：自定义回调，可接入任意 DNS 服务商
	CallbackURL    string `json:"callbackURL"`    // 回调地址，支持 #{ip} #{domain} #{recordType} #{ttl} 变量
	CallbackMethod string `json:"callbackMethod"` // GET / POST，留空：Body 为空取 GET，否则 POST
	CallbackBody   string `json:"callbackBody"`   // 请求体模板，留空则发 GET
}

// Webhook 变更通知（可被 STUN / DDNS 复用）。
type Webhook struct {
	Enabled       bool              `json:"enabled"`
	URL           string            `json:"url"`
	Method        string            `json:"method"`      // POST / GET / PUT / PATCH / HEAD
	Body          string            `json:"body"`        // 模板，支持 #{event} #{target} #{ipAddr} #{status} #{result} #{time} #{timestamp}
	ContentType   string            `json:"contentType"` // 默认 application/json
	SuccessText   string            `json:"successText"` // 命中任一即视为成功，多行分隔
	Headers       map[string]string `json:"headers"`
	SkipTLSVerify bool              `json:"skipTLSVerify"`
	Retry         int               `json:"retry"`      // 总尝试次数，默认 1
	TimeoutSec    int               `json:"timeoutSec"` // 单次超时秒数，默认 15
	Secret        string            `json:"secret"`     // 配置后用 HMAC-SHA256 签名
	Events        []string          `json:"events"`     // 只在这些事件触发；空=全部
}

// ---- 存取 ----

type Store struct {
	mu   sync.Mutex
	path string
	data Config
}

func NewStore(path string) *Store {
	return &Store{path: path}
}

// Load 读取配置文件；文件不存在时写入一份默认配置。
func (s *Store) Load() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	migrated := false
	b, err := os.ReadFile(s.path)
	if err != nil {
		if os.IsNotExist(err) {
			s.data = defaultConfig()
			return s.saveLocked()
		}
		return err
	}
	if err := json.Unmarshal(b, &s.data); err != nil {
		return fmt.Errorf("解析配置文件失败: %w", err)
	}
	normalize(&s.data)
	// 端口迁移：旧版本默认 16601 会与 lucky 冲突，自动迁到 36601。
	// 用户在设置页显式改成其它端口时不受影响（只迁移这一个历史默认值）。
	if s.data.Base.AdminPort == legacyDefaultPort {
		s.data.Base.AdminPort = defaultPort
		migrated = true
	}
	s.data.Base = fillBaseDefaults(s.data.Base)
	if migrated {
		return s.saveLocked()
	}
	return nil
}

// normalize 确保所有切片字段非 nil，避免序列化成 null 导致前端异常。
func normalize(c *Config) {
	if c.PortForwards == nil {
		c.PortForwards = []PortForwardRule{}
	}
	if c.WebRules == nil {
		c.WebRules = []WebRule{}
	}
	if c.DDNS == nil {
		c.DDNS = []DDNSTask{}
	}
	if c.IPDB == nil {
		c.IPDB = []IPDBEntry{}
	}
	if c.SecurityGroups == nil {
		c.SecurityGroups = []SecurityGroup{}
	}
	if c.CronTasks == nil {
		c.CronTasks = []CronTask{}
	}
	if c.SSLCerts == nil {
		c.SSLCerts = []SSLCert{}
	}
	if c.Groups == nil {
		c.Groups = []Group{}
	}
	// WAF 首次运行（配置缺失）时填充推荐默认值
	if c.WAF.Mode == "" && c.WAF.MaxBodyKB == 0 {
		c.WAF = WAFConfig{
			Enabled: true, Mode: "block", MaxBodyKB: 128,
			Rulesets: WAFRulesets{
				SQLi: true, XSS: true, PathTraversal: true,
				SensitiveFile: true, ExploitPath: true, ScannerUA: true,
				CmdInjection: true,
			},
			TrustedIPs: []string{},
		}
	}
	if c.WAF.Mode == "" {
		c.WAF.Mode = "block"
	}
	if c.WAF.MaxBodyKB == 0 {
		c.WAF.MaxBodyKB = 128
	}
	if c.WAF.TrustedIPs == nil {
		c.WAF.TrustedIPs = []string{}
	}
	if c.Honeypot.Ports == nil {
		c.Honeypot.Ports = []HoneypotPort{}
	}
}

func defaultConfig() Config {
	c := Config{Base: fillBaseDefaults(BaseConfig{})}
	normalize(&c)
	return c
}

// 默认后台端口与需迁移的历史端口。
const (
	defaultPort       = 36601
	legacyDefaultPort = 16601
)

func fillBaseDefaults(b BaseConfig) BaseConfig {
	if b.AdminPort == 0 {
		b.AdminPort = defaultPort
	}
	if b.Username == "" {
		b.Username = "666"
	}
	if b.Password == "" {
		b.Password = "666"
	}
	return b
}

func (s *Store) saveLocked() error {
	b, err := json.MarshalIndent(s.data, "", "  ")
	if err != nil {
		return err
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, s.path)
}

func (s *Store) Path() string { return filepath.Clean(s.path) }

func (s *Store) Get() Config {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.data
}

func (s *Store) GetBase() BaseConfig {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.data.Base
}

// Update 在锁内整体替换并落盘。
func (s *Store) Update(fn func(c *Config)) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	fn(&s.data)
	normalize(&s.data)
	return s.saveLocked()
}
