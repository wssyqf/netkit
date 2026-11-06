package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"
	"path/filepath"

	"netkit/internal/acme"
	"netkit/internal/admin"
	"netkit/internal/config"
	"netkit/internal/cron"
	"netkit/internal/ddns"
	"netkit/internal/geoip"
	"netkit/internal/honeypot"
	"netkit/internal/portforward"
	"netkit/internal/reverseproxy"
	"netkit/internal/waf"
)

const version = "v0.3.0"

func main() {
	log.SetFlags(log.LstdFlags)
	var confPath string
	var adminPort int
	flag.StringVar(&confPath, "c", "netkit.conf", "配置文件路径")
	flag.IntVar(&adminPort, "p", 0, "后台管理端口（覆盖配置文件）")
	flag.Parse()

	if !filepath.IsAbs(confPath) {
		abs, err := filepath.Abs(confPath)
		if err == nil {
			confPath = abs
		}
	}

	store := config.NewStore(confPath)
	if err := store.Load(); err != nil {
		log.Fatalf("加载配置失败: %v", err)
	}
	base := store.GetBase()
	if adminPort > 0 {
		base.AdminPort = adminPort
	}

	fmt.Printf("netkit %s\n后台管理地址: http://127.0.0.1:%d  配置文件: %s\n", version, base.AdminPort, confPath)

	// 按配置启动各功能模块
	cfg := store.Get()
	geoip.Load(filepath.Join(filepath.Dir(confPath), "geo", "GeoLite2-Country.mmdb"))
	portforward.Default().SetStore(store)
	portforward.Default().SetGlobalFilter(admin.BuildGlobalFilter(store))
	portforward.Default().Apply(cfg.PortForwards)
	reverseproxy.Default().SetStore(store)
	reverseproxy.Default().SetGlobalFilter(admin.BuildGlobalFilter(store))
	reverseproxy.Default().Apply(cfg.WebRules)
	ddns.Default().Apply(cfg.DDNS)
	cron.Default().Apply(cfg.CronTasks)
	acme.Default().SetStore(store)
	acme.Default().Apply()
	waf.Default().Apply(cfg.WAF)
	// 蜜罐：预留管理端口与各模块监听端口，避免冲突
	honeypot.Default().SetStore(store)
	honeypot.Default().SetReservedPorts(admin.ReservedPorts(cfg, base.AdminPort))
	honeypot.Default().Apply(cfg.Honeypot)

	srv := admin.NewServer(store)
	srv.SetFilter(admin.BuildGlobalFilter(store))
	srv.SetWAFGuard(func() func(http.Handler) http.Handler {
		if !cfg.WAF.Enabled || !cfg.WAF.ApplyAdmin {
			return nil
		}
		return func(h http.Handler) http.Handler {
			wrapped, err := waf.Default().WrapHandler(h)
			if err != nil {
				return h
			}
			return wrapped
		}
	}())
	addr := fmt.Sprintf(":%d", base.AdminPort)
	server := &http.Server{Addr: addr, Handler: srv.Handler()}
	log.Printf("[后台] 开始监听 %s", addr)
	if err := server.ListenAndServe(); err != nil {
		log.Fatalf("后台服务启动失败: %v", err)
	}
}
