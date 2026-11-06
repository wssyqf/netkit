#!/bin/sh
# NetKit 一键安装 / 升级（支持 Alpine(OpenRC) 与 Debian/Ubuntu/RHEL(systemd)）
#
# 用法：把发布包传到目标机后执行
#   tar xzf netkit-<版本>-linux-<架构>.tar.gz
#   cd netkit-<版本>-linux-<架构>
#   sudo sh install.sh
#
# 环境变量：
#   INSTALL_DIR   安装目录（默认 /opt/netkit）
#   ADMIN_PORT    期望的后台端口，仅用于安装后的探活提示（默认从配置读，缺省 36601）
set -eu

APP=netkit
DIR=${INSTALL_DIR:-/opt/netkit}
CONF="$DIR/netkit.conf"

# ---------- 前置检查 ----------
[ "$(id -u)" = "0" ] || { echo "[x] 请用 root 运行：sudo sh install.sh"; exit 1; }

ARCH=$(uname -m)
case "$ARCH" in
  x86_64|amd64)  ARCH_ALT=amd64 ;;
  aarch64|arm64) ARCH_ALT=arm64 ;;
  *) echo "[x] 不支持的架构：$ARCH（仅提供 x86_64 / aarch64 构建）"; exit 1 ;;
esac

# ---------- 定位包内二进制 ----------
BIN=""
for c in "$APP" "${APP}-linux-${ARCH_ALT}" "${APP}-linux-$(uname -m)" "bin/$APP"; do
  [ -f "$c" ] && { BIN=$c; break; }
done
[ -n "$BIN" ] || { echo "[x] 当前目录没找到 NetKit 二进制，请在解包后的目录里运行本脚本"; exit 1; }

if command -v file >/dev/null 2>&1; then
  if file "$BIN" | grep -q "ELF"; then :; else
    echo "[x] $BIN 不是 Linux ELF 可执行文件（可能选错了发布包架构：$ARCH）"; exit 1
  fi
fi
echo "[*] 安装 NetKit（架构 $ARCH）→ $DIR"

# ---------- 停旧服务（升级场景） ----------
if command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
  INIT=systemd; systemctl stop $APP >/dev/null 2>&1 || true
elif command -v rc-update >/dev/null 2>&1; then
  INIT=openrc; rc-service $APP stop >/dev/null 2>&1 || true
else
  INIT=none; pkill -x $APP >/dev/null 2>&1 || true
fi

# ---------- 落盘文件（配置与 GeoIP 库不覆盖） ----------
mkdir -p "$DIR/geo"
cp -f "$BIN" "$DIR/$APP"
chmod 755 "$DIR/$APP"

if [ -f "geo/GeoLite2-Country.mmdb" ] && [ ! -f "$DIR/geo/GeoLite2-Country.mmdb" ]; then
  cp -f geo/GeoLite2-Country.mmdb "$DIR/geo/"
  echo "[+] 已安装 GeoIP 区域库"
else
  echo "[*] GeoIP 库保持现状（缺失时区域拦截自动降级为放行）"
fi
[ -f "$CONF" ] && echo "[*] 保留已有配置 $CONF" || echo "[*] 首次安装：启动后生成默认配置（默认账号 666 / 666，请立即修改）"

# ---------- 注册系统服务 ----------
case "$INIT" in
systemd)
  cat > /etc/systemd/system/$APP.service <<EOF
[Unit]
Description=NetKit 网络工具箱
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
WorkingDirectory=$DIR
ExecStart=$DIR/$APP -c $CONF
Restart=on-failure
RestartSec=3
LimitNOFILE=65535

[Install]
WantedBy=multi-user.target
EOF
  systemctl daemon-reload
  systemctl enable $APP >/dev/null 2>&1
  systemctl start $APP
  echo "[+] systemd 服务已安装并启动：systemctl status $APP"
  ;;
openrc)
  cat > /etc/init.d/$APP <<'EOF'
#!/sbin/openrc-run

name="NetKit"
description="NetKit 多合一网络工具箱"

supervisor=supervise-daemon
command="/opt/netkit/netkit"
command_args="-c /opt/netkit/netkit.conf"
pidfile="/run/${RC_SVCNAME}.pid"
directory="/opt/netkit"

output_log="/var/log/netkit.log"
error_log="/var/log/netkit.err"

depend() {
    need net
    after firewall
}
EOF
  # 支持自定义安装目录
  if [ "$DIR" != "/opt/netkit" ]; then
    sed -i "s|/opt/netkit|$DIR|g" /etc/init.d/$APP
  fi
  chmod 755 /etc/init.d/$APP
  rc-update add $APP default >/dev/null 2>&1 || true
  rc-service $APP start
  echo "[+] OpenRC 服务已安装并启动：rc-service $APP status"
  ;;
none)
  echo "[!] 未检测到 systemd/OpenRC，已直接启动进程（无守护，重启不自启）"
  ( cd "$DIR" && nohup "./$APP" -c "$CONF" > /var/log/$APP.log 2>&1 & )
  ;;
esac

# ---------- 探活 ----------
sleep 2
PORT=${ADMIN_PORT:-}
if [ -z "$PORT" ] && [ -f "$CONF" ]; then
  PORT=$(grep -o '"adminPort"[[:space:]]*:[[:space:]]*[0-9]*' "$CONF" | head -1 | grep -o '[0-9]*$' || true)
fi
PORT=${PORT:-36601}

OK=""
if command -v curl >/dev/null 2>&1; then
  CODE=$(curl -s -o /dev/null -w '%{http_code}' --max-time 5 "http://127.0.0.1:$PORT/" || echo 000)
  [ "$CODE" = "200" ] && OK=1
else
  wget -q -T 5 -O /dev/null "http://127.0.0.1:$PORT/" 2>/dev/null && OK=1
fi

echo "------------------------------------------"
if [ -n "$OK" ]; then
  echo "[√] 安装成功，后台已就绪"
  echo "    访问：http://<本机IP>:$PORT"
  echo "    默认账号 666 / 666，首次登录后请立即在「设置」页修改"
else
  echo "[!] 服务已启动但 127.0.0.1:$PORT 尚未就绪，请检查日志："
  echo "    systemd: journalctl -u $APP -n 20"
  echo "    OpenRC : tail -20 /var/log/netkit.log"
fi
echo "    放行端口：firewall-cmd --add-port=$PORT/tcp 或 ufw allow $PORT/tcp"
echo "------------------------------------------"
