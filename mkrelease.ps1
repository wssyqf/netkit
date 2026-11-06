# NetKit 发布打包：交叉编译 linux/amd64 + linux/arm64，附 GeoIP 库与 install.sh，输出 tar.gz
# 用法：powershell -ExecutionPolicy Bypass -File mkrelease.ps1
# 产物：dist/netkit-<版本>-linux-<架构>.tar.gz
$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $root

# 版本号取自 main.go
$m = Select-String -Path (Join-Path $root "main.go") -Pattern 'const version = "([^"]+)"'
if (-not $m) { throw "main.go 中未找到版本号" }
$ver = $m.Matches[0].Groups[1].Value
Write-Host "[*] NetKit $ver 发布打包"

$env:GOPROXY = "https://goproxy.cn,direct"
$env:GOOS = "linux"
$env:CGO_ENABLED = "0"

# GeoIP 库（可选，从现有服务器拉取一次）
$mmdb = Join-Path $root "geo\GeoLite2-Country.mmdb"
if (-not (Test-Path $mmdb)) {
    New-Item -ItemType Directory -Force -Path (Join-Path $root "geo") | Out-Null
    python -c "import sys;sys.path.insert(0,r'e:\aicode\lucky\deploy');import ssh_tool;c=ssh_tool.connect();s=c.open_sftp();s.get('/opt/netkit/geo/GeoLite2-Country.mmdb',r'e:\aicode\lucky\netkit\geo\GeoLite2-Country.mmdb');s.close();c.close();print('geo ok')"
    if ($LASTEXITCODE -ne 0) {
        Write-Warning "GeoIP 拉取失败（可选组件，安装时缺失会降级）"
    } else {
        Write-Host "[+] GeoIP 库已从服务器拉取"
    }
}

$dist = Join-Path $root "dist"
New-Item -ItemType Directory -Force -Path $dist | Out-Null

foreach ($arch in @("amd64", "arm64")) {
    Write-Host "[*] 编译 linux/$arch ..."
    $env:GOARCH = $arch
    $bin = Join-Path $root "netkit-linux-$arch"
    go build -ldflags="-s -w" -o $bin .
    if ($LASTEXITCODE -ne 0) { throw "编译 linux/$arch 失败" }

    $pkg = "netkit-$ver-linux-$arch"
    $stage = Join-Path $dist $pkg
    if (Test-Path $stage) { Remove-Item $stage -Recurse -Force }
    New-Item -ItemType Directory -Force -Path (Join-Path $stage "geo") | Out-Null

    Copy-Item $bin (Join-Path $stage "netkit") -Force
    Copy-Item (Join-Path $root "install.sh") $stage -Force
    if (Test-Path $mmdb) { Copy-Item $mmdb (Join-Path $stage "geo") -Force }

    $tar = Join-Path $dist "$pkg.tar.gz"
    if (Test-Path $tar) { Remove-Item $tar -Force }
    tar -czf $tar -C $dist $pkg
    if ($LASTEXITCODE -ne 0) { throw "打包 $pkg 失败" }
    Write-Host "[+] $tar"
}

Write-Host ""
Write-Host "部署到目标机（Alpine / Debian 均可）："
Write-Host "  scp dist/netkit-$ver-linux-*.tar.gz root@<目标机>:/tmp/"
Write-Host "  ssh root@<目标机>"
Write-Host "  tar xzf /tmp/netkit-$ver-linux-<架构>.tar.gz -C /opt && cd /opt/netkit-$ver-linux-<架构> && sh install.sh"
