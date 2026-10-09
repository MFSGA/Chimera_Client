#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

# 在 macOS 上以前台方式启动 Mihomo TUN + fake-IP。
# 原始配置保持不变；兼容字段和本机监听范围只写入用户私有目录中的副本。

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONFIG_FILE="${CONFIG_FILE:-$SCRIPT_DIR/config.yaml}"
MIHOMO_GZ="${MIHOMO_GZ:-$HOME/Downloads/mihomo-darwin-arm64-v1.19.31.gz}"
STATE_DIR="${MIHOMO_STATE_DIR:-$HOME/Library/Application Support/Mihomo-TUN-FakeIP}"
MIHOMO_BIN="$STATE_DIR/mihomo"
RUNTIME_CONFIG="$STATE_DIR/config.yaml"
LOG_FILE="$STATE_DIR/mihomo.log"

say() { printf '\n==> %s\n' "$*"; }
fail() { printf '错误：%s\n' "$*" >&2; exit 1; }

for tool in ruby gzip sudo ifconfig pgrep tee; do
  command -v "$tool" >/dev/null 2>&1 || fail "缺少命令：$tool"
done

[[ "$(uname -s)" == "Darwin" ]] || fail '此脚本用于 macOS。'
[[ -r "$CONFIG_FILE" ]] || fail "找不到配置文件：$CONFIG_FILE"
[[ -r "$MIHOMO_GZ" ]] || fail "找不到 Mihomo 压缩包：$MIHOMO_GZ"

TUN_DEVICE="$(ruby -ryaml -e '
  config = YAML.load_file(ARGV.fetch(0))
  tun = config["tun"] || {}
  dns = config["dns"] || {}
  abort "配置中 tun.enable 必须为 true" unless tun["enable"] == true
  abort "配置中 dns.enable 必须为 true" unless dns["enable"] == true
  abort "配置中 dns.enhanced-mode 必须为 fake-ip" unless dns["enhanced-mode"] == "fake-ip"
  device = tun["device-id"] || tun["device"] || "utun1989"
  abort "TUN 设备名无效：#{device}" unless device.match?(/\A[A-Za-z0-9._-]+\z/)
  puts device
' "$CONFIG_FILE")" || fail '读取 TUN 配置失败。'

if ifconfig "$TUN_DEVICE" 2>/dev/null | grep -q 'UP'; then
  fail "$TUN_DEVICE 已经处于 UP 状态。为避免和当前 Mihomo/VPN 冲突，本脚本不会启动第二个 TUN 实例；请先停止现有实例。"
fi

sudo -n true >/dev/null 2>&1 || fail 'sudo -n 不可用；需要免密 sudo 来创建 TUN 接口和系统路由。'

mkdir -p "$STATE_DIR"
chmod 700 "$STATE_DIR"

say '解压 Mihomo 到用户私有运行目录'
TEMP_BIN="$STATE_DIR/.mihomo.$$"
trap 'rm -f "$TEMP_BIN"' EXIT
gzip -dc "$MIHOMO_GZ" > "$TEMP_BIN" || fail '解压 Mihomo 失败。'
chmod 700 "$TEMP_BIN"
mv -f "$TEMP_BIN" "$MIHOMO_BIN"
trap - EXIT

say '生成仅供本次运行使用的配置副本'
ruby -ryaml -e '
  source, destination = ARGV
  config = YAML.load_file(source)
  tun = config.fetch("tun")

  # 转换为 Mihomo 接受的字段名；不修改仓库中的原始 YAML。
  tun["device"] = tun.delete("device-id") if tun.key?("device-id")
  tun["auto-route"] = tun.delete("route-all") if tun.key?("route-all")
  if tun["dns-hijack"] == true
    tun["dns-hijack"] = ["any:53", "tcp://any:53"]
  end

  # TUN 以外的本机监听器仅绑定回环地址，且不向局域网开放。
  config["allow-lan"] = false
  config["bind-address"] = "127.0.0.1"

  File.write(destination, YAML.dump(config))
  File.chmod(0600, destination)
' "$CONFIG_FILE" "$RUNTIME_CONFIG" || fail '生成 Mihomo 配置副本失败。'

say '检查 Mihomo 版本和配置'
"$MIHOMO_BIN" -v
"$MIHOMO_BIN" -t -d "$STATE_DIR" -f "$RUNTIME_CONFIG" || fail 'Mihomo 配置检查失败；请查看上方诊断。'

touch "$LOG_FILE"
chmod 600 "$LOG_FILE"

say "启动 Mihomo；TUN 设备：$TUN_DEVICE"
printf '配置副本：%s\n运行目录：%s\n日志文件：%s\n' "$RUNTIME_CONFIG" "$STATE_DIR" "$LOG_FILE"
printf '按 Ctrl+C 停止 Mihomo。\n\n'

# 前台运行：Ctrl+C 会发送停止信号，Mihomo 可清理自己创建的 TUN 路由。
sudo -n "$MIHOMO_BIN" -d "$STATE_DIR" -f "$RUNTIME_CONFIG" 2>&1 | tee -a "$LOG_FILE"
