#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

# Live demonstration of the TUN + fake-IP path on macOS.
# It reads the existing config but only writes an adapted copy under /tmp.

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONFIG_FILE="${CONFIG_FILE:-$ROOT_DIR/config.yaml}"
MIHOMO_GZ="${MIHOMO_GZ:-/Users/adam/Downloads/mihomo-darwin-arm64-v1.19.31.gz}"
DOMAIN="${DOMAIN:-example.com}"
TEST_PORT="${TEST_PORT:-443}"
DNS_SERVER="${DNS_SERVER:-8.8.8.8}"

RUN_DIR=""
MIHOMO_PID=""
TUN_CAPTURE_PID=""
PHY_CAPTURE_PID=""
STARTED_BY_SCRIPT=0

say() { printf '\n==> %s\n' "$*"; }
fail() { printf '错误：%s\n' "$*" >&2; exit 1; }

stop_capture() {
  local capture_pid="$1"
  local child_pids
  local child_pid
  [[ -n "$capture_pid" ]] || return 0
  # sudo stays as the parent process on macOS; signal its tcpdump child first.
  child_pids="$(pgrep -P "$capture_pid" 2>/dev/null || true)"
  if [[ -n "$child_pids" ]]; then
    for child_pid in $child_pids; do
      sudo -n kill -INT "$child_pid" >/dev/null 2>&1 || true
    done
  else
    sudo -n kill -INT "$capture_pid" >/dev/null 2>&1 || true
  fi
  wait "$capture_pid" >/dev/null 2>&1 || true
}

wait_capture_ready() {
  local capture_pid="$1"
  for _ in {1..30}; do
    if pgrep -P "$capture_pid" >/dev/null 2>&1; then
      return 0
    fi
    kill -0 "$capture_pid" >/dev/null 2>&1 || return 1
    sleep 0.1
  done
  return 1
}

cleanup() {
  local exit_status=$?
  trap - EXIT INT TERM
  stop_capture "$TUN_CAPTURE_PID"
  stop_capture "$PHY_CAPTURE_PID"
  if [[ -n "$MIHOMO_PID" ]] && kill -0 "$MIHOMO_PID" >/dev/null 2>&1; then
    printf '\n正在停止本脚本启动的 Mihomo 并恢复 TUN 路由……\n'
    sudo -n kill -TERM "$MIHOMO_PID" >/dev/null 2>&1 || true
    wait "$MIHOMO_PID" >/dev/null 2>&1 || true
  fi
  if [[ -n "$RUN_DIR" && -d "$RUN_DIR" ]]; then
    rm -rf "$RUN_DIR"
  fi
  exit "$exit_status"
}
trap cleanup EXIT
trap 'exit 130' INT TERM

for tool in ruby gzip dig curl route ifconfig tcpdump awk pgrep; do
  command -v "$tool" >/dev/null 2>&1 || fail "缺少命令：$tool"
done
[[ -f "$CONFIG_FILE" ]] || fail "找不到配置文件：$CONFIG_FILE"

sudo -n true >/dev/null 2>&1 || fail 'sudo -n 不可用；请先配置免密 sudo 后重新运行。'

TUN_DEVICE="$(ruby -ryaml -e 'h=YAML.load_file(ARGV[0]); t=h["tun"] || {}; puts(t["device-id"] || t["device"] || "utun1989")' "$CONFIG_FILE")"
[[ "$TUN_DEVICE" =~ ^[A-Za-z0-9._-]+$ ]] || fail "TUN 设备名不安全：$TUN_DEVICE"
DNS_MODE="$(ruby -ryaml -e 'h=YAML.load_file(ARGV[0]); puts((h["dns"] || {})["enhanced-mode"])' "$CONFIG_FILE")"
[[ "$DNS_MODE" == 'fake-ip' ]] || fail "当前配置的 dns.enhanced-mode 不是 fake-ip：$DNS_MODE"
[[ "$TEST_PORT" =~ ^[0-9]{1,5}$ ]] || fail "端口号无效：$TEST_PORT"

say "测试目标：${DOMAIN}:${TEST_PORT}；TUN 设备：${TUN_DEVICE}"
say '检查是否已有这个 TUN 接口'
if ifconfig "$TUN_DEVICE" 2>/dev/null | grep -q 'UP'; then
  printf '%s 已经处于 UP 状态；本脚本将观察现有接口，不会启动第二个 TUN，也不会停止现有进程。\n' "$TUN_DEVICE"
else
  [[ -f "$MIHOMO_GZ" ]] || fail "找不到 Mihomo 压缩包：$MIHOMO_GZ"
  RUN_DIR="$(mktemp -d "${TMPDIR:-/tmp}/chimera-tun-demo.XXXXXX")"
  chmod 700 "$RUN_DIR"
  MIHOMO_BIN="$RUN_DIR/mihomo"
  TEST_CONFIG="$RUN_DIR/config.yaml"
  RUN_LOG="$RUN_DIR/mihomo.log"

  say '解压 Mihomo 到私有临时目录'
  gzip -dc "$MIHOMO_GZ" > "$MIHOMO_BIN"
  chmod 700 "$MIHOMO_BIN"
  "$MIHOMO_BIN" -v

  say '从原配置生成临时副本，只调整 Mihomo 所需的 TUN 字段和本机监听范围'
  ruby -ryaml -e '
    source, destination = ARGV
    config = YAML.load_file(source)
    tun = config.fetch("tun") { abort "配置中缺少 tun" }
    tun["device"] = tun.delete("device-id") if tun.key?("device-id")
    tun["auto-route"] = tun.delete("route-all") if tun.key?("route-all")
    if tun["dns-hijack"] == true
      tun["dns-hijack"] = ["any:53", "tcp://any:53"]
    end
    config["allow-lan"] = false
    config["bind-address"] = "127.0.0.1"
    File.write(destination, YAML.dump(config))
    File.chmod(0600, destination)
  ' "$CONFIG_FILE" "$TEST_CONFIG"

  # Keep relative geodata paths working while isolating runtime files and cache.
  for data_file in Country.mmdb geosite.dat geoip.dat GeoLite2-Country.mmdb; do
    if [[ -e "$ROOT_DIR/$data_file" && ! -e "$RUN_DIR/$data_file" ]]; then
      ln -s "$ROOT_DIR/$data_file" "$RUN_DIR/$data_file"
    fi
  done

  say '校验临时配置'
  "$MIHOMO_BIN" -t -d "$RUN_DIR" -f "$TEST_CONFIG"

  say '启动 TUN；运行期间按 Enter 或 Ctrl+C 会停止本脚本启动的进程'
  # Keep log files owned by this user inside the mode-700 temporary directory.
  # shellcheck disable=SC2024
  sudo -n "$MIHOMO_BIN" -d "$RUN_DIR" -f "$TEST_CONFIG" > "$RUN_LOG" 2>&1 &
  MIHOMO_PID=$!
  STARTED_BY_SCRIPT=1

  ready=0
  for _ in {1..30}; do
    if ifconfig "$TUN_DEVICE" 2>/dev/null | grep -q 'UP'; then
      ready=1
      break
    fi
    if ! kill -0 "$MIHOMO_PID" >/dev/null 2>&1; then
      tail -n 40 "$RUN_LOG" >&2 || true
      fail 'Mihomo 提前退出；上面是最后 40 行日志。'
    fi
    sleep 0.5
  done
  [[ "$ready" == 1 ]] || { tail -n 40 "$RUN_LOG" >&2 || true; fail "等待 $TUN_DEVICE 启动超时。"; }
fi

say '查看 TUN 地址和主机路由'
ifconfig "$TUN_DEVICE" | awk 'NR <= 4 { print }'
route -n get 1.1.1.1 | awk '/gateway:|interface:/ { print }'

PHY_IF="$(route -n get -inet default 2>/dev/null | awk '/interface:/ {print $2; exit}')"
[[ -n "$PHY_IF" ]] || PHY_IF='en0'
printf '物理网卡（仅用于检查 fake-IP 是否直接漏出）：%s\n' "$PHY_IF"

say '在 TUN 上观察 DNS 查询，再向指定 DNS 地址请求 fake-IP'
printf 'DNS 服务器目标路由（用于查看当前路由选择）：\n'
route -n get "$DNS_SERVER" | awk '/gateway:|interface:/ { print }'
if [[ -z "$RUN_DIR" ]]; then
  RUN_DIR="$(mktemp -d "${TMPDIR:-/tmp}/chimera-tun-observe.XXXXXX")"
  chmod 700 "$RUN_DIR"
fi
DNS_CAPTURE="$RUN_DIR/dns-tun.log"
# Keep packet captures user-owned; tcpdump inherits the open file descriptor.
# shellcheck disable=SC2024
sudo -n /usr/sbin/tcpdump -n -l -i "$TUN_DEVICE" 'udp port 53' > "$DNS_CAPTURE" 2>&1 &
TUN_CAPTURE_PID=$!
wait_capture_ready "$TUN_CAPTURE_PID" || fail 'TUN DNS 抓包没有启动。'
DNS_OUTPUT="$(dig +time=4 +tries=1 +short "@$DNS_SERVER" "$DOMAIN" A)" || fail "DNS 查询失败：$DOMAIN"
stop_capture "$TUN_CAPTURE_PID"
TUN_CAPTURE_PID=""
FAKE_IP="$(printf '%s\n' "$DNS_OUTPUT" | awk '/^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/ {print; exit}')"
[[ -n "$FAKE_IP" ]] || fail "DNS 没有返回 IPv4 地址。原始结果：$DNS_OUTPUT"
printf '%s 经 %s 查询到的 A 记录：%s\n' "$DOMAIN" "$DNS_SERVER" "$FAKE_IP"
printf 'TUN 上匹配该域名的 DNS 抓包：\n'
if ! grep -F "$DOMAIN" "$DNS_CAPTURE" | head -n 8; then
  printf '（tcpdump 未显示该域名；以 DNS 返回结果和后续 fake-IP 连接检查为准）\n'
fi

say '确认 fake-IP 的路由，并用 curl 强制连接 fake-IP（绕过系统代理）'
route -n get "$FAKE_IP" | awk '/gateway:|interface:/ { print }'
TUN_TCP_CAPTURE="$RUN_DIR/tun-tcp.log"
PHY_TCP_CAPTURE="$RUN_DIR/physical-tcp.log"
# shellcheck disable=SC2024
sudo -n /usr/sbin/tcpdump -n -l -i "$TUN_DEVICE" "host $FAKE_IP and tcp port $TEST_PORT" > "$TUN_TCP_CAPTURE" 2>&1 &
TUN_CAPTURE_PID=$!
# shellcheck disable=SC2024
sudo -n /usr/sbin/tcpdump -n -l -i "$PHY_IF" "host $FAKE_IP and tcp port $TEST_PORT" > "$PHY_TCP_CAPTURE" 2>&1 &
PHY_CAPTURE_PID=$!
wait_capture_ready "$TUN_CAPTURE_PID" || fail 'TUN TCP 抓包没有启动。'
wait_capture_ready "$PHY_CAPTURE_PID" || fail '物理网卡 TCP 抓包没有启动。'
CURL_RESULT="$(curl --noproxy '*' --resolve "$DOMAIN:$TEST_PORT:$FAKE_IP" \
  --connect-timeout 8 --max-time 20 -sS -o /dev/null \
  -w 'http=%{http_code} remote_ip=%{remote_ip} tls_verify=%{ssl_verify_result} seconds=%{time_total}' \
  "https://$DOMAIN:$TEST_PORT/")" || fail 'curl 请求失败；请查看 TUN 配置和 Mihomo 日志。'
stop_capture "$TUN_CAPTURE_PID"
TUN_CAPTURE_PID=""
stop_capture "$PHY_CAPTURE_PID"
PHY_CAPTURE_PID=""
printf '%s\n' "$CURL_RESULT"

printf '\nTUN 上发往 fake-IP 的 TCP 包（最多显示 12 行）：\n'
awk -v ip="$FAKE_IP" 'index($0, ip) && $0 ~ / > / {print; n++; if (n == 12) exit}' "$TUN_TCP_CAPTURE"
printf '\n物理网卡上发往 fake-IP 的 TCP 包：\n'
physical_packets="$(awk -v ip="$FAKE_IP" 'index($0, ip) && $0 ~ / > / {print; n++} END {if (n == 0) print "（未捕获到）"}' "$PHY_TCP_CAPTURE")"
printf '%s\n' "$physical_packets"

say '观察结束'
if [[ "$STARTED_BY_SCRIPT" == 1 ]]; then
  printf '按 Enter 或 Ctrl+C 停止 PID %s；退出清理会删除临时配置和缓存。\n' "$MIHOMO_PID"
else
  printf '本脚本没有启动或停止现有 Mihomo；按 Enter 结束观察即可。\n'
fi
read -r _ || true
