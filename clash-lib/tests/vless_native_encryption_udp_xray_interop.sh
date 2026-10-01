#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)
XRAY_BIN=${XRAY_BIN:-"$ROOT_DIR/xray"}
CLASH_BIN=${CLASH_BIN:-"$ROOT_DIR/target/debug/clash-rs"}
UUID=${VLESS_INTEROP_UUID:-"b831381d-6324-4d53-ad4f-8cda48b30811"}
KEEP_INTEROP_TMP=${KEEP_INTEROP_TMP:-0}

for bin in "$XRAY_BIN" "$CLASH_BIN"; do
    if [[ ! -x "$bin" ]]; then
        echo "missing executable: $bin" >&2
        exit 2
    fi
done
command -v python3 >/dev/null

TMP_DIR=$(mktemp -d /tmp/chimera-vless-native-udp-interop.XXXXXX)
XRAY_PID=
CLASH_PID=
ECHO_PID=

cleanup_processes() {
    for pid in "${CLASH_PID:-}" "${XRAY_PID:-}" "${ECHO_PID:-}"; do
        if [[ -n "$pid" ]]; then
            kill "$pid" 2>/dev/null || true
        fi
    done
    for pid in "${CLASH_PID:-}" "${XRAY_PID:-}" "${ECHO_PID:-}"; do
        if [[ -n "$pid" ]]; then
            wait "$pid" 2>/dev/null || true
        fi
    done
    CLASH_PID=
    XRAY_PID=
    ECHO_PID=
}

on_exit() {
    status=$?
    trap - EXIT INT TERM
    cleanup_processes
    if [[ "$status" -eq 0 && "$KEEP_INTEROP_TMP" != "1" ]]; then
        rm -rf "$TMP_DIR"
    else
        echo "interop artifacts: $TMP_DIR" >&2
    fi
    exit "$status"
}
trap on_exit EXIT INT TERM

GENERATOR_OUTPUT=$("$XRAY_BIN" vlessenc)
NATIVE_DECRYPTION=$(printf '%s\n' "$GENERATOR_OUTPUT" |
    sed -n 's/^"decryption": "\([^"]*\)"$/\1/p' | head -1)
NATIVE_ENCRYPTION=$(printf '%s\n' "$GENERATOR_OUTPUT" |
    sed -n 's/^"encryption": "\([^"]*\)"$/\1/p' | head -1 |
    sed 's/\.0rtt\./.1rtt./')

if [[ -z "$NATIVE_DECRYPTION" || -z "$NATIVE_ENCRYPTION" ]]; then
    echo "failed to parse Xray vlessenc output" >&2
    exit 3
fi

read -r XRAY_PORT SOCKS_PORT ECHO_PORT <<EOF_PORT
$(python3 - <<'PY'
import socket
ports = []
for _ in range(3):
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    ports.append(sock.getsockname()[1])
    sock.close()
print(*ports)
PY
)
EOF_PORT

cat >"$TMP_DIR/xray.json" <<EOF_XRAY
{
  "log": {"loglevel": "error"},
  "inbounds": [{
    "listen": "127.0.0.1",
    "port": $XRAY_PORT,
    "protocol": "vless",
    "settings": {
      "clients": [{"id": "$UUID"}],
      "decryption": "$NATIVE_DECRYPTION"
    }
  }],
  "outbounds": [{"protocol": "freedom", "tag": "direct"}]
}
EOF_XRAY

cat >"$TMP_DIR/chimera.yaml" <<EOF_CLASH
mixed-port: $SOCKS_PORT
bind-address: 127.0.0.1
allow-lan: false
mode: rule
log-level: error
ipv6: false
dns:
  enable: false
proxies:
  - name: xray-native-udp
    type: vless
    server: 127.0.0.1
    port: $XRAY_PORT
    uuid: $UUID
    udp: true
    encryption: "$NATIVE_ENCRYPTION"
rules:
  - MATCH,xray-native-udp
EOF_CLASH

"$XRAY_BIN" run -test -config "$TMP_DIR/xray.json"     >"$TMP_DIR/xray-config-test.log" 2>&1
"$CLASH_BIN" -d "$TMP_DIR/clash-home" -c "$TMP_DIR/chimera.yaml" -t     >"$TMP_DIR/chimera-config-test.log" 2>&1

python3 -u - "$ECHO_PORT" >"$TMP_DIR/echo.log" 2>&1 <<'PY' &
import socket
import sys

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind(("127.0.0.1", int(sys.argv[1])))

while True:
    data, addr = sock.recvfrom(65535)
    sock.sendto(data, addr)
PY
ECHO_PID=$!

mkdir -p "$TMP_DIR/clash-home"
"$XRAY_BIN" run -config "$TMP_DIR/xray.json"     >"$TMP_DIR/xray.log" 2>&1 &
XRAY_PID=$!
"$CLASH_BIN" -d "$TMP_DIR/clash-home" -c "$TMP_DIR/chimera.yaml"     >"$TMP_DIR/chimera.log" 2>&1 &
CLASH_PID=$!

python3 - "$SOCKS_PORT" "$ECHO_PORT" <<'PY'
import socket
import struct
import sys
import time

socks_port, echo_port = map(int, sys.argv[1:])

def recv_exact(sock, length):
    chunks = []
    while length:
        data = sock.recv(length)
        if not data:
            raise RuntimeError("unexpected EOF")
        chunks.append(data)
        length -= len(data)
    return b"".join(chunks)

deadline = time.time() + 12
while time.time() < deadline:
    try:
        sock = socket.create_connection(("127.0.0.1", socks_port), 0.2)
        sock.close()
        break
    except OSError:
        time.sleep(0.1)
else:
    raise RuntimeError("Chimera SOCKS listener did not become ready")

with socket.create_connection(("127.0.0.1", socks_port), 5) as control:
    control.settimeout(12)
    control.sendall(b"\x05\x01\x00")
    assert recv_exact(control, 2) == b"\x05\x00"

    control.sendall(b"\x05\x03\x00\x01\x00\x00\x00\x00\x00\x00")
    reply = recv_exact(control, 10)
    assert reply[1] == 0, reply
    assert reply[3] == 1, reply
    relay_addr = socket.inet_ntoa(reply[4:8])
    relay_port = struct.unpack("!H", reply[8:10])[0]
    if relay_addr == "0.0.0.0":
        relay_addr = "127.0.0.1"

    udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp.settimeout(12)
    with udp:
        packet = (
            b"\x00\x00\x00\x01"
            + socket.inet_aton("127.0.0.1")
            + struct.pack("!H", echo_port)
            + b"encrypted-vless-udp"
        )
        udp.sendto(packet, (relay_addr, relay_port))
        response, _ = udp.recvfrom(65535)
        expected = packet
        assert response == expected, (response, expected)
PY

kill "$CLASH_PID" "$XRAY_PID" 2>/dev/null || true
wait "$CLASH_PID" "$XRAY_PID" 2>/dev/null || true
CLASH_PID=
XRAY_PID=

if grep -Eiq 'panic|VLESS encryption UDP runtime is TODO|handshake failed|unexpected EOF'     "$TMP_DIR/chimera.log" "$TMP_DIR/xray.log"; then
    echo "unexpected encrypted UDP failure in interop logs" >&2
    tail -100 "$TMP_DIR/chimera.log" >&2 || true
    tail -100 "$TMP_DIR/xray.log" >&2 || true
    exit 1
fi

echo "PASS native VLESS 1-RTT encrypted UDP"
echo "PASS native VLESS UDP interop against $("$XRAY_BIN" version | head -1)"
