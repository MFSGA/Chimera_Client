#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)
CLASH_BIN=${CLASH_BIN:-"$ROOT_DIR/target/debug/clash-rs"}
V2RAY_IMAGE=${V2RAY_IMAGE:-"v2fly/v2fly-core:latest"}
UUID=${VLESS_INTEROP_UUID:-"b831381d-6324-4d53-ad4f-8cda48b30811"}

[[ -x "$CLASH_BIN" ]] || { echo "missing executable: $CLASH_BIN" >&2; exit 2; }
command -v docker >/dev/null
command -v python3 >/dev/null

TMP_DIR=$(mktemp -d /tmp/chimera-vless-packetaddr-interop.XXXXXX)
V2RAY_PID=
CLASH_PID=
ECHO_PID=

cleanup() {
    for pid in "${CLASH_PID:-}" "${ECHO_PID:-}"; do
        [[ -n "$pid" ]] && kill "$pid" 2>/dev/null || true
    done
    for pid in "${CLASH_PID:-}" "${ECHO_PID:-}"; do
        [[ -n "$pid" ]] && wait "$pid" 2>/dev/null || true
    done
    if [[ -n "${V2RAY_PID:-}" ]]; then
        docker rm -f "$V2RAY_PID" >/dev/null 2>&1 || true
    fi
    CLASH_PID=
    ECHO_PID=
    V2RAY_PID=
    rm -rf "$TMP_DIR"
}
trap cleanup EXIT INT TERM

read -r V2RAY_PORT SOCKS_PORT ECHO_PORT <<EOF_PORT
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

cat >"$TMP_DIR/v2ray.json" <<EOF_V2RAY
{
  "log": {"loglevel": "error"},
  "inbounds": [{
    "listen": "0.0.0.0",
    "port": $V2RAY_PORT,
    "protocol": "vless",
    "settings": {
      "clients": [{"id": "$UUID"}],
      "decryption": "none",
      "packetEncoding": "Packet"
    }
  }],
  "outbounds": [{"protocol": "freedom", "tag": "direct"}]
}
EOF_V2RAY

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
  - name: v2ray-packetaddr
    type: vless
    server: 127.0.0.1
    port: $V2RAY_PORT
    uuid: $UUID
    udp: true
    packet-encoding: packetaddr
    encryption: none
rules:
  - MATCH,v2ray-packetaddr
EOF_CLASH

docker run --rm --network host -v "$TMP_DIR:/etc/v2ray:ro"     --entrypoint /usr/bin/v2ray "$V2RAY_IMAGE"     test -config /etc/v2ray/v2ray.json >/dev/null

"$CLASH_BIN" -d "$TMP_DIR/clash-home" -c "$TMP_DIR/chimera.yaml" -t >/dev/null

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
"$CLASH_BIN" -d "$TMP_DIR/clash-home" -c "$TMP_DIR/chimera.yaml" >"$TMP_DIR/chimera.log" 2>&1 &
CLASH_PID=$!

docker run -d --network host --name "chimera-v2ray-packetaddr-$RANDOM"     -v "$TMP_DIR:/etc/v2ray:ro" --entrypoint /usr/bin/v2ray "$V2RAY_IMAGE"     run -config /etc/v2ray/v2ray.json >"$TMP_DIR/container-id"
V2RAY_PID=$(cat "$TMP_DIR/container-id")

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
    relay_addr = socket.inet_ntoa(reply[4:8])
    relay_port = struct.unpack("!H", reply[8:10])[0]
    if relay_addr == "0.0.0.0":
        relay_addr = "127.0.0.1"

    udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp.settimeout(12)
    with udp:
        header = b"\x00\x00\x00\x01" + socket.inet_aton("127.0.0.1") + struct.pack("!H", echo_port)
        for payload in (b"packetaddr-vless-1", b"packetaddr-vless-2"):
            udp.sendto(header + payload, (relay_addr, relay_port))
            response, _ = udp.recvfrom(65535)
            assert response == header + payload, (response, header + payload)
PY

docker rm -f "$V2RAY_PID" >/dev/null 2>&1 || true
V2RAY_PID=
kill "$CLASH_PID" "$ECHO_PID" 2>/dev/null || true
wait "$CLASH_PID" "$ECHO_PID" 2>/dev/null || true
CLASH_PID=
ECHO_PID=

if grep -Eiq 'panic|packetaddr.*error|handshake failed|unexpected EOF' "$TMP_DIR/chimera.log"; then
    echo "unexpected packetaddr failure in Chimera logs" >&2
    tail -120 "$TMP_DIR/chimera.log" >&2 || true
    exit 1
fi

echo "PASS VLESS packet-encoding:packetaddr against V2Ray 5.41.0"
