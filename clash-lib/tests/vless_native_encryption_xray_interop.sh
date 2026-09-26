#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)
CLASH_BIN=${CLASH_BIN:-"$ROOT_DIR/target/debug/clash-rs"}
XRAY_BIN=${XRAY_BIN:-}
XRAY_IMAGE=${XRAY_IMAGE:-"teddysun/xray:26.3.27"}
UUID=${VLESS_INTEROP_UUID:-"b831381d-6324-4d53-ad4f-8cda48b30811"}
KEEP_INTEROP_TMP=${KEEP_INTEROP_TMP:-0}

if [[ ! -x "$CLASH_BIN" ]]; then
    echo "missing executable: $CLASH_BIN" >&2
    exit 2
fi
if [[ -n "$XRAY_BIN" ]]; then
    if [[ ! -x "$XRAY_BIN" ]]; then
        echo "missing executable: $XRAY_BIN" >&2
        exit 2
    fi
elif ! command -v docker >/dev/null; then
    echo "set XRAY_BIN or install Docker with XRAY_IMAGE available" >&2
    exit 2
fi
command -v python3 >/dev/null

TMP_DIR=$(mktemp -d /tmp/chimera-vless-native-interop.XXXXXX)
ECHO_PID=
XRAY_PID=
CLASH_PID=
XRAY_CONTAINER="chimera-vless-native-interop-$$"

cleanup() {
    status=$?
    trap - EXIT INT TERM
    if [[ -n "$CLASH_PID" ]]; then
        kill "$CLASH_PID" 2>/dev/null || true
        wait "$CLASH_PID" 2>/dev/null || true
    fi
    if [[ -n "$XRAY_PID" ]]; then
        if [[ -z "$XRAY_BIN" ]]; then
            docker rm --force "$XRAY_CONTAINER" >/dev/null 2>&1 || true
        fi
        kill "$XRAY_PID" 2>/dev/null || true
        wait "$XRAY_PID" 2>/dev/null || true
    fi
    if [[ -n "$ECHO_PID" ]]; then
        kill "$ECHO_PID" 2>/dev/null || true
        wait "$ECHO_PID" 2>/dev/null || true
    fi
    if [[ "$KEEP_INTEROP_TMP" == "1" ]]; then
        echo "interop artifacts kept in $TMP_DIR" >&2
    else
        rm -rf "$TMP_DIR"
    fi
    exit "$status"
}
trap cleanup EXIT
trap 'exit 130' INT TERM

run_xray() {
    if [[ -n "$XRAY_BIN" ]]; then
        "$XRAY_BIN" "$@"
    else
        docker run --rm --network none "$XRAY_IMAGE" /usr/bin/xray "$@"
    fi
}

GENERATOR_OUTPUT=$(run_xray vlessenc)
NATIVE_DECRYPTION=$(awk -F '"' '/"decryption":/ { print $4; exit }' <<<"$GENERATOR_OUTPUT")
NATIVE_ENCRYPTION=$(awk -F '"' '/"encryption":/ { print $4; exit }' <<<"$GENERATOR_OUTPUT")
if [[ -z "$NATIVE_DECRYPTION" || -z "$NATIVE_ENCRYPTION" ]]; then
    echo "failed to parse Xray vlessenc output" >&2
    exit 3
fi
CLIENT_ENCRYPTION=${NATIVE_ENCRYPTION/.0rtt./.1rtt.}

read -r ECHO_PORT XRAY_PORT SOCKS_PORT < <(python3 - <<'PY'
import socket

sockets = []
for _ in range(3):
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    sockets.append(sock)
print(*(sock.getsockname()[1] for sock in sockets))
for sock in sockets:
    sock.close()
PY
)

python3 -u - "$ECHO_PORT" >"$TMP_DIR/echo.log" 2>&1 <<'PY' &
import socket
import sys
import threading

listener = socket.socket()
listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
listener.bind(("127.0.0.1", int(sys.argv[1])))
listener.listen()

def serve(conn):
    with conn:
        while True:
            data = conn.recv(65536)
            if not data:
                return
            conn.sendall(data)

while True:
    conn, _ = listener.accept()
    threading.Thread(target=serve, args=(conn,), daemon=True).start()
PY
ECHO_PID=$!

python3 - "$TMP_DIR/xray.json" "$TMP_DIR/chimera.yaml" \
    "$XRAY_PORT" "$SOCKS_PORT" "$UUID" "$NATIVE_DECRYPTION" \
    "$CLIENT_ENCRYPTION" <<'PY'
import json
import pathlib
import sys

xray_path, chimera_path, xray_port, socks_port, uuid, decryption, encryption = sys.argv[1:]
xray = {
    "log": {"loglevel": "error"},
    "inbounds": [{
        "listen": "127.0.0.1",
        "port": int(xray_port),
        "protocol": "vless",
        "settings": {"clients": [{"id": uuid}], "decryption": decryption},
    }],
    "outbounds": [{"protocol": "freedom", "tag": "direct"}],
}
pathlib.Path(xray_path).write_text(json.dumps(xray), encoding="utf-8")
chimera = "\n".join([
    f"mixed-port: {socks_port}",
    "allow-lan: false",
    "bind-address: 127.0.0.1",
    "mode: rule",
    "log-level: error",
    "ipv6: false",
    "dns:",
    "  enable: false",
    "proxies:",
    "  - name: xray-native-1rtt",
    "    type: vless",
    "    server: 127.0.0.1",
    f"    port: {xray_port}",
    f"    uuid: {uuid}",
    "    udp: false",
    f'    encryption: "{encryption}"',
    "rules:",
    "  - MATCH,xray-native-1rtt",
]) + "\n"
pathlib.Path(chimera_path).write_text(chimera, encoding="utf-8")
PY

if [[ -n "$XRAY_BIN" ]]; then
    "$XRAY_BIN" run -test -config "$TMP_DIR/xray.json" \
        >"$TMP_DIR/xray-config-test.log" 2>&1
else
    docker run --rm --network host \
        -v "$TMP_DIR/xray.json:/tmp/xray.json:ro" "$XRAY_IMAGE" \
        /usr/bin/xray run -test -config /tmp/xray.json \
        >"$TMP_DIR/xray-config-test.log" 2>&1
fi

if [[ -n "$XRAY_BIN" ]]; then
    "$XRAY_BIN" run -config "$TMP_DIR/xray.json" >"$TMP_DIR/xray.log" 2>&1 &
else
    docker run --rm --name "$XRAY_CONTAINER" --network host \
        -v "$TMP_DIR/xray.json:/tmp/xray.json:ro" "$XRAY_IMAGE" \
        /usr/bin/xray run -config /tmp/xray.json >"$TMP_DIR/xray.log" 2>&1 &
fi
XRAY_PID=$!

python3 - "$XRAY_PORT" <<'PY'
import socket
import sys
import time

port = int(sys.argv[1])
deadline = time.time() + 10
while time.time() < deadline:
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=0.2):
            break
    except OSError:
        time.sleep(0.1)
else:
    raise RuntimeError("Xray server did not become ready")
PY

mkdir -p "$TMP_DIR/clash-home"
"$CLASH_BIN" -d "$TMP_DIR/clash-home" -c "$TMP_DIR/chimera.yaml" \
    >"$TMP_DIR/chimera.log" 2>&1 &
CLASH_PID=$!

python3 - "$SOCKS_PORT" "$ECHO_PORT" <<'PY'
import socket
import struct
import sys
import time

socks_port, echo_port = map(int, sys.argv[1:])
deadline = time.time() + 10
while time.time() < deadline:
    try:
        with socket.create_connection(("127.0.0.1", socks_port), timeout=0.2):
            break
    except OSError:
        time.sleep(0.1)
else:
    raise RuntimeError("Chimera SOCKS listener did not become ready")

def recv_exact(sock, length):
    chunks = []
    while length:
        data = sock.recv(length)
        if not data:
            raise RuntimeError("unexpected EOF")
        chunks.append(data)
        length -= len(data)
    return b"".join(chunks)

payload = b"native-1rtt-xray-interop"
with socket.create_connection(("127.0.0.1", socks_port), timeout=3) as sock:
    sock.settimeout(8)
    sock.sendall(b"\x05\x01\x00")
    assert recv_exact(sock, 2) == b"\x05\x00"
    request = b"\x05\x01\x00\x01" + socket.inet_aton("127.0.0.1")
    sock.sendall(request + struct.pack("!H", echo_port))
    reply = recv_exact(sock, 10)
    assert reply[1] == 0, reply
    sock.sendall(payload)
    assert recv_exact(sock, len(payload)) == payload
PY

echo "PASS native VLESS 1-RTT interop against Xray"
