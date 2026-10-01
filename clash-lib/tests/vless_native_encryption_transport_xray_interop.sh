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

TMP_DIR=$(mktemp -d /tmp/chimera-vless-encryption-transport-interop.XXXXXX)
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

"$XRAY_BIN" tls cert --domain=localhost --file="$TMP_DIR/server"     >/dev/null 2>&1

GENERATOR_OUTPUT=$("$XRAY_BIN" vlessenc)
NATIVE_DECRYPTION=$(printf '%s\n' "$GENERATOR_OUTPUT" |
    sed -n 's/^"decryption": "\([^"]*\)"$/\1/p' | head -1)
NATIVE_ENCRYPTION=$(printf '%s\n' "$GENERATOR_OUTPUT" |
    sed -n 's/^"encryption": "\([^"]*\)"$/\1/p' | head -1)
CLIENT_ENCRYPTION=${NATIVE_ENCRYPTION/.0rtt./.1rtt.}

if [[ -z "$NATIVE_DECRYPTION" || -z "$CLIENT_ENCRYPTION" ]]; then
    echo "failed to parse Xray vlessenc output" >&2
    exit 3
fi

read -r ECHO_PORT <<EOF_PORT
$(python3 - <<'PY'
import socket
sock = socket.socket()
sock.bind(("127.0.0.1", 0))
print(sock.getsockname()[1])
sock.close()
PY
)
EOF_PORT

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

pick_port() {
    python3 - <<'PY'
import socket
sock = socket.socket()
sock.bind(("127.0.0.1", 0))
print(sock.getsockname()[1])
sock.close()
PY
}

run_case() {
    local name=$1
    local network=$2
    local client_extra=$3
    local server_extra=$4
    local payload=$5
    local case_dir="$TMP_DIR/$name"
    local xray_port socks_port

    mkdir -p "$case_dir/clash-home"
    xray_port=$(pick_port)
    socks_port=$(pick_port)

    cat >"$case_dir/xray.json" <<EOF_XRAY
{
  "log": {"loglevel": "error"},
  "inbounds": [{
    "listen": "127.0.0.1",
    "port": $xray_port,
    "protocol": "vless",
    "settings": {
      "clients": [{"id": "$UUID"}],
      "decryption": "$NATIVE_DECRYPTION"
    },
    "streamSettings": {
      "network": "$network",
      "security": "tls",
      "tlsSettings": {
        "certificates": [{
          "certificateFile": "$TMP_DIR/server.crt",
          "keyFile": "$TMP_DIR/server.key"
        }]
      }$server_extra
    }
  }],
  "outbounds": [{"protocol": "freedom", "tag": "direct"}]
}
EOF_XRAY

    cat >"$case_dir/chimera.yaml" <<EOF_CLASH
mixed-port: $socks_port
bind-address: 127.0.0.1
allow-lan: false
mode: rule
log-level: error
ipv6: false
dns:
  enable: false
proxies:
  - name: xray-native-$name
    type: vless
    server: 127.0.0.1
    port: $xray_port
    uuid: $UUID
    tls: true
    servername: localhost
    skip-cert-verify: true
    encryption: "$CLIENT_ENCRYPTION"$client_extra
rules:
  - MATCH,xray-native-$name
EOF_CLASH

    "$XRAY_BIN" run -test -config "$case_dir/xray.json"         >"$case_dir/xray-config-test.log" 2>&1
    "$CLASH_BIN" -d "$case_dir/clash-home" -c "$case_dir/chimera.yaml" -t         >"$case_dir/chimera-config-test.log" 2>&1

    "$XRAY_BIN" run -config "$case_dir/xray.json"         >"$case_dir/xray.log" 2>&1 &
    XRAY_PID=$!
    "$CLASH_BIN" -d "$case_dir/clash-home" -c "$case_dir/chimera.yaml"         >"$case_dir/chimera.log" 2>&1 &
    CLASH_PID=$!

    python3 - "$socks_port" "$ECHO_PORT" "$payload" <<'PY'
import socket
import struct
import sys
import time

socks_port, echo_port = map(int, sys.argv[1:3])
payload = sys.argv[3].encode()

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

def recv_exact(sock, length):
    chunks = []
    while length:
        data = sock.recv(length)
        if not data:
            raise RuntimeError("unexpected EOF")
        chunks.append(data)
        length -= len(data)
    return b"".join(chunks)

with socket.create_connection(("127.0.0.1", socks_port), 5) as sock:
    sock.settimeout(12)
    sock.sendall(b"\x05\x01\x00")
    assert recv_exact(sock, 2) == b"\x05\x00"

    request = (
        b"\x05\x01\x00\x01"
        + socket.inet_aton("127.0.0.1")
        + struct.pack("!H", echo_port)
    )
    sock.sendall(request)
    reply = recv_exact(sock, 10)
    assert reply[1] == 0, reply

    sock.sendall(payload)
    assert recv_exact(sock, len(payload)) == payload
PY

    kill "$CLASH_PID" "$XRAY_PID" 2>/dev/null || true
    wait "$CLASH_PID" "$XRAY_PID" 2>/dev/null || true
    CLASH_PID=
    XRAY_PID=

    if grep -Eiq 'panic|handshake failed|unexpected EOF|connection reset'         "$case_dir/chimera.log" "$case_dir/xray.log"; then
        echo "unexpected transport failure in $name logs" >&2
        tail -80 "$case_dir/chimera.log" >&2 || true
        tail -80 "$case_dir/xray.log" >&2 || true
        return 1
    fi

    echo "PASS native VLESS 1-RTT over $name"
}

run_case     "tls"     "raw"     ""     ""     "native-1rtt-tls"

run_case     "xhttp-tls"     "xhttp"     '
    network: xhttp
    xhttp-opts:
      path: /xhttp
      mode: stream-one'     ',
      "xhttpSettings": {
        "path": "/xhttp",
        "mode": "auto"
      }'     "native-1rtt-xhttp-tls"

echo "PASS VLESS native 1-RTT outer TLS/XHTTP interop against $("$XRAY_BIN" version | head -1)"
