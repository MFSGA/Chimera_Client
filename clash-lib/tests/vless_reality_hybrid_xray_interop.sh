#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)
XRAY_BIN=${XRAY_BIN:-"$ROOT_DIR/xray"}
CLASH_BIN=${CLASH_BIN:-"$ROOT_DIR/target/debug/clash-rs"}
REALITY_SNI=${REALITY_SNI:-"www.microsoft.com"}
REALITY_TARGET=${REALITY_TARGET:-"$REALITY_SNI:443"}
UUID=${VLESS_INTEROP_UUID:-"114cb5a6-3787-4357-a5da-69b5782cb74f"}
SHORT_ID=${REALITY_SHORT_ID:-"6ba85179e30d4fc2"}
KEEP_INTEROP_TMP=${KEEP_INTEROP_TMP:-0}

for bin in "$XRAY_BIN" "$CLASH_BIN"; do
    if [[ ! -x "$bin" ]]; then
        echo "missing executable: $bin" >&2
        exit 2
    fi
done
command -v python3 >/dev/null

TMP_DIR=$(mktemp -d /tmp/chimera-reality-hybrid-interop.XXXXXX)
ECHO_PID=
XRAY_PID=
CLASH_PID=

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
    trap - EXIT
    cleanup_processes
    if [[ "$status" -eq 0 && "$KEEP_INTEROP_TMP" != "1" ]]; then
        rm -rf "$TMP_DIR"
    else
        echo "interop artifacts: $TMP_DIR" >&2
    fi
    exit "$status"
}
trap on_exit EXIT INT TERM

read -r XRAY_PORT SOCKS_PORT ECHO_PORT <<EOF
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
EOF

KEY_OUTPUT=$("$XRAY_BIN" x25519)
PRIVATE_KEY=$(printf '%s\n' "$KEY_OUTPUT" |
    sed -n 's/^PrivateKey:[[:space:]]*//p' | head -1)
PUBLIC_KEY=$(printf '%s\n' "$KEY_OUTPUT" |
    sed -n -E 's/^(PublicKey|Password):[[:space:]]*//p' | head -1)

if [[ -z "$PRIVATE_KEY" || -z "$PUBLIC_KEY" ]]; then
    echo "failed to parse xray x25519 output" >&2
    exit 3
fi

cat >"$TMP_DIR/xray.json" <<EOF
{
  "log": {"loglevel": "debug"},
  "inbounds": [{
    "listen": "127.0.0.1",
    "port": $XRAY_PORT,
    "protocol": "vless",
    "settings": {
      "clients": [{"id": "$UUID"}],
      "decryption": "none"
    },
    "streamSettings": {
      "network": "tcp",
      "security": "reality",
      "realitySettings": {
        "show": true,
        "target": "$REALITY_TARGET",
        "serverNames": ["$REALITY_SNI"],
        "privateKey": "$PRIVATE_KEY",
        "shortIds": ["$SHORT_ID"]
      }
    }
  }],
  "outbounds": [{"protocol": "freedom", "tag": "direct"}]
}
EOF

cat >"$TMP_DIR/chimera.yaml" <<EOF
socks-port: $SOCKS_PORT
bind-address: 127.0.0.1
allow-lan: false
mode: rule
log-level: debug
ipv6: false
dns:
  enable: false
proxies:
  - name: hybrid-reality
    type: vless
    server: 127.0.0.1
    port: $XRAY_PORT
    uuid: $UUID
    network: tcp
    tls: true
    servername: $REALITY_SNI
    client-fingerprint: chrome
    reality-opts:
      public-key: $PUBLIC_KEY
      short-id: $SHORT_ID
      support-x25519mlkem768: true
rules:
  - MATCH,hybrid-reality
EOF

mkdir -p "$TMP_DIR/chimera-home"
"$XRAY_BIN" run -test -config "$TMP_DIR/xray.json"     >"$TMP_DIR/xray-config-test.log" 2>&1
"$CLASH_BIN" -d "$TMP_DIR/chimera-home" -c "$TMP_DIR/chimera.yaml" -t     >"$TMP_DIR/chimera-config-test.log" 2>&1

python3 -u - "$ECHO_PORT" >"$TMP_DIR/echo.log" 2>&1 <<'PY' &
import socket
import sys
import threading

port = int(sys.argv[1])
listener = socket.socket()
listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
listener.bind(("127.0.0.1", port))
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

"$XRAY_BIN" run -config "$TMP_DIR/xray.json"     >"$TMP_DIR/xray.log" 2>&1 &
XRAY_PID=$!
"$CLASH_BIN" -d "$TMP_DIR/chimera-home" -c "$TMP_DIR/chimera.yaml"     >"$TMP_DIR/chimera.log" 2>&1 &
CLASH_PID=$!

python3 - "$SOCKS_PORT" "$ECHO_PORT" <<'PY'
import socket
import struct
import sys
import time

socks_port = int(sys.argv[1])
echo_port = int(sys.argv[2])

def wait_port(port):
    deadline = time.time() + 12
    while time.time() < deadline:
        try:
            sock = socket.create_connection(("127.0.0.1", port), 0.2)
            sock.close()
            return
        except OSError:
            time.sleep(0.1)
    raise RuntimeError(f"port {port} did not become ready")

def recv_exact(sock, length):
    chunks = []
    remaining = length
    while remaining:
        data = sock.recv(remaining)
        if not data:
            raise RuntimeError("unexpected EOF")
        chunks.append(data)
        remaining -= len(data)
    return b"".join(chunks)

def roundtrip(payload):
    sock = socket.create_connection(("127.0.0.1", socks_port), 5)
    sock.settimeout(8)
    with sock:
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

wait_port(socks_port)
roundtrip(b"hybrid-reality-first")
roundtrip(b"hybrid-reality-second")
PY

if ! grep -Fq "is using X25519MLKEM768 for TLS' communication: true"     "$TMP_DIR/xray.log"; then
    echo "REALITY handshake succeeded without confirmed X25519MLKEM768 negotiation" >&2
    echo "target '$REALITY_TARGET' may not support the hybrid TLS group" >&2
    tail -120 "$TMP_DIR/xray.log" >&2 || true
    exit 4
fi

if grep -Eiq 'panic|handshake\(\) err: [^<]|authentication failed|certificate verification failed'     "$TMP_DIR/chimera.log" "$TMP_DIR/xray.log"; then
    echo "unexpected REALITY failure in logs" >&2
    tail -120 "$TMP_DIR/chimera.log" >&2 || true
    tail -120 "$TMP_DIR/xray.log" >&2 || true
    exit 5
fi

echo "PASS REALITY X25519MLKEM768 interop against $("$XRAY_BIN" version | head -1)"
echo "PASS target=$REALITY_TARGET sni=$REALITY_SNI"
