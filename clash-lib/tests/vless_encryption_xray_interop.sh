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

TMP_DIR=$(mktemp -d /tmp/chimera-vless-encryption-interop.XXXXXX)
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

read -r ECHO_PORT <<EOF
$(python3 - <<'PY'
import socket
s = socket.socket()
s.bind(("127.0.0.1", 0))
print(s.getsockname()[1])
s.close()
PY
)
EOF

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

GENERATOR_OUTPUT=$("$XRAY_BIN" vlessenc)
NATIVE_DECRYPTION=$(printf '%s\n' "$GENERATOR_OUTPUT" |
    sed -n 's/^"decryption": "\([^"]*\)"$/\1/p' | head -1)
NATIVE_ENCRYPTION=$(printf '%s\n' "$GENERATOR_OUTPUT" |
    sed -n 's/^"encryption": "\([^"]*\)"$/\1/p' | head -1)

if [[ -z "$NATIVE_DECRYPTION" || -z "$NATIVE_ENCRYPTION" ]]; then
    echo "failed to parse xray vlessenc output" >&2
    exit 3
fi

pick_two_ports() {
    python3 - <<'PY'
import socket
ports = []
for _ in range(2):
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    ports.append(s.getsockname()[1])
    s.close()
print(*ports)
PY
}

run_case() {
    appearance=$1
    case_dir="$TMP_DIR/$appearance"
    mkdir -p "$case_dir/clash-home"

    read -r XRAY_PORT SOCKS_PORT <<EOF
$(pick_two_ports)
EOF

    decryption=${NATIVE_DECRYPTION/.native./.$appearance.}
    encryption=${NATIVE_ENCRYPTION/.native./.$appearance.}

    cat >"$case_dir/xray.json" <<EOF
{
  "log": {"loglevel": "debug"},
  "inbounds": [{
    "listen": "127.0.0.1",
    "port": $XRAY_PORT,
    "protocol": "vless",
    "settings": {
      "clients": [{"id": "$UUID"}],
      "decryption": "$decryption"
    }
  }],
  "outbounds": [{"protocol": "freedom", "tag": "direct"}]
}
EOF

    cat >"$case_dir/chimera.yaml" <<EOF
mixed-port: $SOCKS_PORT
allow-lan: false
bind-address: 127.0.0.1
mode: rule
log-level: debug
ipv6: false
dns:
  enable: false
proxies:
  - name: xray-encrypted
    type: vless
    server: 127.0.0.1
    port: $XRAY_PORT
    uuid: $UUID
    udp: false
    encryption: "$encryption"
rules:
  - MATCH,xray-encrypted
EOF

    "$XRAY_BIN" run -test -config "$case_dir/xray.json"         >"$case_dir/xray-config-test.log" 2>&1
    "$CLASH_BIN" -d "$case_dir/clash-home" -c "$case_dir/chimera.yaml" -t         >"$case_dir/chimera-config-test.log" 2>&1

    "$XRAY_BIN" run -config "$case_dir/xray.json"         >"$case_dir/xray.log" 2>&1 &
    XRAY_PID=$!
    "$CLASH_BIN" -d "$case_dir/clash-home" -c "$case_dir/chimera.yaml"         >"$case_dir/chimera.log" 2>&1 &
    CLASH_PID=$!

    python3 - "$SOCKS_PORT" "$ECHO_PORT" "$appearance" <<'PY'
import socket
import struct
import sys
import time

socks_port = int(sys.argv[1])
echo_port = int(sys.argv[2])
appearance = sys.argv[3]

def wait_port(port):
    deadline = time.time() + 10
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
    sock = socket.create_connection(("127.0.0.1", socks_port), 3)
    sock.settimeout(5)
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

# Connection 1 has an empty client cache and therefore exercises the 1-RTT
# ticket bootstrap. Connection 2 uses the same Handler and exercises cached 0-RTT.
roundtrip(f"{appearance}-first-1rtt-ticket-bootstrap".encode())
time.sleep(0.15)
roundtrip(f"{appearance}-second-cached-0rtt".encode())
PY

    kill "$CLASH_PID" "$XRAY_PID" 2>/dev/null || true
    wait "$CLASH_PID" "$XRAY_PID" 2>/dev/null || true
    CLASH_PID=
    XRAY_PID=

    if grep -Eiq 'panic|ML-KEM-768 handshake failed|new handshake needed'         "$case_dir/chimera.log" "$case_dir/xray.log"; then
        echo "unexpected encryption failure in $appearance logs" >&2
        tail -80 "$case_dir/chimera.log" >&2 || true
        tail -80 "$case_dir/xray.log" >&2 || true
        return 1
    fi

    echo "PASS $appearance: 1-RTT bootstrap + cached 0-RTT"
}

for appearance in native xorpub random; do
    run_case "$appearance"
done

echo "PASS VLESS encryption interop against $("$XRAY_BIN" version | head -1)"
