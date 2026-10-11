#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)
CLASH_BIN=${CLASH_BIN:-"$ROOT_DIR/target/debug/clash-rs"}
XRAY_BIN=${XRAY_BIN:-"$(command -v xray || true)"}
UUID=${VLESS_INTEROP_UUID:-"b831381d-6324-4d53-ad4f-8cda48b30811"}

if [[ ! -x "$CLASH_BIN" ]]; then
    echo "missing executable: $CLASH_BIN (build with cargo build -p clash-rs first)" >&2
    exit 2
fi
if [[ -z "$XRAY_BIN" || ! -x "$XRAY_BIN" ]]; then
    echo "set XRAY_BIN to an Xray-core executable with REALITY support" >&2
    exit 2
fi
command -v python3 >/dev/null

TMP_DIR=$(mktemp -d /tmp/chimera-reality-hybrid-interop.XXXXXX)
XRAY_PID=
CLASH_PID=
ECHO_PID=
cleanup() {
    status=$?
    trap - EXIT INT TERM
    for pid in "$CLASH_PID" "$XRAY_PID" "$ECHO_PID"; do
        if [[ -n "$pid" ]]; then
            kill "$pid" 2>/dev/null || true
            wait "$pid" 2>/dev/null || true
        fi
    done
    if [[ "$status" -ne 0 ]]; then
        echo "interop artifacts kept in $TMP_DIR" >&2
    else
        rm -rf "$TMP_DIR"
    fi
    exit "$status"
}
trap cleanup EXIT
trap 'exit 130' INT TERM

read -r XRAY_PORT SOCKS_PORT ECHO_PORT < <(python3 - <<'PY'
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

KEY_OUTPUT=$("$XRAY_BIN" x25519)
PRIVATE_KEY=$(awk -F ': ' '/^PrivateKey:/ { print $2; exit }' <<<"$KEY_OUTPUT")
PUBLIC_KEY=$(awk -F ': ' '/^Password \(PublicKey\):/ { print $2; exit }' <<<"$KEY_OUTPUT")
if [[ -z "$PRIVATE_KEY" || -z "$PUBLIC_KEY" ]]; then
    echo "failed to parse Xray x25519 output" >&2
    exit 3
fi

python3 - "$TMP_DIR/xray.json" "$TMP_DIR/chimera.yaml" \
    "$XRAY_PORT" "$SOCKS_PORT" "$UUID" "$PRIVATE_KEY" "$PUBLIC_KEY" <<'PY'
import json
import pathlib
import sys
xray_path, chimera_path, xray_port, socks_port, uuid, private_key, public_key = sys.argv[1:]
xray = {
    "log": {"loglevel": "debug"},
    "inbounds": [{
        "listen": "127.0.0.1", "port": int(xray_port), "protocol": "vless",
        "settings": {"clients": [{"id": uuid}], "decryption": "none"},
        "streamSettings": {
            "network": "tcp", "security": "reality",
            "realitySettings": {
                "show": True, "dest": "example.com:443", "xver": 0,
                "serverNames": ["example.com"], "privateKey": private_key,
                "shortIds": ["0102030405060708"],
            },
        },
    }],
    "outbounds": [{
        "protocol": "freedom",
        "tag": "direct",
        "settings": {"finalRules": [{
            "action": "allow", "network": "tcp", "ip": ["127.0.0.1"],
        }]},
    }],
}
pathlib.Path(xray_path).write_text(json.dumps(xray), encoding="utf-8")
chimera = "\n".join([
    f"mixed-port: {socks_port}", "allow-lan: false", "bind-address: 127.0.0.1",
    "mode: rule", "log-level: error", "ipv6: false", "dns:", "  enable: false",
    "proxies:", "  - name: xray-reality-hybrid", "    type: vless",
    "    server: 127.0.0.1", f"    port: {xray_port}", f"    uuid: {uuid}",
    "    tls: true", "    server-name: example.com", "    client-fingerprint: chrome",
    "    reality-opts:", f"      public-key: {public_key}",
    "      short-id: 0102030405060708", "      support-x25519mlkem768: true",
    "rules:", "  - MATCH,xray-reality-hybrid",
]) + "\n"
pathlib.Path(chimera_path).write_text(chimera, encoding="utf-8")
PY

"$XRAY_BIN" run -test -config "$TMP_DIR/xray.json" >"$TMP_DIR/xray-config-test.log" 2>&1
"$XRAY_BIN" run -config "$TMP_DIR/xray.json" >"$TMP_DIR/xray.log" 2>&1 &
XRAY_PID=$!

python3 - "$XRAY_PORT" <<'PY'
import socket, sys, time
port = int(sys.argv[1])
deadline = time.time() + 10
while time.time() < deadline:
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=0.2):
            break
    except OSError:
        time.sleep(0.1)
else:
    raise RuntimeError("Xray REALITY listener did not become ready")
PY

python3 -u - "$ECHO_PORT" >"$TMP_DIR/echo.log" 2>&1 <<'PY' &
import socket, sys, threading
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

mkdir -p "$TMP_DIR/chimera-home"
"$CLASH_BIN" -d "$TMP_DIR/chimera-home" -c "$TMP_DIR/chimera.yaml" \
    >"$TMP_DIR/chimera.log" 2>&1 &
CLASH_PID=$!

python3 - "$SOCKS_PORT" "$ECHO_PORT" <<'PY'
import socket, struct, sys, time
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
payload = b"reality-hybrid-xray-interop"
with socket.create_connection(("127.0.0.1", socks_port), timeout=3) as sock:
    sock.settimeout(10)
    sock.sendall(b"\x05\x01\x00")
    assert recv_exact(sock, 2) == b"\x05\x00"
    request = b"\x05\x01\x00\x01" + socket.inet_aton("127.0.0.1")
    sock.sendall(request + struct.pack("!H", echo_port))
    reply = recv_exact(sock, 10)
    assert reply[1] == 0, reply
    sock.sendall(payload)
    assert recv_exact(sock, len(payload)) == payload
PY

for _ in $(seq 1 50); do
    if grep -Fq "is using X25519MLKEM768 for TLS' communication: true" "$TMP_DIR/xray.log"; then
        echo "PASS REALITY X25519MLKEM768 VLESS interop against Xray"
        exit 0
    fi
    sleep 0.1
done
echo "traffic passed but Xray did not confirm X25519MLKEM768 negotiation" >&2
exit 4
