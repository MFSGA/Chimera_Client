#!/usr/bin/env python3
"""Run local VLESS Native 1-RTT TCP and UDP interoperability checks.

Set MIHOMO_BIN, XRAY_BIN, and CLASH_BIN to executable paths, then run this
script manually. It uses loopback listeners, temporary configuration files,
and a fixed test UUID; it does not use remote proxy targets or user configs.
"""

from __future__ import annotations

import json
import os
import pathlib
import re
import shutil
import socket
import struct
import subprocess
import tempfile
import threading
import time

ROOT = pathlib.Path(__file__).resolve().parents[2]
MIHOMO = pathlib.Path(
    os.environ.get("MIHOMO_BIN") or shutil.which("mihomo") or "mihomo"
)
XRAY = pathlib.Path(os.environ.get("XRAY_BIN") or shutil.which("xray") or "xray")
CHIMERA = pathlib.Path(
    os.environ.get("CLASH_BIN") or ROOT / "target/debug/clash-rs"
)
UUID = "b831381d-6324-4d53-ad4f-8cda48b30811"
APPEARANCES = ("native", "xorpub", "random")


def require_executable(name: str, binary: pathlib.Path) -> None:
    if not binary.is_file() or not os.access(binary, os.X_OK):
        raise SystemExit(f"{name} must point to an executable: {binary}")


def reserve_tcp_ports(count: int) -> dict[int, socket.socket]:
    """Hold unique loopback TCP ports until each service is ready to bind."""
    reservations: dict[int, socket.socket] = {}
    try:
        while len(reservations) < count:
            reserved = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            reserved.bind(("127.0.0.1", 0))
            port = reserved.getsockname()[1]
            if port in reservations:
                reserved.close()
                continue
            reservations[port] = reserved
    except OSError:
        close_reservations(reservations)
        raise
    return reservations


def close_reservations(reservations: dict[int, socket.socket]) -> None:
    for reserved in reservations.values():
        reserved.close()
    reservations.clear()


def release_port(
    reservations: dict[int, socket.socket], port: int
) -> None:
    reserved = reservations.pop(port, None)
    if reserved is not None:
        reserved.close()


def check_ready(
    port: int, process: subprocess.Popen[bytes], name: str
) -> None:
    deadline = time.monotonic() + 12
    while time.monotonic() < deadline:
        status = process.poll()
        if status is not None:
            raise RuntimeError(f"{name} exited before readiness (status {status})")
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.25):
                return
        except OSError:
            time.sleep(0.1)
    raise RuntimeError(f"{name} did not listen on 127.0.0.1:{port} within 12s")


def terminate(process: subprocess.Popen[bytes] | None) -> None:
    if process is None or process.poll() is not None:
        return
    process.terminate()
    try:
        process.wait(timeout=3)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=3)


def recv_exact(sock: socket.socket, length: int) -> bytes:
    chunks = bytearray()
    while len(chunks) < length:
        part = sock.recv(length - len(chunks))
        if not part:
            raise RuntimeError(
                f"unexpected EOF: expected {length} bytes, got {len(chunks)}"
            )
        chunks.extend(part)
    return bytes(chunks)


def tcp_roundtrip(socks_port: int, echo_port: int, mode: str) -> None:
    payload = f"chimera-mihomo-{mode}.1rtt".encode()
    with socket.create_connection(("127.0.0.1", socks_port), timeout=3) as sock:
        sock.settimeout(11)
        sock.sendall(b"\x05\x01\x00")
        if recv_exact(sock, 2) != b"\x05\x00":
            raise RuntimeError("SOCKS5 no-auth negotiation failed")

        request = (
            b"\x05\x01\x00\x01"
            + socket.inet_aton("127.0.0.1")
            + struct.pack("!H", echo_port)
        )
        sock.sendall(request)
        reply = recv_exact(sock, 10)
        if reply[1] != 0:
            raise RuntimeError(f"SOCKS5 CONNECT failed: {reply!r}")

        sock.sendall(payload)
        response = recv_exact(sock, len(payload))
        if response != payload:
            raise RuntimeError("TCP echo payload did not match")


def udp_roundtrip(socks_port: int, echo_port: int, mode: str) -> None:
    payload = f"chimera-mihomo-udp-{mode}.1rtt".encode()
    with socket.create_connection(("127.0.0.1", socks_port), timeout=3) as control:
        control.settimeout(12)
        control.sendall(b"\x05\x01\x00")
        if recv_exact(control, 2) != b"\x05\x00":
            raise RuntimeError("SOCKS5 no-auth negotiation failed")

        control.sendall(b"\x05\x03\x00\x01\x00\x00\x00\x00\x00\x00")
        response = recv_exact(control, 10)
        if response[1] != 0 or response[3] != 1:
            raise RuntimeError(f"SOCKS5 UDP ASSOCIATE failed: {response!r}")

        relay_address = socket.inet_ntoa(response[4:8])
        relay_port = struct.unpack("!H", response[8:10])[0]
        if relay_address == "0.0.0.0":
            relay_address = "127.0.0.1"

        request = (
            b"\x00\x00\x00\x01"
            + socket.inet_aton("127.0.0.1")
            + struct.pack("!H", echo_port)
            + payload
        )
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp:
            udp.settimeout(12)
            udp.sendto(request, (relay_address, relay_port))
            response, _ = udp.recvfrom(65535)
        if response != request:
            raise RuntimeError("UDP echo datagram did not match")


def start_tcp_echo(
    listener: socket.socket, stop: threading.Event
) -> threading.Thread:
    listener.listen(16)
    listener.settimeout(0.25)

    def serve_connection(connection: socket.socket) -> None:
        with connection:
            connection.settimeout(5)
            try:
                while True:
                    data = connection.recv(65536)
                    if not data:
                        return
                    connection.sendall(data)
            except OSError:
                return

    def serve() -> None:
        while not stop.is_set():
            try:
                connection, _ = listener.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            threading.Thread(
                target=serve_connection, args=(connection,), daemon=True
            ).start()

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    return thread


def start_udp_echo(
    listener: socket.socket, stop: threading.Event
) -> threading.Thread:
    listener.settimeout(0.25)

    def serve() -> None:
        while not stop.is_set():
            try:
                data, address = listener.recvfrom(65535)
            except socket.timeout:
                continue
            except OSError:
                return
            try:
                listener.sendto(data, address)
            except OSError:
                return

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    return thread


def print_log_tail(path: pathlib.Path, label: str, limit: int) -> None:
    if not path.exists():
        return
    lines = path.read_text(errors="replace").splitlines()[-limit:]
    print(f"{label}:\n" + "\n".join(lines), flush=True)


def run_mode(
    mode: str,
    server_key: str,
    client_key: str,
) -> None:
    with tempfile.TemporaryDirectory(prefix="chimera-mihomo-native-") as temp:
        work = pathlib.Path(temp)
        reservations = reserve_tcp_ports(4)
        server_port, socks_port, echo_port, udp_echo_port = reservations
        stop = threading.Event()
        tcp_listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        udp_listener = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        server_process: subprocess.Popen[bytes] | None = None
        client_process: subprocess.Popen[bytes] | None = None
        tcp_thread: threading.Thread | None = None
        udp_thread: threading.Thread | None = None

        mihomo_log = work / "mihomo.log"
        chimera_log = work / "chimera.log"

        try:
            release_port(reservations, echo_port)
            tcp_listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            tcp_listener.bind(("127.0.0.1", echo_port))
            tcp_thread = start_tcp_echo(tcp_listener, stop)

            release_port(reservations, udp_echo_port)
            udp_listener.bind(("127.0.0.1", udp_echo_port))
            udp_thread = start_udp_echo(udp_listener, stop)

            decryption = server_key.replace(".native.", f".{mode}.")
            encryption = client_key.replace(".native.", f".{mode}.").replace(
                ".0rtt.", ".1rtt."
            )
            server_config = work / "mihomo.yaml"
            server_config.write_text(
                f"""mode: rule
log-level: warning
allow-lan: false
ipv6: false
dns:
  enable: false
listeners:
  - name: mihomo-native
    type: vless
    listen: 127.0.0.1
    port: {server_port}
    users:
      - username: test
        uuid: {UUID}
    decryption: {json.dumps(decryption)}
rules:
  - MATCH,DIRECT
"""
            )

            client_config = work / "chimera.yaml"
            client_config.write_text(
                f"""mixed-port: {socks_port}
allow-lan: false
bind-address: 127.0.0.1
mode: rule
log-level: warning
ipv6: false
mmdb: null
dns:
  enable: false
proxies:
  - name: mihomo-native
    type: vless
    server: 127.0.0.1
    port: {server_port}
    uuid: {UUID}
    udp: true
    encryption: {json.dumps(encryption)}
rules:
  - MATCH,mihomo-native
"""
            )

            (work / "mihomo-home").mkdir()
            (work / "chimera-home").mkdir()
            validate_mihomo = subprocess.run(
                [
                    str(MIHOMO),
                    "-t",
                    "-f",
                    str(server_config),
                    "-d",
                    str(work / "mihomo-home"),
                ],
                capture_output=True,
                text=True,
                timeout=12,
            )
            if validate_mihomo.returncode != 0:
                raise RuntimeError(
                    "Mihomo rejected generated config: "
                    + validate_mihomo.stderr[-500:]
                )

            validate_chimera = subprocess.run(
                [
                    str(CHIMERA),
                    "-t",
                    "-d",
                    str(work / "chimera-home"),
                    "-c",
                    str(client_config),
                    "--compatibility",
                    "false",
                ],
                capture_output=True,
                text=True,
                timeout=12,
            )
            if validate_chimera.returncode != 0:
                raise RuntimeError(
                    "Chimera rejected generated config: "
                    + validate_chimera.stderr[-500:]
                )

            release_port(reservations, server_port)
            with mihomo_log.open("w") as server_output:
                server_process = subprocess.Popen(
                    [
                        str(MIHOMO),
                        "-f",
                        str(server_config),
                        "-d",
                        str(work / "mihomo-home"),
                    ],
                    stdout=server_output,
                    stderr=subprocess.STDOUT,
                )
                check_ready(server_port, server_process, "Mihomo")

                release_port(reservations, socks_port)
                with chimera_log.open("w") as client_output:
                    client_process = subprocess.Popen(
                        [
                            str(CHIMERA),
                            "-d",
                            str(work / "chimera-home"),
                            "-c",
                            str(client_config),
                            "--compatibility",
                            "false",
                        ],
                        stdout=client_output,
                        stderr=subprocess.STDOUT,
                    )
                    check_ready(socks_port, client_process, "Chimera")
                    tcp_roundtrip(socks_port, echo_port, mode)
                    udp_roundtrip(socks_port, udp_echo_port, mode)

            print(
                f"PASS Chimera -> Mihomo VLESS {mode}.1rtt TCP + UDP echo",
                flush=True,
            )
        except Exception:
            print_log_tail(mihomo_log, "Mihomo log", 14)
            print_log_tail(chimera_log, "Chimera log", 14)
            raise
        finally:
            terminate(client_process)
            terminate(server_process)
            stop.set()
            tcp_listener.close()
            udp_listener.close()
            if tcp_thread is not None:
                tcp_thread.join(timeout=2)
            if udp_thread is not None:
                udp_thread.join(timeout=2)
            close_reservations(reservations)


def generate_keys() -> tuple[str, str]:
    result = subprocess.run(
        [str(XRAY), "vlessenc"],
        capture_output=True,
        text=True,
        timeout=15,
        check=True,
    )
    server_match = re.search(r'"decryption": "([^"]+)"', result.stdout)
    client_match = re.search(r'"encryption": "([^"]+)"', result.stdout)
    if server_match is None or client_match is None:
        raise RuntimeError("Xray vlessenc output did not contain both keys")

    server_key = server_match.group(1)
    client_key = client_match.group(1)
    if (
        ".native." not in server_key
        or ".native." not in client_key
        or ".0rtt." not in client_key
    ):
        raise RuntimeError("Xray vlessenc returned an unexpected key format")
    return server_key, client_key


def main() -> None:
    for name, binary in (
        ("MIHOMO_BIN", MIHOMO),
        ("XRAY_BIN", XRAY),
        ("CLASH_BIN", CHIMERA),
    ):
        require_executable(name, binary)

    server_key, client_key = generate_keys()
    for mode in APPEARANCES:
        run_mode(mode, server_key, client_key)
    print("MIHOMO_NATIVE_ALL_PASS")


if __name__ == "__main__":
    main()
