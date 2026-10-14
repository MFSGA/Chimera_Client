#!/usr/bin/env python3
"""End-to-end Chimera -> Mihomo REALITY classic / X25519MLKEM768 test.

Run manually with MIHOMO_BIN, XRAY_BIN, CLASH_BIN, OPENSSL_BIN (OpenSSL 3+).
Uses ONLY loopback sockets and ephemeral keys/configuration. Never contacts
real proxy destinations or performs a compatibility-mode MMDB download.
The fake REALITY fallback target MUST be a TLS 1.3 server, not an echo socket.
"""
import os, pathlib, re, shutil, socket, struct, subprocess, tempfile, threading, time

ROOT = pathlib.Path(__file__).resolve().parents[2]
MIHOMO = pathlib.Path(os.environ.get('MIHOMO_BIN') or shutil.which('mihomo') or 'mihomo')
XRAY = pathlib.Path(os.environ.get('XRAY_BIN') or shutil.which('xray') or 'xray')
CHIMERA = pathlib.Path(os.environ.get('CLASH_BIN') or ROOT / 'target/debug/clash-rs')
OPENSSL = os.environ.get('OPENSSL_BIN') or shutil.which('openssl') or 'openssl'

UUID = 'b831381d-6324-4d53-ad4f-8cda48b30811'
for name, binary in [('MIHOMO_BIN', MIHOMO), ('XRAY_BIN', XRAY), ('CLASH_BIN', CHIMERA)]:
    if not binary.is_file() or not os.access(binary, os.X_OK):
        raise SystemExit(f'{name} must point to an executable: {binary}')
openssl_version=subprocess.check_output([OPENSSL,'version'],text=True,timeout=6)
if not openssl_version.startswith(('OpenSSL 3.','OpenSSL 4.')):
    raise SystemExit('OpenSSL 3+ is required for local TLS 1.3 camouflage; set OPENSSL_BIN')

def alloc_port():
    with socket.socket() as s:
        s.bind(('127.0.0.1', 0))
        return s.getsockname()[1]

def wait_port(port, process, secs=12):
    until = time.monotonic() + secs
    while time.monotonic() < until:
        if process.poll() is not None:
            raise RuntimeError('process exited before listener ready (exit=%s)' % process.returncode)
        try:
            with socket.create_connection(('127.0.0.1', port), timeout=.2):
                return
        except OSError:
            time.sleep(.12)
    raise RuntimeError('listener port %s not ready' % port)

def recv_exact(sock, size):
    parts=[]
    while size:
        data=sock.recv(size)
        if not data:
            raise RuntimeError('unexpected EOF during SOCKS reply/echo')
        parts.append(data)
        size-=len(data)
    return b''.join(parts)

def socks_round_trip(port, target_port, payload):
    with socket.create_connection(('127.0.0.1', port), timeout=3) as sock:
        sock.settimeout(10)
        sock.sendall(b'\x05\x01\x00')
        assert recv_exact(sock,2)==b'\x05\x00', 'SOCKS greeting failed'
        sock.sendall(b'\x05\x01\x00\x01'+socket.inet_aton('127.0.0.1')+struct.pack('!H',target_port))
        response=recv_exact(sock,10)
        assert response[1]==0, 'SOCKS connect rejected: %r' % response
        sock.sendall(payload)
        assert recv_exact(sock,len(payload))==payload, 'echo payload mismatch'

def terminate(proc):
    if proc is None: return
    if proc.poll() is None:
        proc.terminate()
        try: proc.wait(timeout=4)
        except subprocess.TimeoutExpired:
            proc.kill();proc.wait(timeout=4)

with tempfile.TemporaryDirectory(prefix='chimera-mihomo-reality-') as tmp:
    tmp=pathlib.Path(tmp)
    keys=subprocess.check_output([str(XRAY),'x25519'],text=True,timeout=8)
    private=re.search(r'^PrivateKey:\s*(\S+)',keys,re.M).group(1)
    public=re.search(r'^Password \(PublicKey\):\s*(\S+)',keys,re.M).group(1)
    vless_port,echo_port,tls_port=alloc_port(),alloc_port(),alloc_port()
    assert len({vless_port,echo_port,tls_port}) == 3
    # Echo listener stays bound; all network targets are literal localhost.
    echo=socket.socket()
    echo.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
    echo.bind(('127.0.0.1',echo_port));echo.listen(16)
    echo.settimeout(.5)
    stopping=threading.Event()
    def echo_client(c):
        with c:
            c.settimeout(5)
            try:
                while data:=c.recv(65536): c.sendall(data)
            except OSError: pass
    def echo_accept():
        while not stopping.is_set():
            try:c,_=echo.accept()
            except socket.timeout:continue
            except OSError:return
            threading.Thread(target=echo_client,args=(c,),daemon=True).start()
    thread=threading.Thread(target=echo_accept,daemon=True);thread.start()

    # REALITY camouflage fallback must speak genuine TLS 1.3; a raw TCP echo
    # server is NOT a valid REALITY dest and yields a false interop failure.
    tls_key=tmp/'camouflage.key';tls_crt=tmp/'camouflage.crt'
    subprocess.run([OPENSSL,'req','-x509','-newkey','rsa:2048','-nodes',
        '-keyout',str(tls_key),'-out',str(tls_crt),'-days','1',
        '-subj','/CN=example.com'],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=15)
    tls_log=tmp/'tls-camouflage.log'
    with open(tls_log,'w') as tls_out:
        tls_proc=subprocess.Popen([OPENSSL,'s_server','-accept',f'127.0.0.1:{tls_port}',
          '-cert',str(tls_crt),'-key',str(tls_key),'-tls1_3','-quiet'],
          stdout=tls_out,stderr=subprocess.STDOUT)
    wait_port(tls_port,tls_proc)
    print('Local REALITY camouflage TLS1.3 server ready on 127.0.0.1',flush=True)

    srv_cfg=tmp/'mihomo.yaml'
    srv_cfg.write_text(f'''mode: rule
log-level: warning
ipv6: false
allow-lan: false
dns:
  enable: false
listeners:
  - name: mihomo-reality-interop
    type: vless
    listen: 127.0.0.1
    port: {vless_port}
    users:
      - username: test
        uuid: {UUID}
    reality-config:
      dest: 127.0.0.1:{tls_port}
      private-key: "{private}"
      short-id: ["0102030405060708"]
      server-names: ["example.com"]
rules:
  - MATCH,DIRECT
''')
    (tmp/'mihomo-home').mkdir()
    validation=subprocess.run([str(MIHOMO),'-t','-f',str(srv_cfg),'-d',str(tmp/'mihomo-home')],capture_output=True,text=True,timeout=12)
    if validation.returncode:
        raise RuntimeError('Mihomo config rejected: '+validation.stderr[-900:]+validation.stdout[-900:])
    server_log=tmp/'mihomo.log'
    server=None
    try:
        with open(server_log,'w') as out:
            server=subprocess.Popen([str(MIHOMO),'-f',str(srv_cfg),'-d',str(tmp/'mihomo-home')],stdout=out,stderr=subprocess.STDOUT)
            wait_port(vless_port,server)
            print('Mihomo VLESS/REALITY server listening on loopback',flush=True)
            for hybrid in (False,True):
                name='hybrid-X25519MLKEM768' if hybrid else 'classic-X25519'
                socks_port=alloc_port()
                client_dir=tmp/name;client_dir.mkdir()
                client_cfg=client_dir/'chimera.yaml'
                client_cfg.write_text(f'''mixed-port: {socks_port}
allow-lan: false
bind-address: 127.0.0.1
mode: rule
log-level: warning
ipv6: false
mmdb: null
dns:
  enable: false
proxies:
  - name: mihomo-reality
    type: vless
    server: 127.0.0.1
    port: {vless_port}
    uuid: {UUID}
    tls: true
    server-name: example.com
    client-fingerprint: chrome
    reality-opts:
      public-key: {public}
      short-id: "0102030405060708"
      support-x25519mlkem768: {str(hybrid).lower()}
rules:
  - MATCH,mihomo-reality
''')
                cfgtest=subprocess.run([str(CHIMERA),'-t','-d',str(client_dir),'-c',str(client_cfg),'--compatibility','false'],capture_output=True,text=True,timeout=12)
                if cfgtest.returncode:
                    raise RuntimeError('Chimera config test rejected '+name+': '+cfgtest.stderr[-700:])
                cli_log=client_dir/'chimera.log'
                with open(cli_log,'w') as logfile:
                    cli=subprocess.Popen([str(CHIMERA),'-d',str(client_dir),'-c',str(client_cfg),'--compatibility','false'],stdout=logfile,stderr=subprocess.STDOUT)
                    try:
                        wait_port(socks_port,cli)
                        payload=('pr58-mihomo-'+name).encode()
                        socks_round_trip(socks_port,echo_port,payload)
                        print('PASS Chimera -> Mihomo VLESS/REALITY '+name+' TCP echo, payload exact',flush=True)
                    except Exception:
                        print('Chimera '+name+' failed; first error lines:',flush=True)
                        print('\n'.join(line[:240] for line in cli_log.read_text(errors='replace').splitlines() if ' ERROR ' in line or ' WARN ' in line)[-1300:],flush=True)
                        raise
                    finally:terminate(cli)
    except Exception:
        print('Mihomo server test failed; check local ephemeral configuration and TLS camouflage.',flush=True)
        raise
    finally:
        terminate(server);terminate(tls_proc);stopping.set();echo.close();thread.join(timeout=2)
print('MIHOMO_REALITY_INTEROP_ALL_PASS',flush=True)
