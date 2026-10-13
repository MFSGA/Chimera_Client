#!/usr/bin/env python3
"""Real Mihomo VLESS Native 1-RTT TCP/UDP interop over localhost.

Manually run with MIHOMO_BIN, XRAY_BIN (for temporary key generation), and
CLASH_BIN set to executable paths. Tests native/xorpub/random appearances,
using an ephemeral Mihomo server, SOCKS5 TCP and UDP echo, temporary config,
and no remote proxy targets, privileged networking, or user credential files.
"""
import pathlib,subprocess,tempfile,socket,struct,time,threading,re,json,os,shutil
ROOT=pathlib.Path(__file__).resolve().parents[2]
MIHOMO=pathlib.Path(os.environ.get('MIHOMO_BIN') or shutil.which('mihomo') or 'mihomo')
XRAY=pathlib.Path(os.environ.get('XRAY_BIN') or shutil.which('xray') or 'xray')
CHIMERA=pathlib.Path(os.environ.get('CLASH_BIN') or ROOT/'target/debug/clash-rs')
for name,binary in [('MIHOMO_BIN',MIHOMO),('XRAY_BIN',XRAY),('CLASH_BIN',CHIMERA)]:
 if not binary.is_file() or not os.access(binary,os.X_OK):
  raise SystemExit(f'{name} must point to an executable: {binary}')
UUID='b831381d-6324-4d53-ad4f-8cda48b30811'

def reserve():
 with socket.socket() as s:
  s.bind(('127.0.0.1',0));return s.getsockname()[1]
def check_ready(port,p):
 for _ in range(120):
  if p.poll() is not None:raise RuntimeError('server exited '+str(p.returncode))
  try:
   with socket.create_connection(('127.0.0.1',port),timeout=.2):return
  except OSError:time.sleep(.1)
 raise RuntimeError('listener not ready')
def terminate(p):
 if p and p.poll() is None:
  p.terminate()
  try:p.wait(timeout=3)
  except subprocess.TimeoutExpired:p.kill();p.wait(timeout=3)
def recvn(s,n):
 a=b''
 while len(a)<n:
  p=s.recv(n-len(a))
  if not p:raise RuntimeError('connection EOF; expected '+str(n)+' got '+str(len(a)))
  a+=p
 return a
def roundtrip(socks_port,echo_port,mode):
 payload=('chimera-mihomo-'+mode+'.1rtt').encode()
 with socket.create_connection(('127.0.0.1',socks_port),timeout=3) as s:
  s.settimeout(11);s.sendall(b'\x05\x01\x00')
  assert recvn(s,2)==b'\x05\x00'
  s.sendall(b'\x05\x01\x00\x01'+socket.inet_aton('127.0.0.1')+struct.pack('!H',echo_port))
  reply=recvn(s,10);assert reply[1]==0,reply
  s.sendall(payload)
  assert recvn(s,len(payload))==payload,'mismatched echo'
def udp_roundtrip(socks_port,udp_echo_port,mode):
 payload=('chimera-mihomo-udp-'+mode+'.1rtt').encode()
 with socket.create_connection(('127.0.0.1',socks_port),timeout=3) as control:
  control.settimeout(12);control.sendall(b'\x05\x01\x00')
  assert recvn(control,2)==b'\x05\x00'
  control.sendall(b'\x05\x03\x00\x01\x00\x00\x00\x00\x00\x00')
  response=recvn(control,10)
  assert response[1]==0,response
  relay_addr=socket.inet_ntoa(response[4:8]);relay_port=struct.unpack('!H',response[8:10])[0]
  if relay_addr=='0.0.0.0':relay_addr='127.0.0.1'
  with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as udp:
   udp.settimeout(12)
   packet=b'\x00\x00\x00\x01'+socket.inet_aton('127.0.0.1')+struct.pack('!H',udp_echo_port)+payload
   udp.sendto(packet,(relay_addr,relay_port));reply,_=udp.recvfrom(65535)
   assert reply==packet,(len(reply),len(packet))

raw=subprocess.check_output([str(XRAY),'vlessenc'],text=True,timeout=15)
server_key=re.search(r'"decryption": "([^"]+)"',raw).group(1)
client_key=re.search(r'"encryption": "([^"]+)"',raw).group(1)
assert '.native.' in server_key and '.native.' in client_key and '.0rtt.' in client_key
for mode in ('native','xorpub','random'):
 with tempfile.TemporaryDirectory(prefix='chimera-mihomo-native-') as d:
  p=pathlib.Path(d);server_port,socks_port,echo_port,udp_echo_port=reserve(),reserve(),reserve(),reserve()
  assert len({server_port,socks_port,echo_port,udp_echo_port})==4
  echo=socket.socket();echo.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1);echo.bind(('127.0.0.1',echo_port));echo.listen(16);echo.settimeout(.3)
  stop=threading.Event()
  def serve(c):
   with c:
    c.settimeout(5)
    try:
     while q:=c.recv(65536):c.sendall(q)
    except OSError:pass
  def loop():
   while not stop.is_set():
    try:c,_=echo.accept()
    except socket.timeout:continue
    except OSError:break
    threading.Thread(target=serve,args=(c,),daemon=True).start()
  t=threading.Thread(target=loop,daemon=True);t.start()
  udp_echo=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
  udp_echo.bind(('127.0.0.1',udp_echo_port));udp_echo.settimeout(.4)
  def loop_udp():
   while not stop.is_set():
    try:data,addr=udp_echo.recvfrom(65535)
    except socket.timeout:continue
    except OSError:break
    try:udp_echo.sendto(data,addr)
    except OSError:break
  tu=threading.Thread(target=loop_udp,daemon=True);tu.start()
  decryption=server_key.replace('.native.','.'+mode+'.')
  encryption=client_key.replace('.native.','.'+mode+'.').replace('.0rtt.','.1rtt.')
  scfg=p/'mihomo.yaml'
  scfg.write_text(f'''mode: rule\nlog-level: warning\nallow-lan: false\nipv6: false\ndns:\n  enable: false\nlisteners:\n  - name: mihomo-native\n    type: vless\n    listen: 127.0.0.1\n    port: {server_port}\n    users:\n      - username: test\n        uuid: {UUID}\n    decryption: {json.dumps(decryption)}\nrules:\n  - MATCH,DIRECT\n''')
  ccfg=p/'chimera.yaml'
  ccfg.write_text(f'''mixed-port: {socks_port}\nallow-lan: false\nbind-address: 127.0.0.1\nmode: rule\nlog-level: warning\nipv6: false\nmmdb: null\ndns:\n  enable: false\nproxies:\n  - name: mihomo-native\n    type: vless\n    server: 127.0.0.1\n    port: {server_port}\n    uuid: {UUID}\n    udp: true\n    encryption: {json.dumps(encryption)}\nrules:\n  - MATCH,mihomo-native\n''')
  (p/'mh').mkdir();(p/'ch').mkdir()
  vr=subprocess.run([str(MIHOMO),'-t','-f',str(scfg),'-d',str(p/'mh')],capture_output=True,text=True,timeout=12)
  assert vr.returncode==0,'Mihomo server config rejected: '+vr.stderr[-500:]
  vr2=subprocess.run([str(CHIMERA),'-t','-d',str(p/'ch'),'-c',str(ccfg),'--compatibility','false'],capture_output=True,text=True,timeout=12)
  assert vr2.returncode==0,'Chimera client config rejected: '+vr2.stderr[-500:]
  sproc=None;cproc=None
  try:
   with open(p/'mihomo.log','w') as sl,open(p/'chimera.log','w') as cl:
    sproc=subprocess.Popen([str(MIHOMO),'-f',str(scfg),'-d',str(p/'mh')],stdout=sl,stderr=subprocess.STDOUT)
    check_ready(server_port,sproc)
    cproc=subprocess.Popen([str(CHIMERA),'-d',str(p/'ch'),'-c',str(ccfg),'--compatibility','false'],stdout=cl,stderr=subprocess.STDOUT)
    check_ready(socks_port,cproc)
    try:
     roundtrip(socks_port,echo_port,mode)
     udp_roundtrip(socks_port,udp_echo_port,mode)
    except Exception:
     print('Mihomo last log:', '\n'.join((p/'mihomo.log').read_text(errors='replace').splitlines()[-14:]),flush=True)
     print('Chimera error log:', '\n'.join(y[:240] for y in (p/'chimera.log').read_text(errors='replace').splitlines() if 'ERROR' in y or 'WARN' in y)[-1600:],flush=True)
     raise
    print('PASS Chimera -> Mihomo native VLESS '+mode+'.1rtt TCP + UDP echo exact',flush=True)
  finally:
   terminate(cproc);terminate(sproc);stop.set();echo.close();udp_echo.close();t.join(timeout=2);tu.join(timeout=2)
print('MIHOMO_NATIVE_ALL_PASS')
