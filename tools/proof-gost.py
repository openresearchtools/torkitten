#!/usr/bin/env python3
"""Bounded GOST transport proof with local SOCKS/TLS fixtures, never real credentials."""
import argparse
import hashlib
import json
import os
import pathlib
import pwd
import select
import shutil
import socket
import socketserver
import ssl
import struct
import subprocess
import threading
import time

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--gost", required=True, type=pathlib.Path, help="absolute path to pinned GOST v3.3.0")
parser.add_argument("--work-dir", required=True, type=pathlib.Path, help="fresh directory below TorkittenV2Build")
parser.add_argument("--half-close", action="store_true", help="also test independent stock GOST WSS half-close")
parser.add_argument("--openssh-root", type=pathlib.Path, help="absolute extracted OpenSSH package root for optional SSH/SFTP proof")
args = parser.parse_args()
BUILD = pathlib.Path("/run/media/user/Data/TorkittenV2Build").resolve()
if not args.gost.is_absolute() or not args.work_dir.is_absolute():
    parser.error("--gost and --work-dir must be absolute paths")
GOST = args.gost.resolve()
ROOT = args.work_dir.resolve()
if not GOST.is_file() or not os.access(GOST, os.X_OK):
    parser.error("--gost must be an executable file")
if ROOT == BUILD or BUILD not in ROOT.parents or ROOT.exists():
    parser.error("--work-dir must be a fresh directory strictly below TorkittenV2Build")
if not shutil.which("openssl"):
    parser.error("openssl is required")
if args.openssh_root:
    if not args.openssh_root.is_absolute():
        parser.error("--openssh-root must be absolute")
    for name in ["usr/sbin/sshd", "usr/lib/openssh/sshd-session", "usr/lib/openssh/sshd-auth"]:
        if not os.access(args.openssh_root/name, os.X_OK):
            parser.error("missing OpenSSH executable: " + name)
    if not all(shutil.which(name) for name in ["ssh", "ssh-keygen", "sftp"]):
        parser.error("ssh, ssh-keygen and sftp are required for the OpenSSH proof")
version = subprocess.run([str(GOST), "-V"], check=True, capture_output=True, text=True, timeout=5).stdout.strip()
if not version.startswith("gost v3.3.0 "):
    parser.error("this proof requires the pinned GOST v3.3.0 binary")
os.umask(0o077)
ROOT.mkdir(mode=0o700, parents=True)
EXPECTED = {"tcp byte preservation", "unix byte preservation", "wrong-ca", "wrong-hostname", "missing-cookie", "proxy-denied", "proxy-absent", "onion hostname sent to SOCKS proxy"}
if args.half_close:
    EXPECTED.update(["direct TCP half-close baseline", "independent GOST WSS half-close"])
if args.openssh_root:
    EXPECTED.update(["OpenSSH exec stdin EOF and stdout", "OpenSSH SFTP binary round trip"])

PROCS = []
SERVERS = []
EVENTS = {"tcp": 0, "unix": 0, "gateway": [], "socks": []}
RESULTS = []

def port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]

def exact(s, n):
    data = b""
    while len(data) < n:
        b = s.recv(n-len(data))
        if not b: raise EOFError()
        data += b
    return data

def pipe(a,b):
    while True:
        for src in select.select([a,b], [], [], 3)[0]:
            data = src.recv(65536)
            if not data: return
            (b if src is a else a).sendall(data)

class Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True

class UnixServer(socketserver.ThreadingUnixStreamServer):
    daemon_threads = True

class Echo(socketserver.BaseRequestHandler):
    def handle(self):
        EVENTS[self.server.kind] += 1
        try:
            while True:
                data = self.request.recv(65536)
                if not data: break
                self.request.sendall(data)
        except OSError: pass

class AfterEOF(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.settimeout(5)
        data = b""
        try:
            while True:
                part = self.request.recv(65536)
                if not part: break
                data += part
            self.request.sendall(b"after-eof:" + data)
        except OSError: pass

class Socks(socketserver.BaseRequestHandler):
    def handle(self):
        s = self.request
        s.settimeout(3)
        try:
            v,n = exact(s,2)
            exact(s,n)
            s.sendall(b"\x05\x00")
            v,cmd,_,atyp = exact(s,4)
            if atyp == 1: host = socket.inet_ntoa(exact(s,4))
            elif atyp == 3: host = exact(s,exact(s,1)[0]).decode()
            else: raise ValueError("unexpected address type")
            destport = struct.unpack("!H",exact(s,2))[0]
            EVENTS["socks"].append([host,destport,self.server.mode])
            if self.server.mode == "deny":
                s.sendall(b"\x05\x02\x00\x01" + b"\x00"*6)
                return
            if host not in ["127.0.0.1", "exampletest.onion"] or destport != self.server.target:
                s.sendall(b"\x05\x02\x00\x01" + b"\x00"*6)
                return
            with socket.create_connection(("127.0.0.1",destport),3) as dst:
                s.sendall(b"\x05\x00\x00\x01" + b"\x00"*6)
                s.settimeout(None); dst.settimeout(None)
                pipe(s,dst)
        except (OSError,EOFError,ValueError): pass

class Gateway(socketserver.BaseRequestHandler):
    def handle(self):
        try:
            with self.server.context.wrap_socket(self.request,server_side=True) as s:
                s.settimeout(3)
                header = b""
                while b"\r\n\r\n" not in header and len(header)<16384:
                    header += exact(s,1)
                text = header.decode("latin1")
                path = text.split(" ",2)[1]
                valid_cookie = "Cookie: proof-cookie=sentinel\r\n" in text
                EVENTS["gateway"].append({"path":path,"cookie":valid_cookie})
                if not valid_cookie or path not in self.server.routes:
                    s.sendall(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n")
                    return
                with socket.create_connection(("127.0.0.1",self.server.routes[path]),3) as dst:
                    dst.sendall(header)
                    s.settimeout(None); dst.settimeout(None)
                    pipe(s,dst)
        except (OSError,EOFError): pass

def serve(s):
    SERVERS.append(s)
    threading.Thread(target=s.serve_forever,daemon=True).start()
    return s

def launch(name, cfg):
    path = ROOT/(name+".json")
    path.write_text(json.dumps(cfg,indent=2)+"\n")
    log = open(ROOT/(name+".log"),"wb")
    p = subprocess.Popen([str(GOST),"-C",str(path)],stdout=log,stderr=log)
    log.close()
    PROCS.append(p)
    time.sleep(.18)
    if p.poll() is not None: raise RuntimeError(name+" failed; inspect log")
    return p

def attempt(p, payload):
    try:
        with socket.create_connection(("127.0.0.1",p),1) as s:
            s.settimeout(2)
            s.sendall(payload)
            got = exact(s,len(payload))
            return got == payload
    except (OSError,EOFError): return False

def client_config(p, proxy, gateway, path, ca=True, hostname="gateway.test", cookie=True, host="127.0.0.1"):
    tls = {"secure":True,"serverName":hostname}
    if ca: tls["caFile"] = str(ROOT/"cert.pem")
    return {"log":{"level":"warn"},"services":[{"name":"client","addr":f"127.0.0.1:{p}","handler":{"type":"tcp","chain":"fixed"},"listener":{"type":"tcp"},"forwarder":{"nodes":[{"name":"placeholder","addr":"127.0.0.1:0"}]}}],"chains":[{"name":"fixed","hops":[{"name":"tor","nodes":[{"name":"tor-proxy","addr":f"127.0.0.1:{proxy}","connector":{"type":"socks5","metadata":{"notls":True}},"dialer":{"type":"tcp"}}]},{"name":"gateway","nodes":[{"name":"gateway","addr":f"{host}:{gateway}","connector":{"type":"forward"},"dialer":{"type":"wss","tls":tls,"metadata":{"path":path,"header":{"Cookie":"proof-cookie=sentinel"} if cookie else {}}}}]}]}]}

def half_close(p):
    payload = os.urandom(65536)
    try:
        with socket.create_connection(("127.0.0.1",p),1) as s:
            s.settimeout(5)
            s.sendall(payload)
            s.shutdown(socket.SHUT_WR)
            return exact(s,len(payload)+10) == b"after-eof:" + payload
    except (OSError,EOFError): return False

def openssh_proof(proxy, gateway, routes):
    key, hostkey = ROOT/"ssh-client", ROOT/"ssh-host"
    for path in [key, hostkey]:
        subprocess.run(["ssh-keygen","-q","-t","ed25519","-N","","-f",str(path)],check=True)
    sshport, wsport, localport = port(), port(), port()
    username = pwd.getpwuid(os.getuid()).pw_name
    config = ROOT/"sshd_config"
    config.write_text(f"ListenAddress 127.0.0.1\nPort {sshport}\nHostKey {hostkey}\nPidFile {ROOT/'sshd.pid'}\nAuthorizedKeysFile none\nAuthorizedKeysCommand /usr/bin/cat {key}.pub\nAuthorizedKeysCommandUser {username}\nUsePAM no\nPasswordAuthentication no\nKbdInteractiveAuthentication no\nAuthenticationMethods publickey\nAllowUsers {username}\nDisableForwarding yes\nPermitTTY no\nSshdSessionPath {args.openssh_root/'usr/lib/openssh/sshd-session'}\nSshdAuthPath {args.openssh_root/'usr/lib/openssh/sshd-auth'}\nSubsystem sftp internal-sftp\n")
    with open(ROOT/"sshd.log","wb") as log:
        sshd = subprocess.Popen([str(args.openssh_root/"usr/sbin/sshd"),"-D","-e","-f",str(config)],stdout=log,stderr=log)
    PROCS.append(sshd)
    time.sleep(.2)
    if sshd.poll() is not None: raise RuntimeError("sshd fixture failed; inspect sshd.log")
    launch("server-ssh",{"services":[{"name":"ssh","addr":f"127.0.0.1:{wsport}","handler":{"type":"forward"},"listener":{"type":"ws","metadata":{"path":"/ssh"}},"forwarder":{"nodes":[{"name":"sshd","addr":f"127.0.0.1:{sshport}","network":"tcp"}]}}]})
    routes["/ssh"] = wsport
    launch("client-ssh",client_config(localport,proxy,gateway,"/ssh"))
    known = ROOT/"known_hosts"
    known.write_text("proof-host " + (ROOT/"ssh-host.pub").read_text())
    options = ["-F","/dev/null","-o","BatchMode=yes","-o","IdentitiesOnly=yes","-o","StrictHostKeyChecking=yes","-o",f"UserKnownHostsFile={known}","-o","GlobalKnownHostsFile=/dev/null","-o","HostKeyAlias=proof-host","-o","ConnectTimeout=5","-i",str(key)]
    data = os.urandom(65536)
    remote = f"{username}@127.0.0.1"
    result = subprocess.run(["ssh",*options,"-p",str(localport),remote,"cat"],input=data,capture_output=True,timeout=15)
    (ROOT/"ssh-client.log").write_bytes(result.stderr)
    RESULTS.append({"test":"OpenSSH exec stdin EOF and stdout","passed":result.returncode==0 and result.stdout==data})
    source, uploaded, downloaded = ROOT/"upload.bin", ROOT/"remote.bin", ROOT/"download.bin"
    source.write_bytes(data)
    batch = ROOT/"sftp-batch"
    batch.write_text(f'put "{source}" "{uploaded}"\nget "{uploaded}" "{downloaded}"\n')
    result = subprocess.run(["sftp",*options,"-P",str(localport),"-b",str(batch),remote],capture_output=True,timeout=15)
    (ROOT/"sftp-client.log").write_bytes(result.stdout+result.stderr)
    RESULTS.append({"test":"OpenSSH SFTP binary round trip","passed":result.returncode==0 and uploaded.is_file() and downloaded.is_file() and uploaded.read_bytes()==data and downloaded.read_bytes()==data})

try:
    subprocess.run(["openssl","req","-x509","-newkey","ed25519","-nodes","-keyout",str(ROOT/"key.pem"),"-out",str(ROOT/"cert.pem"),"-days","1","-subj","/CN=gateway.test","-addext","subjectAltName=DNS:gateway.test"],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
    os.chmod(ROOT/"key.pem",0o600)
    tcp = Server(("127.0.0.1",0),Echo); tcp.kind="tcp"; serve(tcp)
    sockpath = ROOT/"echo.sock"
    if sockpath.exists(): sockpath.unlink()
    unix = UnixServer(str(sockpath),Echo); unix.kind="unix"; serve(unix)
    tcp_ws, unix_ws = port(),port()
    launch("server",{"log":{"level":"warn"},"services":[{"name":"tcp","addr":f"127.0.0.1:{tcp_ws}","handler":{"type":"forward"},"listener":{"type":"ws","metadata":{"path":"/tcp"}},"forwarder":{"nodes":[{"name":"tcp-target","addr":f"127.0.0.1:{tcp.server_address[1]}","network":"tcp"}]}},{"name":"unix","addr":f"127.0.0.1:{unix_ws}","handler":{"type":"forward"},"listener":{"type":"ws","metadata":{"path":"/unix"}},"forwarder":{"nodes":[{"name":"unix-target","addr":str(sockpath),"network":"unix"}]}}]})
    gw=Server(("127.0.0.1",0),Gateway); gw.routes={"/tcp":tcp_ws,"/unix":unix_ws}; gw.context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); gw.context.load_cert_chain(ROOT/"cert.pem",ROOT/"key.pem"); serve(gw)
    socks=Server(("127.0.0.1",0),Socks); socks.mode="allow"; socks.target=gw.server_address[1]; serve(socks)
    payload=os.urandom(65536)
    for name,path in [("tcp","/tcp"),("unix","/unix")]:
        p=port(); proc=launch("client-"+name,client_config(p,socks.server_address[1],gw.server_address[1],path))
        ok=attempt(p,payload); RESULTS.append({"test":name+" byte preservation","passed":ok}); proc.terminate();proc.wait(3)
    for name,kwargs,mode in [("wrong-ca",{"ca":False},"allow"),("wrong-hostname",{"hostname":"wrong.test"},"allow"),("missing-cookie",{"cookie":False},"allow"),("proxy-denied",{},"deny"),("proxy-absent",{},"absent")]:
        socks.mode=mode
        p=port(); proxy=port() if mode=="absent" else socks.server_address[1]
        before=len(EVENTS["gateway"]); backend_before=EVENTS["tcp"]
        proc=launch("client-"+name,client_config(p,proxy,gw.server_address[1],"/tcp",**kwargs))
        successes=sum(attempt(p,b"negative-proof") for _ in range(4))
        entry={"test":name,"passed":successes==0 and EVENTS["tcp"]==backend_before,"gateway_requests":len(EVENTS["gateway"])-before,"backend_connections":EVENTS["tcp"]-backend_before}
        if mode in ["deny","absent"]:entry["passed"]=entry["passed"] and entry["gateway_requests"]==0
        if name in ["wrong-ca", "wrong-hostname"]:
            entry["passed"] = entry["passed"] and entry["gateway_requests"] == 0
        if name == "missing-cookie":
            requests = EVENTS["gateway"][before:]
            entry["passed"] = entry["passed"] and len(requests) == 4 and not any(r["cookie"] for r in requests)
        RESULTS.append(entry);proc.terminate();proc.wait(3)
    socks.mode="allow"
    p=port();proc=launch("client-onion-host",client_config(p,socks.server_address[1],gw.server_address[1],"/tcp",host="exampletest.onion"))
    RESULTS.append({"test":"onion hostname sent to SOCKS proxy","passed":attempt(p,b"onion-check") and any(x[0]=="exampletest.onion" for x in EVENTS["socks"])});proc.terminate();proc.wait(3)
    if args.openssh_root:
        openssh_proof(socks.server_address[1],gw.server_address[1],gw.routes)
    if args.half_close:
        backend = serve(Server(("127.0.0.1",0),AfterEOF))
        RESULTS.append({"test":"direct TCP half-close baseline","passed":half_close(backend.server_address[1])})
        wsport, localport = port(), port()
        launch("server-half-close",{"services":[{"name":"half-close","addr":f"127.0.0.1:{wsport}","handler":{"type":"forward"},"listener":{"type":"wss","tls":{"certFile":str(ROOT/"cert.pem"),"keyFile":str(ROOT/"key.pem")},"metadata":{"path":"/half-close"}},"forwarder":{"nodes":[{"name":"after-eof","addr":f"127.0.0.1:{backend.server_address[1]}","network":"tcp"}]}}]})
        cfg = client_config(localport,0,wsport,"/half-close")
        # Isolate GOST WSS semantics from the deliberately simple SOCKS/TLS fixtures.
        cfg["chains"][0]["hops"] = cfg["chains"][0]["hops"][1:]
        launch("client-half-close",cfg)
        RESULTS.append({"test":"independent GOST WSS half-close","passed":half_close(localport)})
finally:
    for p in PROCS:
        if p.poll() is None:
            p.terminate()
            try:p.wait(3)
            except subprocess.TimeoutExpired:p.kill();p.wait()
    for s in SERVERS:s.shutdown();s.server_close()
    (ROOT/"echo.sock").unlink(missing_ok=True)
    out={"version":version,"binary":str(GOST),"binary_sha256":hashlib.sha256(GOST.read_bytes()).hexdigest(),"scope":"Real pinned GOST executable; local SOCKS5 and TLS gateway fixtures, not real Tor/Caddy/Authelia integration","half_close_selected":args.half_close,"openssh_root":str(args.openssh_root) if args.openssh_root else None,"results":RESULTS,"events":EVENTS}
    (ROOT/"results.json").write_text(json.dumps(out,indent=2)+"\n")
    print(json.dumps({"work_dir":str(ROOT),"results":RESULTS},indent=2))

if {r["test"] for r in RESULTS} != EXPECTED or not all(r["passed"] for r in RESULTS):
    raise SystemExit(1)
