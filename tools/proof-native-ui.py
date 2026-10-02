#!/usr/bin/env python3
"""Exercise the real GTK/WebKit shell against a private Unix HTTP fixture."""
import argparse
import http.server
import json
import os
import pathlib
import socketserver
import subprocess
import threading

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--binary', type=pathlib.Path, required=True)
parser.add_argument('--work-dir', type=pathlib.Path, required=True)
args = parser.parse_args()
if not args.binary.is_absolute() or not args.work_dir.is_absolute():
    parser.error('binary and work directory must be absolute')
os.umask(0o077)
args.work_dir.mkdir(mode=0o700, parents=True, exist_ok=False)
sock = args.work_dir / 'admin.sock'
records, leaks = [], []
done = threading.Event()

class Canary(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        leaks.append(self.path)
        self.send_response(200)
        self.end_headers()
    def log_message(self, *args):
        pass

canary = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Canary)
threading.Thread(target=canary.serve_forever, daemon=True).start()
script = """async function main(){
const r=await fetch('/api/probe',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({hello:'unix'})});
const data=await r.json();let blocked=false;
try{await fetch('http://127.0.0.1:PORT/canary')}catch(e){blocked=true}
await fetch('/api/proof',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({status:r.status,data,networkBlocked:blocked})});
document.body.textContent='Native bridge proof completed';
}main().catch(e=>location.href='/error?'+encodeURIComponent(String(e)));""".replace('PORT', str(canary.server_port))

class Handler(http.server.BaseHTTPRequestHandler):
    def record(self):
        row = dict(method=self.command, path=self.path, host=self.headers.get('Host'), origin=self.headers.get('Origin'))
        records.append(row)
        return row
    def reply(self, status, kind, body):
        self.send_response(status)
        self.send_header('Content-Type', kind)
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)
    def do_GET(self):
        self.record()
        body = b'<!doctype html><html><body>Testing<script src="/app.js"></script></body></html>' if self.path == '/' else script.encode()
        self.reply(200, 'text/html' if self.path == '/' else 'text/javascript', body)
    def do_POST(self):
        row = self.record()
        row['body'] = json.loads(self.rfile.read(int(self.headers.get('Content-Length', '0'))))
        self.reply(418 if self.path == '/api/probe' else 200, 'application/json', json.dumps(row).encode())
        if self.path == '/api/proof':
            done.set()
    def log_message(self, *args):
        pass

server = socketserver.ThreadingUnixStreamServer(str(sock), Handler)
os.chmod(sock, 0o600)
threading.Thread(target=server.serve_forever, daemon=True).start()
with (args.work_dir / 'native.log').open('wb') as log:
    process = subprocess.Popen([str(args.binary), str(sock)], stdout=log, stderr=log)
    try:
        completed = done.wait(25)
        result = dict(completed=completed, records=records, direct_network_requests=leaks, native_exit=process.poll())
        (args.work_dir / 'result.json').write_text(json.dumps(result, indent=2) + '\n')
        assert completed and not leaks, result
        proof = next(row['body'] for row in records if row['path'] == '/api/proof')
        assert proof['status'] == 418 and proof['networkBlocked'] and proof['data']['body'] == dict(hello='unix')
        assert all(row['host'] == 'app' and row['origin'] == 'torkitten://app' for row in records)
        print('Native Unix bridge, response status, and network denial passed')
    finally:
        process.terminate()
        process.wait(10)
        server.shutdown()
        canary.shutdown()
        sock.unlink()
