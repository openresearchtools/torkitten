#!/usr/bin/env python3
# Copyright 2026 The Torkitten Authors
# SPDX-License-Identifier: Apache-2.0
"""Real pinned Authelia OAuth + Caddy mTLS proof; private external fixtures, no Tor."""
import argparse
import base64
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import secrets
import socket
import struct
import subprocess
import time
import urllib.parse


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('authelia', type=Path)
    p.add_argument('caddy', type=Path)
    p.add_argument('workdir', type=Path)
    p.add_argument('--rotate', action='store_true', help='also prove global client-registration epoch revocation')
    p.add_argument('--image', default='localhost/torkitten-builder:ubuntu-24.04-8c5d997e863bd2be')
    args = p.parse_args()
    repo = Path(__file__).resolve().parent.parent
    work = args.workdir.resolve()
    if work.is_relative_to(repo):
        p.error('fixtures must be outside the repository')
    os.umask(0o077)
    work.mkdir(parents=True, exist_ok=False)
    processes, logs = [], []
    env = {k: v for k, v in os.environ.items() if not k.startswith('AUTHELIA_')}
    env.update(XDG_CONFIG_HOME=str(work / 'config-home'), XDG_DATA_HOME=str(work / 'data-home'))

    def run(*argv):
        r = subprocess.run(list(map(str, argv)), env=env, stdout=subprocess.PIPE,
                           stderr=subprocess.STDOUT, text=True, timeout=60)
        if r.returncode:
            (work / 'failed-command.private.log').write_text(r.stdout)
            raise RuntimeError(f'Fixture command failed ({r.returncode}); private diagnostic file retained')
        return r.stdout

    def start(name, argv):
        log = (work / f'{name}.log').open('w')
        logs.append(log)
        proc = subprocess.Popen(list(map(str, argv)), env=env, stdout=log, stderr=subprocess.STDOUT)
        processes.append(proc)
        return proc

    onion = 'a' * 56 + '.onion'  # Component test identity only; never advertised as a Tor service.
    issuer, audience, client_id = f'https://{onion}/login', f'https://{onion}', 'torkitten-proof'
    generated = run(args.authelia, 'crypto', 'hash', 'generate', 'argon2', '--random', '--random.length', '48')
    password = re.search(r'^Random Password: (.+)$', generated, re.M).group(1)
    digest = re.search(r'^Digest: (.+)$', generated, re.M).group(1)
    (work / 'users.yml').write_text(json.dumps({'users': {'proof_owner': {
        'disabled': False, 'displayname': 'OAuth proof', 'password': digest, 'groups': ['proof-owner']}}}))
    run('openssl', 'genpkey', '-algorithm', 'RSA', '-pkeyopt', 'rsa_keygen_bits:2048', '-out', work / 'oidc.key')
    config = {
        'log': {'level': 'warn', 'format': 'json'},
        'server': {'address': f'unix://{work}/authelia.sock?umask=0077&path=login',
                   'disable_healthcheck': True, 'endpoints': {'authz': {'forward-auth': {
                       'implementation': 'ForwardAuth', 'authn_strategies': [
                           {'name': 'HeaderAuthorization', 'schemes': ['Bearer']}]}}}},
        'totp': {'issuer': 'TorKitten OAuth proof', 'algorithm': 'sha1', 'digits': 6, 'period': 30, 'skew': 1},
        'webauthn': {'disable': True},
        'authentication_backend': {'password_reset': {'disable': True}, 'file': {'path': str(work / 'users.yml')}},
        'access_control': {'default_policy': 'deny', 'rules': [
            {'domain': onion, 'subject': 'group:proof-owner', 'policy': 'two_factor'}]},
        'session': {'secret': secrets.token_urlsafe(48), 'name': 'proof_session', 'cookies': [
            {'domain': onion, 'authelia_url': issuer, 'default_redirection_url': audience + '/'}]},
        'storage': {'encryption_key': secrets.token_urlsafe(48), 'local': {'path': str(work / 'db.sqlite3')}},
        'notifier': {'filesystem': {'filename': str(work / 'notifications.txt')}},
        'ntp': {'disable_startup_check': True}, 'telemetry': {'metrics': {'enabled': False}},
        'identity_providers': {'oidc': {'hmac_secret': secrets.token_urlsafe(48),
            'jwks': [{'key': (work / 'oidc.key').read_text(), 'algorithm': 'RS256', 'use': 'sig'}],
            'clients': [{'client_id': client_id, 'client_name': 'TorKitten proof', 'public': True,
                'authorization_policy': 'two_factor', 'consent_mode': 'explicit',
                'redirect_uris': ['http://127.0.0.1/oauth/callback'],
                'scopes': ['authelia.bearer.authz', 'offline_access'], 'audience': [audience],
                'grant_types': ['authorization_code', 'refresh_token'], 'response_types': ['code'],
                'response_modes': ['form_post'], 'token_endpoint_auth_method': 'none',
                'require_pushed_authorization_requests': True, 'require_pkce': True, 'pkce_challenge_method': 'S256'}]}}
    }
    cfg = work / 'configuration.yml'
    cfg.write_text(json.dumps(config, indent=2))
    run(args.authelia, 'config', 'validate', '--config', cfg)
    run(args.authelia, 'storage', 'migrate', 'up', '--config', cfg)
    generated = run(args.authelia, 'storage', 'user', 'totp', 'generate', 'proof_owner', '--config', cfg)
    uri = re.search(r"URI '(otpauth://[^']+)'", generated).group(1)
    secret = urllib.parse.parse_qs(urllib.parse.urlsplit(uri).query)['secret'][0]
    for name, purpose in [('server', 'serverAuth'), ('client', 'clientAuth')]:
        ext = work / f'{name}.ext'
        ext.write_text('basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\n'
                       + f'extendedKeyUsage={purpose}\n' + (f'subjectAltName=DNS:{onion}\n' if name == 'server' else ''))
        run('openssl', 'genpkey', '-algorithm', 'EC', '-pkeyopt', 'ec_paramgen_curve:P-256', '-out', work / f'{name}.key')
        run('openssl', 'x509', '-new', '-key', work / f'{name}.key', '-subj', f'/CN={name}',
            '-extfile', ext, '-days', '2', '-out', work / f'{name}.pem')
    with socket.socket() as s:
        s.bind(('127.0.0.1', 0))
        port = s.getsockname()[1]
    caddyfile = work / 'Caddyfile'
    caddyfile.write_text(f'''{{
 admin unix/{work}/admin.sock
 auto_https off
}}
https://{onion}:{port} {{
 bind 127.0.0.1
 tls {work}/server.pem {work}/server.key {{
  client_auth {{
   mode require_and_verify
   trust_pool file {work}/client.pem
   verifier leaf {{
    file {work}/client.pem
   }}
  }}
 }}
 handle /login/* {{
  reverse_proxy unix/{work}/authelia.sock
 }}
 handle {{
  forward_auth unix/{work}/authelia.sock {{
   uri /login/api/authz/forward-auth
   header_up X-Forwarded-Host {onion}
  }}
  respond "authorized"
 }}
}}
''')
    run(args.caddy, 'validate', '--config', caddyfile, '--adapter', 'caddyfile')
    success = False
    try:
        auth = start('authelia', [args.authelia, '--config', cfg])
        start('caddy', [args.caddy, 'run', '--config', caddyfile, '--adapter', 'caddyfile'])
        deadline = time.monotonic() + 20
        while not (work / 'admin.sock').exists() or not (work / 'authelia.sock').exists():
            if any(proc.poll() is not None for proc in processes) or time.monotonic() > deadline:
                raise RuntimeError('Fixture startup failed; inspect private logs')
            time.sleep(.1)
        counter = struct.pack('>Q', int(time.time()) // 30)
        key = base64.b32decode(secret + '=' * (-len(secret) % 8))
        digest = hmac.new(key, counter, hashlib.sha1).digest()
        offset = digest[-1] & 15
        totp = f'{(struct.unpack(">I", digest[offset:offset+4])[0] & 0x7fffffff) % 1000000:06d}'
        proof = work / 'proof.private.json'
        proof.write_text(json.dumps({'Issuer': issuer, 'Audience': audience, 'ClientID': client_id,
            'Address': f'127.0.0.1:{port}', 'CA': str(work / 'server.pem'),
            'Certificate': str(work / 'client.pem'), 'Key': str(work / 'client.key'),
            'Username': 'proof_owner', 'Password': password, 'TOTP': totp, 'EpochControl': str(work) if args.rotate else ''}))
        test = subprocess.Popen([str(repo / 'tools/container.sh'), 'run', '--rm', '--userns=host', '--network=host',
            '-v', f'{repo}:/src:ro', '-v', f'{work}:{work}:rw',
            '-v', '/run/media/user/Data/TorkittenV2Build:/work:rw', '-w', '/src',
            '-e', 'GOCACHE=/work/cache/go-build', '-e', 'GOMODCACHE=/work/cache/go-mod', '-e', 'GOFLAGS=-mod=readonly',
            '-e', f'TORKITTEN_OAUTH_PROOF={proof}', args.image, 'go', 'test', '-count=1', '-v', './internal/oauth',
            '-run', '^TestLiveAuthelia$'], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        deadline = time.monotonic() + 90
        rotated = False
        while test.poll() is None:
            if time.monotonic() > deadline:
                test.kill()
                raise RuntimeError('Real OAuth proof timed out')
            if args.rotate and not rotated and (work / 'rotate.ready').exists():
                auth.terminate(); auth.wait(timeout=10)
                config['identity_providers']['oidc']['clients'][0]['client_id'] += '-next'
                cfg.write_text(json.dumps(config, indent=2))
                auth = start('authelia-next', [args.authelia, '--config', cfg])
                time.sleep(1)
                if auth.poll() is not None:
                    raise RuntimeError('Epoch Authelia restart failed')
                (work / 'rotate.done').write_text('done')
                rotated = True
            time.sleep(.1)
        output, _ = test.communicate()
        (work / 'test.log').write_text(output)
        success = test.returncode == 0
        print(output, end='')
        if not success:
            raise RuntimeError('Real OAuth proof failed; inspect private fixture evidence')
    finally:
        for proc in reversed(processes):
            proc.terminate()
            try: proc.wait(timeout=10)
            except subprocess.TimeoutExpired: proc.kill(); proc.wait()
        for log in logs: log.close()
        (work / 'results.json').write_text(json.dumps({'passed': success,
            'scope': 'Real pinned Authelia native OAuth APIs and Caddy strict TLS/mTLS; loopback fixture, not Tor',
            'authelia_sha256': hashlib.sha256(args.authelia.read_bytes()).hexdigest(),
            'caddy_sha256': hashlib.sha256(args.caddy.read_bytes()).hexdigest()}, indent=2))


if __name__ == '__main__':
    main()
