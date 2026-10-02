#!/usr/bin/env python3
"""Exercise a real Caddy binary; create all credentials in a new external directory."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import socket
import ssl
import subprocess
import time


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path)
    parser.add_argument("workdir", type=Path)
    args = parser.parse_args()
    binary, work = args.binary.resolve(), args.workdir.resolve()
    if work.is_relative_to(Path(__file__).resolve().parent.parent):
        parser.error("fixtures must be outside the repository")
    os.umask(0o077)
    work.mkdir(parents=True, exist_ok=False)

    def run(*command):
        return subprocess.check_output(command, stderr=subprocess.STDOUT, text=True, timeout=15).strip()

    def certificate(name, purpose="clientAuth", expired=False):
        key, cert = work / f"{name}.key", work / f"{name}.pem"
        extensions = work / f"{name}.extensions"
        extensions.write_text("basicConstraints=critical,CA:FALSE\n"
                              "keyUsage=critical,digitalSignature\n"
                              f"extendedKeyUsage={purpose}\n"
                              + ("subjectAltName=DNS:mtls.test\n" if name == "server" else ""))
        run("openssl", "genpkey", "-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:P-256",
            "-out", str(key))
        dates = ["-not_before", "20200101000000Z", "-not_after", "20200102000000Z"] if expired else ["-days", "2"]
        run("openssl", "x509", "-new", "-key", str(key), "-subj", f"/CN={name}",
            "-extfile", str(extensions), *dates, "-out", str(cert))
        return cert, key

    certs = {name: certificate(name, "serverAuth" if name in ("server", "wrong-eku") else "clientAuth",
                               name == "expired")
             for name in ("server", "approved", "spare", "unlisted", "unknown", "expired", "wrong-eku")}
    trusted = ["approved", "spare", "unlisted", "expired", "wrong-eku"]
    allowed = [name for name in trusted if name != "unlisted"]
    with socket.socket() as reserve, socket.socket() as control:
        reserve.bind(("127.0.0.1", 0))
        control.bind(("127.0.0.1", 0))
        port, control_port = reserve.getsockname()[1], control.getsockname()[1]
    admin = work / "admin.sock"
    config = {
        "admin": {"listen": f"unix/{admin}", "config": {"persist": False}},
        "storage": {"module": "file_system", "root": str(work / "storage")},
        "apps": {
            "tls": {"certificates": {"load_files": [{"certificate": str(certs["server"][0]),
                                                     "key": str(certs["server"][1])}]}},
            "http": {"servers": {"proof": {
                "listen": [f"127.0.0.1:{port}"], "protocols": ["h1"],
                "automatic_https": {"disable": True},
                "tls_connection_policies": [{"client_authentication": {
                    "mode": "require_and_verify",
                    "ca": {"provider": "file", "pem_files": [str(certs[n][0]) for n in trusted]},
                    "verifiers": [{"verifier": "leaf", "leaf_certs_loaders": [
                        {"loader": "file", "files": [str(certs[n][0]) for n in allowed]}]}]}}],
                "routes": [{"handle": [{"handler": "static_response", "body": "authorized"}]}]
            }}}
        }
    }
    # A separate unauthenticated fixture proves this client can resume TLS.
    config["apps"]["http"]["servers"]["control"] = {
        "listen": [f"127.0.0.1:{control_port}"], "protocols": ["h1"],
        "automatic_https": {"disable": True}, "tls_connection_policies": [{}],
        "routes": [{"handle": [{"handler": "static_response", "body": "authorized"}]}]
    }
    initial = work / "initial.json"
    initial.write_text(json.dumps(config, indent=2))
    caddy_version = run(str(binary), "version")
    run(str(binary), "validate", "--config", str(initial))
    log = (work / "caddy.log").open("w")
    env = dict(os.environ, XDG_DATA_HOME=str(work / "data"), XDG_CONFIG_HOME=str(work / "config"))
    process = subprocess.Popen([str(binary), "run", "--config", str(initial)], env=env,
                               stdout=log, stderr=subprocess.STDOUT)
    results = []

    def context(name, version=ssl.TLSVersion.TLSv1_3):
        ctx = ssl.create_default_context(cafile=str(certs["server"][0]))
        ctx.minimum_version = ctx.maximum_version = version
        if name:
            ctx.load_cert_chain(*map(str, certs[name]))
        return ctx

    def request(label, ctx, expect, session=None, expect_reused=None, target_port=port):
        raw, tls = None, None
        try:
            raw = socket.create_connection(("127.0.0.1", target_port), timeout=5)
            tls = ctx.wrap_socket(raw, server_hostname="mtls.test", session=session)
            tls.sendall(b"GET / HTTP/1.1\r\nHost: mtls.test\r\nConnection: close\r\n\r\n")
            response = b""
            while data := tls.recv(4096):
                response += data
            accepted = response.startswith(b"HTTP/1.1 200") and response.endswith(b"authorized")
            outcome = {"case": label, "accepted": accepted, "session_reused": tls.session_reused,
                       "ticket_received": tls.session.has_ticket, "tls": tls.version()}
            new_session = tls.session
        except ssl.SSLError as error:
            outcome = {"case": label, "accepted": False, "tls_error": str(error)}
            accepted, new_session = False, None
        finally:
            if tls:
                tls.close()
            elif raw:
                raw.close()
        outcome["passed"] = accepted == expect and (
            expect_reused is None or outcome.get("session_reused") == expect_reused)
        results.append(outcome)
        assert outcome["passed"], outcome
        return new_session

    try:
        deadline = time.monotonic() + 10
        while not admin.exists():
            assert process.poll() is None, "Caddy exited; inspect caddy.log"
            assert time.monotonic() < deadline, "Caddy admin readiness timed out"
            time.sleep(0.05)
        for version in (ssl.TLSVersion.TLSv1_2, ssl.TLSVersion.TLSv1_3):
            for name in ("approved", None, "unlisted", "unknown", "expired", "wrong-eku"):
                request(f"{name or 'missing'}-{version.name}", context(name, version), name == "approved")
        sessions = []
        for version in (ssl.TLSVersion.TLSv1_2, ssl.TLSVersion.TLSv1_3):
            control_ctx = context(None, version)
            control_session = request(f"control-{version.name}-initial", control_ctx, True,
                                      expect_reused=False, target_port=control_port)
            assert control_session.has_ticket, "Positive control did not receive a session ticket"
            request(f"control-{version.name}-resumed", control_ctx, True, control_session,
                    True, control_port)
            for name in ("approved", "spare"):
                ctx = context(name, version)
                first = request(f"{name}-{version.name}-initial", ctx, True, expect_reused=False)
                assert not first.has_ticket, "Caddy unexpectedly enabled session tickets for mTLS"
                retried = request(f"{name}-{version.name}-cached-session", ctx, True, first, False)
                sessions.append((name, version, ctx, retried))
        policy = config["apps"]["http"]["servers"]["proof"]["tls_connection_policies"][0]
        policy["client_authentication"]["verifiers"][0]["leaf_certs_loaders"][0]["files"] = [
            str(certs[n][0]) for n in allowed if n != "approved"]
        # Leave the trust pool unchanged: only the stock leaf allowlist revokes this device.
        revoked = work / "revoked.json"
        revoked.write_text(json.dumps(config, indent=2))
        run(str(binary), "reload", "--config", str(revoked), "--address", f"unix/{admin}")
        for name, version, ctx, session in sessions:
            request(f"{name}-{version.name}-after-revoke-cached-session", ctx, name == "spare", session,
                    False if name == "spare" else None)
            request(f"{name}-{version.name}-after-revoke-fresh", context(name, version), name == "spare")
    finally:
        process.terminate()
        try:
            process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)
        log.close()
        report = {"caddy_version": caddy_version,
                  "binary": str(binary), "binary_sha256": hashlib.sha256(binary.read_bytes()).hexdigest(),
                  "openssl": run("openssl", "version"), "python_ssl": ssl.OPENSSL_VERSION,
                  "scope": "Real Caddy with local self-signed fixtures; no Tor, Authelia, GOST or GTK integration",
                  "results": results}
        (work / "results.json").write_text(json.dumps(report, indent=2) + "\n")
    print(f"PASS: {len(results)} real Caddy mTLS cases; evidence: {work / 'results.json'}")


if __name__ == "__main__":
    main()
