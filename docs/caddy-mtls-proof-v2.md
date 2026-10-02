# Caddy v2 device mTLS proof

`tools/proof-caddy-mtls.py` runs the pinned, source-built Caddy executable with
local fixtures. It proves that a device can use an independently generated,
self-signed client certificate without adding an online certificate authority
or custom Caddy authentication module.

Run with Python 3.9 or newer, Python TLS support and OpenSSL 3.5 or newer:

```sh
python3 /run/media/user/Data/Repositories/torkitten/tools/proof-caddy-mtls.py \
  /absolute/path/to/caddy \
  /run/media/user/Data/TorkittenV2Build/proofs/caddy-mtls-new-run
```

The output directory must be new and outside the repository. The script uses
umask `077`; generated credentials, configurations, logs and `results.json`
stay in that directory. Both HTTP fixtures bind only to loopback. The Caddy
administration API uses a private Unix socket. No actual device credentials,
external service, host trust-store changes or elevated privileges are used.
The executable is supplied explicitly and is never downloaded by the proof.

## Recorded result

On 2026-10-02 all **32 assertions passed** using:

```text
binary: /run/media/user/Data/TorkittenV2Build/artifacts/third-party/caddy/ubuntu-24.04-x86_64-v2.11.6-1290d7636728-f99b5538ef5b9c75/usr/bin/caddy
version: v2.11.6
binary SHA-256: d19687f449d7af33e7d879b96f49c76a9b4bfa6b5a889187c5e116c2e6d80056
source commit: ac834b5dc70a17dca296f47c78c64587d6631cbb
source tree: 1290d76367286ca5eafed88f549f3f186ada24d5
recipe SHA-256: f99b5538ef5b9c750473ec7b0b95084285ea92bb9311b8fe5a86f6381232f827
OpenSSL and Python SSL: OpenSSL 3.5.5
results: /run/media/user/Data/TorkittenV2Build/proofs/caddy-mtls-004/results.json
```

The credentials are P-256 self-signed certificates with `CA:FALSE`, digital
signature key usage and client-authentication extended key usage. OpenSSL
creates them; there is no certificate issuance code in TorKitten. Caddy uses
`require_and_verify`, the stock file certificate pool, and the stock exact-leaf
verifier. The same approved device certificate appears in the trust pool and
the leaf allowlist. Caddy's JSON field is `ca`; its Caddyfile equivalent is
`trust_pool`. The generated JSON is the complete tested configuration.

Both TLS 1.2 and TLS 1.3 pass these checks:

- A valid, explicitly approved device reaches the endpoint.
- Missing credentials and a device outside the trust pool are rejected.
- A trusted certificate omitted from the exact-leaf allowlist is rejected.
- An expired certificate is rejected even when trusted and allowlisted.
- A certificate with only server-authentication EKU is rejected even when
  trusted and allowlisted.
- Removing only one device from the leaf allowlist, keeping the trust pool
  unchanged, rejects its fresh and cached-session reconnection attempts.
  A second approved device continues to connect.

**Pinned Caddy disables session tickets whenever TLS client authentication is
configured.** The proof asserts that its mTLS listener issues no tickets and
never resumes. A separate, explicitly unauthenticated fixture successfully
resumes both TLS versions, establishing that the test client supports session
resumption. This fixture is a test control only; it is not a product route.
The result does not claim that an actual resumed mTLS connection was tested:
stock Caddy prevents that case. Retain this assertion when refreshing Caddy.

## Limits

This proof validates stock Caddy's device-certificate admission and reconnect
behavior. It does not establish Authelia login, Tor authorization, GOST mTLS
support, GTK private-CA trust, bootstrap import, TLS renewal, or termination of
already-open tunnels. Those require their own real-component proofs.

Reloading an allowlist is not an active-connection revocation mechanism.
TorKitten must stop acceptance and close active streams when revoking access.
Likewise, revoking Authelia sessions does not revoke an approved device's
certificate: that device can log in again with fresh 2FA. A revoked device
must be removed from its allowlist as a distinct policy change.

`require_and_verify` matters: the exact-leaf verifier compares certificate
identity; by itself it does not establish expiry or client-authentication EKU.
Do not replace the tested mode with `require` while claiming those checks.

- [Pinned Caddy client authentication and ticket disabling](https://github.com/caddyserver/caddy/blob/v2.11.6/modules/caddytls/connpolicy.go)
- [Pinned Caddy leaf file loader](https://github.com/caddyserver/caddy/blob/v2.11.6/modules/caddytls/leaffileloader.go)
- [Caddy TLS configuration](https://caddyserver.com/docs/caddyfile/directives/tls)
