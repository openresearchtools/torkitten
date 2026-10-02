# GOST v2 transport proof

`tools/proof-gost.py` exercises the pinned **GOST v3.3.0** executable with
Python standard-library fixtures and `openssl`. It does not download or build
GOST. Use the binary produced from the pristine source snapshot, or the exact
upstream release binary after checking its recorded digest.

**Unresolved acceptance gate:** the pinned GOST implementation imposes a
10-second read deadline after half-close. The tests below do not establish
unrestricted, transparent transport for arbitrary services. A service that
must keep returning data longer after its peer finishes writing may exceed
that limit. This constraint must be resolved before claiming general service
compatibility; no different protocol or weaker security path is substituted.

## Why Caddy and GOST have different jobs

Caddy already supports **HTTP upstreams over Unix sockets**, as well as TCP
addresses, and proxies HTTP upgrades such as WebSockets. A Unix socket by
itself does not identify the application protocol: an HTTP server on a Unix
socket works with Caddy's HTTP reverse proxy; arbitrary SSH or other raw stream
bytes are not HTTP requests.

The missing operation is raw-stream-to-WebSocket conversion and its inverse:
accept native bytes on a client loopback port, carry them as WebSocket frames,
then deliver native bytes to the configured server TCP or Unix stream target.
The tested GOST configuration supplies that operation. Caddy supplies the HTTPS
gateway and Authelia authorization before the WebSocket upgrade. This proof
does not treat Caddy's Unix-socket support as a limitation.

Run from any directory, with absolute paths and a fresh output directory:

```sh
python3 /run/media/user/Data/Repositories/torkitten/tools/proof-gost.py \
  --gost /absolute/path/to/gost \
  --work-dir /run/media/user/Data/TorkittenV2Build/proofs/gost-run-001
```

The script rejects existing work directories and paths outside
`TorkittenV2Build`. It creates the directory with mode `0700`, uses umask `077`,
and writes all temporary certificates, configuration, logs and results there.
Nothing generated is written into the repository. It records the supplied
binary's version and SHA-256 in `results.json`. An exception, missing assertion
or failed assertion returns a nonzero exit status. Children are stopped before
the proof exits. No real credentials, external network service or elevated
privileges are used.

## Recorded source-build run

On 2026-10-02 the eight base assertions passed against the source-built binary:

```text
/run/media/user/Data/TorkittenV2Build/artifacts/third-party/gost/ubuntu-24.04-x86_64-v3.3.0-64c020de19a7-8637d6afe1eb86b7/usr/bin/gost
version: gost v3.3.0 (go1.27.1 linux/amd64)
SHA-256: 1c26facb31b3a7ad5a24defc4bb315301e340ad67db458bb59ed399319bb7bf6
source commit: cb76f63754768c7b5d68895a0d51635b0141b80f
source tree: 64c020de19a737f3a487d0fdc9739ab13a3938c3
recipe SHA-256: 8637d6afe1eb86b7004e5dd03c06db92de4d6f824c77b094ae2523417f5ba221
results: /run/media/user/Data/TorkittenV2Build/proofs/gost-source-001/results.json
```

An extended run of the same binary passed all twelve assertions, with results
at `/run/media/user/Data/TorkittenV2Build/proofs/gost-source-extended-002/results.json`.
Reproduce it with a **new** work directory and the two optional arguments:

```sh
python3 /run/media/user/Data/Repositories/torkitten/tools/proof-gost.py \
  --gost /run/media/user/Data/TorkittenV2Build/artifacts/third-party/gost/ubuntu-24.04-x86_64-v3.3.0-64c020de19a7-8637d6afe1eb86b7/usr/bin/gost \
  --work-dir /run/media/user/Data/TorkittenV2Build/proofs/gost-source-extended-003 \
  --half-close \
  --openssh-root /run/media/user/Data/TorkittenV2Build/proofs/openssh-fixture/extracted
```

The optional SSH test uses installed `ssh`, `sftp` and `ssh-keygen` clients,
plus an external extracted `openssh-server` package. For the recorded run,
Ubuntu `openssh-server` version `1:10.2p1-2ubuntu3.6` was downloaded with
`apt-get download` and unpacked using `dpkg-deb -x` into the directory above;
nothing was installed into the host. Its package SHA-256 was
`108256262b0fb7bb8eddd92e87230f775c90eb321413e8789754b3509f7b55c6`.
The matching `openssh-sftp-server` package was also extracted, but is not
needed: the fixture uses OpenSSH's built-in `internal-sftp` subsystem.
Server and clients reported OpenSSH 10.2p1. The fixture runs as the current
user, on loopback, with generated public-key authentication and strict host-key
verification. `AuthorizedKeysCommand /usr/bin/cat <fixture-public-key>` keeps
key lookup explicit without changing volume permissions or disabling
`StrictModes`; password login, PAM, forwarding and PTYs are disabled.

The extra assertions establish:

- OpenSSH executes `cat`; 64 KiB of binary stdin plus EOF returns unchanged
  stdout and a successful exit through the SOCKS/TLS/cookie fixture path.
- OpenSSH SFTP uploads and downloads 64 KiB unchanged through that same path.
- A direct TCP baseline and an independent stock GOST WSS connection both
  preserve a write half-close: the backend waits for EOF before replying with
  the complete payload. This separate diagnostic verifies the test CA and
  hostname but deliberately excludes the SOCKS/TLS gateway fixtures, whose
  small copy loops close both directions on EOF. It is not an alternative
  product route and does not prove half-close through Caddy or Tor.

The pinned GOST `internal/net/pipe.go` sets a **10-second read deadline after
half-close**. The passing response is immediate; indefinite half-close
transparency is not claimed.

## Exact tested configuration

Each client listener binds `127.0.0.1` and has a single fixed chain:

1. A TCP dialer and SOCKS5 connector to a local proxy fixture.
2. A WSS dialer and `forward` connector to the TLS gateway fixture. The WSS
   dialer explicitly sets `tls.secure: true`, `tls.serverName: gateway.test`,
   the test CA through `tls.caFile`, the exact service path, and a synthetic
   Cookie header.

There are no bypass rules, alternate nodes, chain selection policies, probes,
custom retry policies, TLS exceptions or plaintext transport alternatives.
The client's forwarding target is the fixed placeholder `127.0.0.1:0`; only
the server configuration contains the actual service destination.

The TLS fixture accepts the synthetic cookie and forwards the WebSocket
upgrade to a private GOST WS listener. That listener uses `handler.type:
forward`, with one fixed `forwarder.nodes` entry. One entry has
`network: tcp`; the other has `network: unix` and an absolute Unix stream socket
path. Protocol sniffing and payload rewriting are not enabled. The generated
JSON files in the work directory are the complete configurations that ran.

The script checks all of the following:

- A 64 KiB random payload arrives unchanged through the TCP service.
- The same payload arrives unchanged through the Unix stream service.
- An untrusted TLS certificate and a wrong expected hostname are rejected
  before any HTTP request reaches the fixture or service.
- Four requests without the cookie reach the gateway but never reach the
  protected service.
- Four requests through a denying SOCKS proxy, and four with the proxy absent,
  fail without reaching the directly accessible gateway or service.
- An `.onion` hostname reaches the SOCKS fixture as a hostname, and the
  configured stream still works when that fixture routes it locally.

## Interpretation and remaining proofs

This is a **real GOST executable with local SOCKS and TLS fixtures**. The TLS
fixture is not Caddy, the cookie check is not Authelia, and the SOCKS fixture is
not Tor. Passing proves only the listed behavior for the generated fixed
configuration. It does not establish Tor client authorization, real 2FA,
certificate provisioning, mTLS, browser cookie behavior, DNS confinement,
revocation, end-to-end half-close through Caddy/Tor, interactive SSH/PTYs,
SSE, nested WebSockets or the GTK client. Those require subsequent proofs.
SSH execution, SFTP and isolated GOST WSS half-close are covered only when
their optional assertions are selected and pass, as in the recorded run.

GOST's general router can choose its direct default route for an absent or
empty chain. Therefore this result must not be generalized to arbitrary GOST
configuration. TorKitten must render and validate the fixed chain, reject
missing prerequisites/configuration, and retain the failure tests. Configuring
an alternate transport or weakening TLS after a failure is not permitted.

The release's `go.mod` pins `github.com/go-gost/x v0.16.0`. The source paths
relevant to this proof are its `chain/chain.go`, `chain/route.go`,
`chain/router.go`, `dialer/ws/dialer.go`, `connector/forward/connector.go` and
`handler/forward/local/forward.go`. This test adds no transport implementation
to TorKitten; its small proxy and TLS implementations exist only as fixtures.

- [GOST v3.3.0 release](https://github.com/go-gost/gost/releases/tag/v3.3.0)
- [Pinned dependency versions](https://github.com/go-gost/gost/blob/v3.3.0/go.mod)
- [Fixed server forwarding](https://gost.run/en/tutorials/port-forwarding/#server-side-forwarding)
- [WebSocket dialer configuration](https://gost.run/en/reference/dialers/ws/)
- [Pinned route selection](https://github.com/go-gost/x/blob/v0.16.0/chain/route.go)
- [Pinned GOST pipe and half-close timeout](https://github.com/go-gost/x/blob/v0.16.0/internal/net/pipe.go)
- [Pinned GOST WebSocket stream adapter](https://github.com/go-gost/x/blob/v0.16.0/internal/util/ws/ws.go)
- [Caddy reverse proxy: Unix upstreams and WebSocket upgrades](https://caddyserver.com/docs/caddyfile/directives/reverse_proxy)
