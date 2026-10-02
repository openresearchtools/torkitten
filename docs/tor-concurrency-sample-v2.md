# Tor and Chisel concurrency sample

On 2026-10-02 an isolated fixture exercised the public Tor network with
Tor 0.4.9.13, Caddy 2.11.6 and Chisel 1.12.0. Every sample delivered the checked
data, but one shared Chisel connection produced a 10.49-second SSE arrival
gap. This is evidence against promising smooth concurrent operation from
protocol compatibility alone. It does not prove which component caused the gap.

| Path | UI p95 | Worst UI request | Largest SSE arrival gap | SSE p95 delivery delay | 2 MiB download |
| --- | ---: | ---: | ---: | ---: | ---: |
| Localhost | 1.07 ms | 2.58 ms | 101 ms | 0.25 ms | 0.003 s |
| Tor + TLS | 2.13 s | 2.28 s | 1.62 s | 2.05 s | 16.88 s |
| Tor + TLS + one Chisel connection | 2.63 s | 11.04 s | 10.49 s | 11.39 s | 13.12 s |
| Tor + TLS + four Chisel connections | 2.12 s | 2.46 s | 1.93 s | 2.66 s | 19.30 s |

Each sample ran two concurrent UI workers, each making 20 requests for a
12,330-byte synthetic page; one SSE stream producing 150 numbered events at
100 ms intervals; and one 2 MiB binary download. Workers reused HTTP/1.1
connections. All 40 UI responses passed status/length checks, all 150 SSE events
arrived in their exact sequence, and each binary download matched its expected
length and SHA-256. Eight MiB of bulk data was transferred across all four
samples. No tunnel reconnections occurred; retries were disabled.

Both Tor processes ran on the same host, with independent data directories and
an actual client-authorized v3 onion service on the public network. Source-built
Tor/Caddy binaries came from the existing v2 build artifacts. Chisel's official
release asset was checked against its recorded GitHub asset digest:

```text
release: v1.12.0, published 2026-08-29T13:30:36Z
asset: chisel_1.12.0_linux_amd64.gz
asset SHA-256: f3f180f1d93aa72cce4e6386f98cc06569a0146fbd65eb4423cf83e6434bcfe6
binary SHA-256: 811362311f13ac4bdc42fe4e7650aca618a68e3a40f930de88536d18b14d2b52
```

TLS used an explicitly trusted ephemeral certificate with onion hostname
verification. Chisel used a pinned server SSH fingerprint, random credentials
and an anchored exact-target ACL. Caddy listened on a private Unix socket;
other fixture listeners used loopback. The Tor/TLS baseline intentionally
exposed its synthetic HTTP backend through Caddy for comparison. That control
route is not the product architecture. **Authelia and mTLS were absent**;
this sample does not establish complete authorization or revocation behavior.

This was one sequential run in the table's order, with no repetitions or
per-connection circuit telemetry. Separate Chisel connections shared the same
Tor client and SOCKS port, with no additional circuit-isolation credentials.
Circuit sharing and changes are unknown. Tor bootstrap/publication were
excluded; initial Tor/TLS requests included SOCKS/TLS setup, whereas Chisel
connections were established before their workloads. Logical-channel setup
remained included. These differences prevent attributing the measured latency
change solely to Chisel, encryption or multiplexing.

This is not an actual browser, llama.cpp, ComfyUI, long-duration, 100 MiB-transfer
or throughput-guarantee test. Separate connections improved worst-case
responsiveness in this sample while completing the bulk transfer more slowly.
One transport implementation need not mean one shared network connection.
Neither arrangement guarantees LAN-like responsiveness over Tor.

The script, raw timings, sanitized summary, lineage and cleanup record are in
`/run/media/user/Data/TorkittenV2Build/proofs/tor-chisel-perf-001/`. All fixture
children exited; only its own ephemeral keys, credentials and Tor state were
removed. Existing application state and earlier proofs were not changed.

- [Chisel release](https://github.com/jpillora/chisel/releases/tag/v1.12.0)
- [Channel per accepted connection](https://github.com/jpillora/chisel/blob/v1.12.0/share/tunnel/tunnel_in_proxy.go)
- [SSH channel flow control](https://github.com/golang/crypto/blob/v0.55.0/ssh/channel.go)
- [Tor onion-service path](https://community.torproject.org/onion-services/overview/)
