# Running Torkitten in Podman or Docker

The OCI image contains the same daemon, administration pages, remote portal,
Tor, Caddy, and persistent state model as the native package. It runs as UID
10001 without capabilities. Tor and Caddy are children of `torkittend`; they
are shut down cleanly with the container and recovered with bounded backoff if
they fail.

The container keeps its executables beneath `/opt/torkitten`. This prevents a
host's native Torkitten AppArmor profiles from being attached accidentally to
the container processes when both forms are installed on the same machine.

## Default loopback-only administration

Use `packaging/oci/compose.yaml` with either Podman Compose or Docker Compose:

```sh
TORKITTEN_IMAGE=localhost/torkitten:0.1.0 podman compose \
  -f packaging/oci/compose.yaml up -d
```

Open [http://localhost:12755](http://localhost:12755). The first visit creates
the persistent administrator; later visits use normal revocable sessions. The
named volume preserves identities, certificates, sites, mappings, guests, and
settings when the container is replaced.

The only published container port is the administration service, and it is
bound to host loopback. Onion virtual ports are internal Unix sockets and must
never be added to `ports:`.

## Containerized upstream applications

An upstream that binds its own loopback address must share Torkitten's network
namespace. In Compose, add the application to the same project and set:

```yaml
services:
  application:
    image: your-application-image
    network_mode: service:torkitten
```

The application may then listen on a distinct port such as
`127.0.0.1:3000`, and that exact address can be selected in the Torkitten
mapping. Do not add the application port to `ports:` unless you independently
intend to publish it on the host.

The Podman-native equivalent is a pod:

```sh
podman pod create --name torkitten-pod -p 127.0.0.1:12755:12755
podman run -d --pod torkitten-pod --name torkitten \
  --read-only --cap-drop=all --security-opt=no-new-privileges \
  --tmpfs /tmp:rw,mode=1777 \
  -v torkitten-state:/var/lib/torkitten \
  localhost/torkitten:0.1.0
podman run -d --pod torkitten-pod --name application your-application-image
```

## Explicit native-host loopback access

Applications bound to the Linux host's `127.0.0.1` are not reachable through
the default isolated container namespace. Use host networking only when that
access is intentional:

```sh
TORKITTEN_IMAGE=localhost/torkitten:0.1.0 podman compose \
  -f packaging/oci/compose.host-network.yaml up -d
```

This standalone configuration does not publish container ports. Torkitten
itself binds administration to `127.0.0.1:12755`, while its mapping validator
continues to accept only numeric loopback targets or approved absolute Unix
sockets. It does not install a SOCKS proxy, alter firewall rules, or route
unrelated host traffic through Tor.

## Local image build

Download the verified GitHub Actions Tor and Caddy artifacts, then run:

```sh
./tools/package-oci.sh
```

The repository is mounted read-only for compilation. Podman storage, Cargo
cache, staging context, the built image, and the OCI archive remain under
`/run/media/user/Data/TorkittenBuild` by default.
