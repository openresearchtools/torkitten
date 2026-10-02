# Native builds

The shared UI is embedded by the Go app. Linux uses GTK4/WebKitGTK 6.0 and
libsoup3. The native shell loads only `torkitten://app/`; requests go through a
fixed private Unix HTTP connection with Host `app` and Origin
`torkitten://app`. It forwards method, bounded body, status and content type.
The GTK save chooser accepts only `TorKitten-connection.png`, MIME `image/png`,
at most 2 MiB, from the trusted page’s Blob origin. The production chooser
requires an interactive save choice. The actual download callback passed exact
PNG bytes in `proofs/native-png-001`; only the chooser destination was substituted.

No native JavaScript object, remote page, service UI, public HTTP listener, or
TLS exception is used. A restrictive CSP and navigation policy keep external
content out. Login is delegated by the Go core through verified Tor/TLS/mTLS.

Build on Linux with rootless Podman:

```sh
tools/build-app.sh
```

The bundle is `/run/media/user/Data/TorkittenV2Build/artifacts/app` by default.
`TORKITTEN_BUILD_ROOT` may select another external build directory. The bundle
contains `bin/torkitten`, `bin/torkitten-native`, Tor, Caddy, Authelia and stock OpenSSH server/helpers; Chisel,
age and gozxing are compiled into the Go app. Component build metadata,
licenses and binary SHA256 sums accompany the binaries. The host needs GTK4
(4.10+), WebKitGTK 6.0, libsoup3, Tor's shared-library dependencies, `openssl`,
`/usr/bin/ssh-keygen`, `/usr/bin/cat`, and a working systemd user manager for hosting. A missing prerequisite is an error. On Ubuntu 24.04
or newer, install the runtime packages explicitly:

```sh
sudo apt-get install libgtk-4-1 libwebkitgtk-6.0-4 libsoup-3.0-0 libevent-2.1-7t64 libssl3t64 liblzma5 libzstd1 libcap2 libsystemd0 libseccomp2 libcrypt1 zlib1g coreutils openssl openssh-client
```

These system packages receive security updates through the host package manager;
they are not copied into the bundle. The pinned builder also installs `openssl`
and `openssh-client` explicitly. `tools/run-local.sh` checks the two command
prerequisites before opening the bundle and accepts the app's usual arguments.
The obsolete v1 container image/owner-reset launch paths are removed on this branch.

The bundle's `THIRD-PARTY-NOTICES.txt` identifies the dynamically linked LGPL
libraries and recipients' modification/relinking rights; `licenses/LGPL-2.1.txt`
contains the license. Authelia frontend license texts are collected from the
frozen pnpm dependency graph, with Vite/Rolldown/Tailwind runtime attribution.
MPL-2.0 Go module source archives accompany their notices in `sources/go-modules/`.
The `metadata/` inventories record the notice and source-archive hashes.

Launch with an explicit state directory and the bundle's absolute bin path:

```sh
/run/media/user/Data/TorkittenV2Build/artifacts/app/bin/torkitten \
  --state /run/media/user/Data/TorkittenV2Build/app-state \
  --bin-dir /run/media/user/Data/TorkittenV2Build/artifacts/app/bin
```

Closing the Linux window leaves the Go daemon running. The native shell can
also attach to an existing private `admin.sock`. The existing v1 state and
containers are independent. The complete bundled UI passed GTK rendering,
import dialog open/cancel/reset, host tab switching and actual service-form
persistence in isolated `proofs/ui-app-002` state. Its test-only harness does
not ship in the app.

To repeat the native bridge test on a desktop session, choose a fresh output
directory:

```sh
python3 tools/proof-native-ui.py \
  --binary /run/media/user/Data/TorkittenV2Build/artifacts/native/bin/torkitten-native \
  --work-dir /run/media/user/Data/TorkittenV2Build/proofs/native-ui-new
```

## Managed host SSH

The host SSH switch launches bundled OpenSSH 10.5p1 in its standard inetd mode
for each accepted private Unix stream. It uses the current unprivileged OS
account, per-identity Ed25519 host/login keys and fixed helper paths. The sole
key source is the fixed private public-key file read by stock OpenSSH’s
`AuthorizedKeysCommand` through `/usr/bin/cat`; `StrictModes` stays enabled.
Password, PAM, root, alternate users and SSH forwarding are disabled. Normal
exec, shell/PTY and internal SFTP remain available with the account’s permissions.
The native client receives credentials only after OAuth and writes a private
ordinary SSH configuration; JavaScript never receives these keys. Disabling
the switch closes existing SSH connections, and New identity replaces both keys.
No system-wide `sshd` configuration, service, package installation or TCP SSH
listener is needed. The opt-in `TestHostSSHRealCommandSFTPAndRevocation` test
runs as the actual host user with `TORKITTEN_SSH_BIN` set to the bundled bin path.

## Live QR camera permissions

The bundled scanner requests video only and decodes frames through the private
local Go API; frames are not uploaded through Tor or to a remote server. Linux
asks with a native GTK dialog whose default is Deny. Only the trusted
`torkitten://app` WebView may request camera capture. Microphone, display capture,
other permission types and other origins are denied. Closing the native window
cancels a pending prompt and disables camera capture. The shared UI stops tracks
on successful recognition, Cancel and page hiding. Saved QR images remain available through the file chooser.

The shell compiled with warnings as errors. Under
`TorkittenV2Build/proofs/camera-native-001`, a real WebKit mock-camera stream passed
video-only permission, stop, audio-only denial and mixed audio/video denial; the
native permission-dialog response was substituted only in the test binary.
Eight mocked denial cases cover untrusted/missing origins, other WebViews,
unknown permission types, audio, display and window closing. The actual shared
scanner UI passed synthetic canvas video → real local QR decoder → found-only
response → password form with the captured image retained locally, plus track
cleanup on success and Cancel, under
`proofs/scanner-ui-004`. No hardware camera capture or optical scanning was tested.
Its temporary app state was removed; retained frames contain only an encrypted
dummy payload with no server credentials.

## Android build boundary

`mobile/mobile.go` delegates the same private HTTP handler to a thin Java
WebView shell. The shell accepts only its bundled asset origin, blocks network
loads, exposes a narrow request bridge only there, and uses the OS file chooser
for saved QR images. Camera access uses Android's OS runtime permission
prompt and grants only `RESOURCE_VIDEO_CAPTURE` for exactly
`https://appassets.androidplatform.net`. Other origins, microphone and unknown
resources are denied. `onStop` cancels pending camera requests and invokes the
bundled scanner's track cleanup; it does not use `onPause`, which can accompany
the OS permission dialog itself. Activity destruction denies pending requests
and destroys the WebView, ending its grants and capture. The OS-level permission
remains controlled by Android and the user. This follows the Android
[permission-request API](https://developer.android.com/reference/android/webkit/PermissionRequest)
and [runtime-permission flow](https://developer.android.com/training/permissions/requesting).
Encrypted connection QR exports pass bounded PNG bytes through
`Native.save` to an OS create-document picker; no download URL is fetched. It never hosts service content. No loopback TCP
administration listener is introduced. The native adapter supplies the same
Host/Origin to the Go handler.

The optional build target requires a locally installed Android SDK platform36
and the [official NDK r30](https://developer.android.com/ndk/downloads), exact
revision `30.0.16248370`. Set `ANDROID_HOME` and `ANDROID_NDK_HOME`, then run:

```sh
tools/build-android.sh
```

It uses a pinned Go1.27.1 container and
`golang.org/x/mobile v0.0.0-20260908204917-8b95e45f8d3e`, builds an arm64 AAR with
minimum API26, and compiles the Java shell against SDK36. Outputs remain under
`TORKITTEN_BUILD_ROOT/android`. This target does not produce or sign an APK.

Android delivery is incomplete until a native arm64 Tor build is packaged in
the read-only application native-library directory as `libtor.so`, its required
libraries are included, the complete package is built and signed, and a real
device proves startup, Tor, TLS/mTLS, login, import, mapping and cleanup. Android
10+ prohibits executing binaries copied into writable application storage;
there is no runtime-download or alternate-transport path. The current Activity
closes its Go core when destroyed; background/foreground-service lifecycle is
not implemented. Android SDK/NDK are absent on the development host, so the
Android AAR and shell are **unbuilt and unverified**. Linux proof does not imply
Android compatibility.
