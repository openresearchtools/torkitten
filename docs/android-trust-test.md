# Android browser trust experiment — 2026-09-05

## Scope and versions

This is evidence from real Android browser applications in a KVM-backed Google
Android Emulator, not desktop browsers with mobile emulation. It is **not** a
physical-device support declaration or evidence about iOS Safari.

A separate dummy container, owner, TOTP enrollment, Tor identity, authorized
client, and host-loopback application were used. The retained user service was
not changed. Server code, certificate policy, and image were unchanged:

- Torkitten source: `6b4faf389f81fabd92f385c4b28a8509f3b38e92`.
- Image: `67b9affa3b07283574a73673625f1af5ee3a19e78e06ec329d86dd91a1c3ec84`.
- Caddy 2.11.4, Authelia 4.39.20, Tor 0.4.9.11.

| Client component | Tested version |
| --- | --- |
| Android | 17 / API 37; Google Play x86_64, 16 KiB pages, SDK image 37.1 revision 9 |
| Emulator | 37.1.11; KVM; visible window for the Firefox investigation |
| Orbot | 17.9.5-RC-4 / Tor 0.4.9.11 |
| Chrome | 149.0.7827.5, bundled in the Google image; not claimed to be the newest Chrome |
| Firefox | 155.0.1, Mozilla's release APK |
| Firefox proxy extension | FoxyProxy Standard 9.7, installed through Mozilla Add-ons |

Chrome's initial tests used the emulator with its window hidden. The browser
itself was the installed Android app, not a headless desktop browser. Tests
continued with the Android window visible. A later software-renderer stall was
resolved by restarting only the test emulator with host GPU rendering.

## Chrome result

1. Before CA installation, Chrome showed `NET::ERR_CERT_AUTHORITY_INVALID`.
2. A manual warning exception was used only to reach the dummy login and
   authenticated certificate downloads. No global certificate-error flag was
   used.
3. The downloaded public root was installed through Android Settings →
   Security & privacy → More security & privacy → Encryption & credentials →
   Install a certificate → CA certificate.
4. Both the main onion and the previously unvisited `demo` prefix returned
   authenticated content. Chrome's native panel said **Connection is secure**
   and identified the Torkitten root. Browser restart and Android reboot
   retained trust.
5. Removing the CA and restarting Chrome restored the original certificate
   error. Reinstalling the CA restored trust. This distinguishes actual trust
   from the earlier manual exception.

## Firefox: two separate configuration requirements

### Onion transport

Firefox passed `check.torproject.org` over Orbot's full-device VPN, but the dummy
onion showed **Address Not Found**. Read-only inspection of the running browser
confirmed `network.dns.blockDotOnion=true`, `network.proxy.type=5`, and
`network.trr.mode=0`.

The [Firefox 155.0.1 DNS implementation](https://github.com/mozilla-firefox/firefox/blob/fb95137a04eb8fe1196cb12f26b100c1e060295c/netwerk/dns/nsDNSService2.cpp#L973-L980)
explicitly returns `NS_ERROR_UNKNOWN_HOST` for `.onion` when that guard is set.
[Orbot's issue discussion](https://github.com/guardianproject/orbot-android/issues/693#issuecomment-1152472827)
describes the same protection and warns about leaking onion names if it is
simply disabled outside Tor.

The successful configuration retained that guard and used explicit SOCKS5:

1. Install [FoxyProxy Standard](https://addons.mozilla.org/en-US/firefox/addon/foxyproxy-standard/)
   from Mozilla Add-ons. This adds a third-party browser dependency; it is not
   an out-of-the-box Firefox result.
2. In its Options → Proxies, add the built-in **TOR** preset:
   SOCKS5, `127.0.0.1`, port `9050`, **Proxy DNS enabled**.
3. Save and select that proxy. It connects only to Orbot on the Android device;
   no commercial or external proxy account is involved.
4. Keep Orbot connected. The final lab configuration uses full-device VPN,
   with Android's Wi-Fi proxy restored to None and Orbot Power User Mode off.

A separate trial with Android's Wi-Fi HTTP proxy pointed at Orbot's port 8118
still produced Address Not Found in Firefox. That configuration is not a proven
alternative and was removed.

### CA trust

With SOCKS configured, Firefox reached TLS and showed **Secure Connection
Failed**, with an explanation that the certificate issuer was unknown. Its
`security.enterprise_roots.enabled` preference was false, despite the root
already being present in Android's user trust store.

The successful browser-owned opt-in was:

1. Firefox Settings → About Firefox; tap the Firefox logo seven times to expose
   its additional settings.
2. Settings → Secret Settings → **Use third party CA certificates**.
3. Enable only that option and restart Firefox.

This option imports trust from Android's CA store; it does not suppress TLS
validation. The [Mozilla issue discussion](https://github.com/mozilla-mobile/fenix/issues/16993#issuecomment-1003431684)
documents this workflow. The tested browser then reported
`security.enterprise_roots.enabled=true`; `network.dns.blockDotOnion` remained
true and `security.nocertdb` remained false. No Firefox certificate exception
was accepted, no TLS/privacy bypass flags were used, and no browser APK or
extension code was patched.

## Firefox end-to-end observations

- Password plus TOTP login reached the authenticated launcher.
- The application prefix opened without another login; both pages returned
  HTTP 200 over HTTP/2 in secure contexts.
- Firefox's native site panel said **Secure connection — Verified by Torkitten
  Local CA - 2026 ECC Root** for both hostnames.
- Its native certificate viewer supplied the actual main-host leaf; that leaf
  verified against the downloaded root and exact hostname.
- Clearing the dummy site's cookies redirected an application request to the
  protected login flow, without displaying the application. Password/TOTP
  login worked again.
- Removing the Android CA and restarting Firefox restored the issuer warning,
  even with the CA-store opt-in still enabled. Reinstalling it restored secure
  access and the retained session.
- Firefox downloaded the public root and generated Apple profile. Their root
  bytes matched each other, Chrome's downloads, and the live Caddy public root.

**Cold-start limitation:** the first onion navigation after some Firefox cold
starts returned Address Not Found before the proxy extension was ready. One
ordinary **Try Again** then restored secure authenticated access. This is not a
certificate exception, but it means this combination is not yet a seamless,
out-of-the-box supported client. Do not omit the retry from restart evidence.

## Stock Tor Browser for Android follow-up

Tor Browser 15.0.21's official x86_64 APK was verified against the Tor Browser
Developers signing key before installation. It crashed during Gecko startup on
the original 16 KiB-page image. The original AVD was preserved; a separate,
visible Android 17 Google Play 37.0 revision 6 device with 4 KiB pages launched
the same unmodified APK successfully. No Orbot or proxy extension was installed
on that second device: Tor Browser used its own Tor client.

- Tor's public connection check succeeded.
- The private dummy onion returned **Unable to connect**, without a usable
  client-authorization key prompt/import flow. Native Tor logs reported failure
  to decrypt the descriptor because client authorization was likely required.
  The [upstream discussion](https://forum.torproject.org/t/how-to-access-hidden-service-with-client-auth-restricted-discovery-on-android/15024)
  identifies the Android client-authentication limitation. Orbot's imported
  credential does not automatically transfer to Tor Browser's separate Tor.
- Read-only runtime inspection showed `security.enterprise_roots.enabled=false`
  and `security.nocertdb=true`. Those settings were not changed; this was not a
  live user-CA import/removal control for Tor Browser.
- On the separate public `self-signed.badssl.com` test, the normal **Advanced →
  Accept the Risk and Continue** action loaded the HTTPS page with HTTP 200.
  No credentials were submitted. This is a permitted manual exception, not
  trusted-root validation or evidence that Torkitten became accessible.

The private service was blocked **before TLS**, so its authentication, root
trust, and application access did not pass in stock Android Tor Browser. No
certificate/privacy preference was weakened; only standard USB debugging was
enabled for inspection. Exception persistence after restart was not tested.
Both AVDs were retained, and Orbot was restored on the original device.

## Certificate and evidence boundaries

The lab root is ECDSA P-256. Its separate main-host and wildcard leaves are
signed directly by that root, have critical DNS SANs and empty subjects, and
have a 397-day validity interval. These unchanged certificates were accepted
by the tested native Chrome and configured Firefox. No PKI change was needed
for this experiment.

Public-root DER SHA-256:

```text
7918e477c1b34899f8f1dd8e554889a2c96a8a28ccd86463a39c417f116ea2d9
```

Reports, native UI screenshots, downloaded public certificates/profiles, and
reusable lab tooling are outside Git under
`$TORKITTEN_BUILD_ROOT/android-trust-lab/`. Deliberately retained dummy
credentials are separately labeled and permission-restricted under its
`private/` directory. Never copy that directory or emulator state into Git or
public evidence.

These results do **not** explain the reported Safari warning after Apple Full
Trust, validate the user's separate CA/served chain, test profile installation
on iOS, or establish physical Android device compatibility. Those require
separate device and certificate evidence. An Apple profile's public root
matching the PEM is not itself proof that Safari trusts it.
