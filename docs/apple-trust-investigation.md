# Apple profile and certificate investigation — 2026-09-05

## Status and scope

The owner reports the newest iOS version, an installed Torkitten root profile,
and explicitly enabled Full Trust. Safari shows **Not Secure** while certificate
details show a valid certificate; Chrome reports **ERR_CERT_AUTHORITY_INVALID**.
**That failure remains unresolved.** The Chrome error points to issuer/chain
trust; a certificate viewer's validity field alone does not prove trusted server
identity. Do not repeat the trust-toggle instructions or assume an outdated OS.

This investigation compares Apple's documentation and published trust-policy
source with the actual packaged launcher and the running user service's public
certificates. It is not an iOS execution test. The Android experiment used a
separate dummy instance: matching PEM/profile bytes within that instance does
not prove that the owner's phone has the current user instance's root.

No runtime code, certificate policy, identity, CA, credentials, sessions,
publication settings, container, or running component was changed or restarted.
Public certificates, public launcher JavaScript, bounded running Caddy
configuration, and narrow process metadata were read from the user container.
Only selected public diagnostic fields were recorded, not the complete Caddy
configuration. No private key or product state file was read.

## Apple's profile example

Apple publishes a complete [CertificateRoot profile example](https://developer.apple.com/documentation/devicemanagement/certificateroot)
([plain-text version](https://developer.apple.com/documentation/devicemanagement/certificateroot.md)).
It uses the same structure as `runtime/launcher/app.js`:

- a top-level `PayloadType` of `Configuration`, version 1;
- a `PayloadContent` array containing a root-certificate payload;
- payload type `com.apple.security.root`, version 1;
- DER certificate bytes represented by a plist `<data>` element; and
- separate profile and payload identifiers and UUIDs.

Apple explicitly permits manual installation without supervision or MDM. The
example is an XML plist, not a mandatory signed CMS envelope. Adding a profile
signature is not a substitute for trust in the HTTPS issuer. Apple's
[manual-trust documentation](https://support.apple.com/en-us/102390) explains the
additional SSL/TLS trust approval, which the owner reports already completing.

The **unmodified JavaScript from the running image** was executed with its
current public root as input, both with native `crypto.randomUUID` and with the
existing fallback. Both generated profiles:

- parsed as plists;
- matched the fields and value types in Apple's example;
- contained exactly one root payload with distinct valid UUIDs; and
- contained DER bytes identical to the root returned by that running Caddy's
  private PKI API.

A follow-up also extracted the public root body from the **actual running
protected-download route**, without bypassing HTTP authorization. Its DER bytes
matched both the private PKI response and all three comparison profiles. This
rules out a stale embedded download root in the configuration inspected; it is
not merely an assumption that the launcher downloads the current PKI root.

A separate comparison profile was assembled using Apple's example-shaped plist
and the same public root. Neither it nor the current generated profile was
installed on an Apple device during this investigation. The particular file
already installed on the owner's phone has not been obtained or compared.

## Public certificates from the actual running service

Read-only TLS handshakes to Caddy's private listener captured both the base-host
leaf and the wildcard leaf selected for a prefixed hostname. These are not just
certificates inferred from the current rendering code or the Android fixture.

| Check | Observation |
| --- | --- |
| Signature algorithm | ECDSA with SHA-256 |
| Root and leaf key | P-256, 256 bits |
| Root constraints | Critical CA true, path length 1, certificate-signing usage |
| Leaf usage | Digital signature; `id-kp-serverAuth` EKU present |
| Names | Exact base DNS SAN; separate single-label wildcard DNS SAN |
| Empty leaf subject | SAN extension is critical |
| Leaf validity interval | 397 days |
| Served chains | Leaf plus the same public root; direct-root signing, no intermediate dependency |
| Ordinary chain/hostname verification | Passed against the live public root |
| Runtime internal issuer | `sign_with_root: true`, not merely present in source |
| TLS selection overrides | No `default_sni`, `fallback_sni`, or custom certificate selection |
| Wrong-name probes | Unrelated SNI, IP-address-style request, and absent SNI all rejected the TLS handshake |

The quoted Caddy intermediate-chain workaround is therefore **already active**.
The expected leaf issuer here is the current **root**, not Caddy's intermediate.
Caddy's pinned [internal issuer documentation in source](https://github.com/caddyserver/caddy/blob/89190a02601c918d8de199c16a9d7d778ba204fa/modules/caddytls/internalissuer.go#L49-L53)
describes that option. Adding another issuer declaration would not fix an
intermediate-chain problem in these observed direct-root chains.

The selection probes were local Unix-socket TLS handshakes, not captures of the
phone's ClientHello. Python suppresses SNI for an IP literal, like an ordinary
IP-address browser request; the IP probe did not force a literal-IP SNI value.
A wildcard can still cover unconfigured prefixes of the same service; these
checks do not claim that every unconfigured hostname fails at TLS rather than
at the separate HTTP authorization/routing boundary.

Apple's [trusted-certificate requirements](https://support.apple.com/en-us/103769)
require SHA-2 signatures, DNS names in SAN, server-authentication EKU, and a
maximum 825-day leaf validity interval for the stated policy. The current
certificates meet those listed conditions. The [398-day policy](https://support.apple.com/en-us/102028)
explicitly excludes certificates from user-added or administrator-added roots;
it is not a ten-year-root prohibition. Our leaves are 397 days regardless.

Apple's published Security source was inspected at commit
`db15acbe6a7f257a859ad9a3bb86097bfe0679d9`:

- [`SecPolicyCheckCertNonEmptySubject`](https://github.com/apple-oss-distributions/Security/blob/db15acbe6a7f257a859ad9a3bb86097bfe0679d9/OSX/sec/Security/SecPolicyLeafCallbacks.c#L161-L178)
  explicitly permits an empty non-CA subject with a critical SAN. Therefore,
  absence of a leaf Common Name is not itself a demonstrated Apple defect.
- [`SecPolicyCheckCertSSLHostname`](https://github.com/apple-oss-distributions/Security/blob/db15acbe6a7f257a859ad9a3bb86097bfe0679d9/OSX/sec/Security/SecPolicyLeafCallbacks.c#L296-L319)
  checks DNS SANs. A wildcard-specific rejection would not explain a failure
  of the separately issued exact base-host certificate.
- [`SecPolicyAddStrongKeySizeOptions`](https://github.com/apple-oss-distributions/Security/blob/db15acbe6a7f257a859ad9a3bb86097bfe0679d9/OSX/sec/Security/SecPolicy.c#L1400-L1413)
  sets a 256-bit minimum for EC keys.

Source inspection and ordinary TLS validation are **not** execution of the
phone's particular Apple trust implementation. These checks narrow the search;
they do not establish Safari compatibility or exclude an implementation bug.

## A closely matching report

A [Caddy Community report](https://caddy.community/t/how-to-get-iphone-to-trust-caddy-root-crt/26318)
from November 2024 describes an installed, trusted Caddy root with continuing
Safari/iPhone certificate failures, including `-1202` and `-9807`. The reporter
said that updating iOS made the unchanged certificate work. The exact resolving
iOS version is not supplied in the thread.

This demonstrates that the symptom is not unique to Torkitten and need not be a
malformed profile. It does **not** prove that the owner's failure has the same
cause or that an update will fix it. Do not prescribe random PKI changes or
attribute the problem to iOS without the device evidence.

## Evidence needed to distinguish the remaining causes

These are diagnostic evidence requirements, not instructions for the owner to
edit or export an installed iPhone certificate. A reliable current-iOS
fingerprint-viewing procedure has not been verified. Do not send the owner on
an unsupported fingerprint hunt. If the original public-only download is not
available, a deliberate fresh-profile comparison is preferable, with the
owner's approval and without implying that reinstallation is a proven fix.

1. Compare the root in the **Torkitten profile actually installed on the phone**
   with the running instance's root by DER SHA-256, not its display name.
   Different containers' roots can have the same display name. Server-side
   configuration and download checks cannot observe the phone's trust store.
2. Compare the certificate Safari received, including issuer, SAN, dates and
   fingerprint, with the corresponding captured live leaf. An intermediate
   issuer on the phone would differ from the currently observed direct-root
   leaf. If both root and leaf fingerprints match, investigate native Apple
   trust evaluation and retained browser decisions rather than continuing to
   assume a wrong Caddy root or hostname selection.
3. If necessary, perform a deliberate on-device comparison with the
   Apple-example-shaped public-root-only profile, without rotating the CA or
   modifying server security policy. Record the actual browser outcome and
   exact OS build for any reproducible platform-specific failure.

The Torkitten `.mobileconfig` contains public root material and can be supplied
for that comparison. Never request or include an `.auth_private` file, Tor key
QR, password, TOTP seed, cookie, or unrelated device-management profile in these
reports.

Public captures, source references, comparison profiles, and the executable
profile-generator diagnostic are kept outside Git under
`$TORKITTEN_BUILD_ROOT/evidence/apple-trust-investigation/`. The comparison files
are diagnostic artifacts, not a replacement runtime release or a verified iOS
fix. No Apple compatibility claim or speculative PKI change is justified yet.
