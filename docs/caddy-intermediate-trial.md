# Revertible Caddy intermediate-signing trial

## Purpose and checkpoint

The owner requested an isolated trial of the other native Caddy signing mode
for the reported iOS trust failure. The prior work was committed and pushed as
`d8861e2` before this change. The trial is separate on
`trial/caddy-intermediate-ca`; it is **not** a demonstrated Safari/Chrome fix.

Only the generated certificate-authority/issuer configuration changes in
production Go. There are no changes to routing, authentication, cookies,
onboarding/profile generation, Tor authorization, component versions, or UI.
Historical Android and Apple investigation reports describe the preceding
**direct-root** configuration, not this new trial.

## Configuration

The prior chain was `root → leaf`. The trial is `root → intermediate → leaf`:

```caddyfile
pki {
    ca local {
        name "Torkitten Local CA"
        intermediate_lifetime 17520h
    }
}
cert_issuer internal {
    lifetime 9528h
}
```

There is no `sign_with_root` option. The website leaves retain the requested
397-day lifetime. The native intermediate lifetime is 730 days so it can sign
those leaves without Caddy clamping them to its default seven-day intermediate
expiry. Caddy owns intermediate and leaf generation/renewal. Its native
remaining-issuer-lifetime bounds still apply; Torkitten adds no certificate
signing or renewal code.

The root is **not rotated**. Its public download and the root embedded in the
Apple profile remain the same certificate. The intermediate travels with the
website's TLS chain; it is not a replacement trust anchor for users to install.
A fresh profile download is available from the same authenticated launcher,
but re-downloading it does not create a new CA or itself prove an iOS fix.

## Why existing Caddy state requires a controlled transition

The pinned issuer uses the same `local` storage namespace for both modes.
Changing configuration alone does not immediately replace a still-valid cached
direct-root leaf. Likewise, a stored seven-day intermediate is not automatically
reissued as a two-year certificate just because its configured lifetime changes.

The real-Caddy transition test demonstrates both behaviors and the offline
procedure:

1. Preserve the persistent root and all product state.
2. Stop the component before staging any native files.
3. Retain the old `certificates/local` leaf cache and the old
   `pki/authorities/local/intermediate.crt` / `intermediate.key` in restricted
   rollback storage, outside the candidate's active Caddy storage namespace.
4. Start Caddy with the new generated policy. **Caddy itself** generates the new
   intermediate and leaves using the retained root.
5. Verify a three-certificate trust path, correct hostnames, the requested
   lifetimes, and the unchanged public-root bytes.

Never remove or replace `pki/authorities/local/root.crt` or `root.key`. Never
manually generate/sign a substitute intermediate or leaf. Private state and
cached private leaf/intermediate keys are not Git artifacts or public evidence.

## Operator rollout and rollback boundaries

This is a specifically authorized, one-off owner operation, not a new supported
container-replacement persistence feature. Removing a container still destroys
its ordinary writable layer. Before replacement, make a stopped, permission-
preserving copy of the complete `/var/lib/torkitten` tree and verify its contents,
ownership, and modes against the staged candidate before first boot.

Build a complete image rather than patching binaries in a retained writable
layer. Keep the old image/container and the restricted backup. Never run two
copies of the same onion identity simultaneously. Keep publication bound to the
same localhost administration port with the original rootless networking and
security restrictions.

A container restart preserves durable credentials, TOTP, mappings, devices,
local-session hashes, and agent-token hashes, but clears Authelia's memory-backed
onion sessions. Remote clients must log in again. No Tor credential or root-CA
re-enrollment is required merely because the signer chain changed.

A later rollback must preserve **current** durable product/security state,
including any intervening revocations; do not blindly resurrect the pre-trial
snapshot. Copy the stopped current state into a candidate using the previous
image, stage only the leaf cache so Caddy issues direct-root leaves again, and
verify the unchanged root and current product state. The new intermediate can
remain stored because direct-root issuance does not use it.

Deployment-specific image IDs, private backup locations, verification results,
and the operator switch/rollback helper belong outside Git under
`$TORKITTEN_BUILD_ROOT`. The rootless container owning the user's existing
service must remain separately recoverable if any check fails.

## Automated evidence

`TestPinnedCaddyTLSAndForwardAuth` now validates TLS using only the public root,
checks the intermediate trust path and lifetimes, and verifies that Caddy restart
retains the root/leaf. Existing authorization, protected-root download, unknown
HTTP route denial, and rejected-load retention checks still run.

`TestPinnedCaddyIssuerTransitionAndRollback` uses real pinned Caddy to verify:

- direct-root leaves remain cached after merely switching configuration;
- staging the intermediate/leaf cache yields the intended intermediate chain;
- the root and 397-day leaf lifetime remain unchanged; and
- reverting issuance with the current CA state returns to a valid direct-root
  chain without replacing the trust anchor.

These tests are not native iOS validation. The owner's Safari and Chrome result
on the updated service remains the deciding compatibility observation.
