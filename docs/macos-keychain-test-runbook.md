# macOS keychain-access-group test runbook (Phase 2)

This is the exact VM sequence to PROVE the keychain-access-group wrapper works on a
signed build: the app and the gateway share a team-scoped keychain access group
(`V4YZPC7T6G.com.tsout.conduit.shared`), so the gateway reads secrets the app wrote
into the data-protection keychain with NO password prompt, across app updates,
while a non-team copy is denied.

Run everything on the Mac (VM) with the signing identity and both provisioning
profiles installed. None of the steps below can be exercised on Windows or Linux:
`codesign`, the data-protection keychain, and the access-group entitlement are
macOS-only.

## Prerequisites (on the Mac VM)

- The Developer ID Application identity is in the login keychain:
  ```
  security find-identity -v -p codesigning | grep 'Brandon SOuth (V4YZPC7T6G)'
  ```
- Both provisioning profiles are present (downloaded earlier):
  - `~/Downloads/Conduit_Developer_ID.provisionprofile` (app)
  - `~/Downloads/Conduit_Gateway_Developer_ID.provisionprofile` (gateway)
- Rust toolchain + Node + the Tauri CLI are installed (you build from source).

## (a) Build the bundle

From the repo root:

```
npx tauri build --config src-tauri/tauri.bundle.conf.json
```

This produces `src-tauri/target/release/bundle/macos/Toolport.app` with the bare
gateway at `Toolport.app/Contents/MacOS/toolport-gateway`.

## (b) Sign + package (wrap the gateway as a nested .app)

```
./scripts/macos-sign-local.sh
```

Defaults: APP = `src-tauri/target/release/bundle/macos/Toolport.app`, IDENTITY =
`Developer ID Application: Brandon SOuth (V4YZPC7T6G)`, profiles from `~/Downloads`.
Override positionally or via env if needed:

```
APP=/path/to/Toolport.app ./scripts/macos-sign-local.sh
```

The script:

- moves the gateway into `Toolport.app/Contents/Helpers/ToolportGateway.app`,
- embeds the gateway provisioning profile there,
- leaves a symlink at the old bare path for backward compat,
- signs inside-out and prints the `keychain-access-groups` entitlement plus each
  embedded profile's `ExpirationDate` (confirm it reads ~2044).

It is idempotent: re-running rebuilds the helper bundle and re-signs.

Confirm the layout:

```
ls -l "src-tauri/target/release/bundle/macos/Toolport.app/Contents/MacOS/toolport-gateway"
# -> a symlink: toolport-gateway -> ../Helpers/ToolportGateway.app/Contents/MacOS/toolport-gateway

file "src-tauri/target/release/bundle/macos/Toolport.app/Contents/Helpers/ToolportGateway.app/Contents/MacOS/toolport-gateway"
# -> Mach-O ... (the real binary)
```

## (c) Launch the app and write a secret to the keychain

Launch the signed app (Gatekeeper should accept it since it is Developer ID +
hardened runtime):

```
open "src-tauri/target/release/bundle/macos/Toolport.app"
```

In the app, add an MCP server that has a secret (an API key). Saving it writes the
secret into the data-protection keychain under the shared access group. Note the
exact secret value you entered so you can compare later, and note the keychain
service/account the app uses for that secret (visible in `Keychain Access` or via
`security` if you know the service name).

## (d) Prove the gateway reads the secret with NO prompt

The gateway reads that secret when spawned as a client would spawn it. Run the
nested gateway binary directly. Because the binary is signed with the gateway
entitlements + embedded profile that authorize the same access group, the read
must succeed silently (no keychain password dialog).

```
GW="src-tauri/target/release/bundle/macos/Toolport.app/Contents/Helpers/ToolportGateway.app/Contents/MacOS/toolport-gateway"

# Spawn it the way a client does (stdio MCP). Either point a real client at it,
# or drive a quick MCP handshake. The point is that the gateway resolves the
# server's secret from the keychain to connect to that server.
"$GW" --help    # sanity: it runs
```

To exercise the actual secret read, start the gateway so it proxies the server you
configured in step (c) (it resolves that server's API key from the shared keychain
group), then issue a tool call that requires the key. Watch for:

- NO keychain "toolport-gateway wants to use your confidential information" prompt.
- The proxied call succeeds (the gateway found and used the secret).

You can also confirm the value round-trips with `security` IF you know the service
name (replace `SERVICE` and `ACCOUNT`):

```
security find-generic-password -s 'SERVICE' -a 'ACCOUNT' -w
# prints the secret value you entered in step (c), no prompt
```

Repeat the same `security` read after also spawning the gateway to confirm both the
app-written and gateway-read paths agree.

Expected result: the value reads back and there is NO password prompt. This is the
core proof that the shared access group works on a signed build.

## (e) Update test: re-sign, still no prompt

Simulate an app update (new signature, same team). Re-run the sign script, which
produces a fresh signature over the same identity/team:

```
./scripts/macos-sign-local.sh
```

Relaunch the app and re-spawn the gateway, then repeat step (d). The keychain item
is bound to the access group (team-scoped), not to a specific code signature, so:

- The gateway STILL reads the secret with NO prompt.

If a prompt appears here, the access group is not being honored across the new
signature (regression).

## (f) Denial test: a non-team / ad-hoc-signed copy is rejected

Prove that a binary WITHOUT the team's access-group entitlement cannot read the
secret. Copy the gateway out and re-sign it ad-hoc (no entitlements, no team):

```
cp "$GW" /tmp/toolport-gateway-adhoc
codesign --force -s - /tmp/toolport-gateway-adhoc   # ad-hoc, strips entitlements
codesign -d --entitlements - /tmp/toolport-gateway-adhoc 2>&1 | grep -i keychain || echo "no keychain-access-groups (expected)"

# Now try to read the same secret with the ad-hoc binary's identity.
/tmp/toolport-gateway-adhoc ...   # attempt the same secret-backed proxied call
```

Expected result: the read is DENIED. You should see either:

- `errSecMissingEntitlement` / OSStatus `-34018`, or
- a keychain password prompt (the system refuses silent access without the group).

A clean way to see the raw status is with the same `security` call run under the
ad-hoc binary's context, or by observing the gateway log the keychain error. The
key point: the ad-hoc copy must NOT silently read the secret, while the
properly-signed nested gateway (steps d and e) must.

## What this proves

- The app and the nested, profile-bearing gateway share one team-scoped keychain
  access group, so the gateway reads app-written secrets with no prompt.
- That holds across a re-sign (app update).
- A binary lacking the entitlement is denied, so the access group is doing real
  work (not just "any local process can read it").
