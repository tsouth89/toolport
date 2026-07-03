# Signing installers

This covers Windows (SmartScreen) and macOS (Gatekeeper/notarization).

# Windows installer

Unsigned installers trigger a Windows SmartScreen warning ("Windows protected
your PC"). Removing it requires an **authenticode code-signing certificate** from
a trusted CA. There is no free way to make SmartScreen trust an installer; a
self-signed certificate does not help end users.

## Options

| Option                                       | Cost               | Notes                                                                                                                                                                                                                                                                                                                                                                                           |
| -------------------------------------------- | ------------------ | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Azure Trusted Signing**                    | ~$10/month         | Cheapest real option. Cloud-based, no cert file to manage. Requires an Azure account and identity verification; orgs need 3+ years of history (individuals are eligible). Chains to a Microsoft-operated trusted root and shows your validated publisher name. It is **standard, not EV**, signing, so SmartScreen reputation still accrues with downloads and an early install may still warn. |
| **OV certificate** (Sectigo, DigiCert, etc.) | ~$100 to $400/year | Standard cert. SmartScreen reputation builds over time/downloads, so early downloads may still warn briefly. Usually requires a hardware token (or cloud HSM) now.                                                                                                                                                                                                                              |
| **EV certificate**                           | ~$300 to $600/year | Instant SmartScreen reputation, no warning from day one. Hardware token required.                                                                                                                                                                                                                                                                                                               |
| **Ship unsigned (interim)**                  | free               | Fine for an early beta. Users click "More info → Run anyway". Document the bypass in release notes.                                                                                                                                                                                                                                                                                             |

For a pre-launch beta with no budget, shipping unsigned and documenting the
bypass is the pragmatic choice. Reputation also accrues as more people run it.

## Wiring it up (once you have a cert)

Tauri signs during `tauri build` when Windows signing is configured.

**Installed cert (thumbprint):** add to `src-tauri/tauri.conf.json` under
`bundle`:

```json
"windows": {
  "certificateThumbprint": "YOUR_CERT_THUMBPRINT",
  "digestAlgorithm": "sha256",
  "timestampUrl": "http://timestamp.digicert.com"
}
```

**Azure Trusted Signing (or any custom signer):** use a sign command instead
(Tauri 2.1+):

```json
"windows": {
  "signCommand": "trusted-signing-cli -e <endpoint> -a <account> -c <profile> %1"
}
```

Get an installed cert's thumbprint with:

```powershell
Get-ChildItem Cert:\CurrentUser\My | Format-List Subject, Thumbprint
```

## Azure Trusted Signing in this repo's CI (the live setup)

The release workflow (`.github/workflows/release.yml`) already wires this up, and
stays **inert until the secrets exist** (the signing step is gated on
`AZURE_CLIENT_ID`, so an earlier-tagged release just builds unsigned). It installs
`trusted-signing-cli`, writes a `signCommand` config, and Tauri signs the app exe,
the bundled gateway sidecar, and the NSIS installer during the build (before the
updater `.sig` is computed, so auto-update keeps working).

**One-time Azure setup:**

1. Create an **Artifact Signing (Trusted Signing) account** + complete **Individual**
   identity validation, then create a **Public Trust certificate profile**. Note the
   account name, the certificate profile name, and the account's endpoint URI (e.g.
   `https://eus.codesigning.azure.net` for East US).
2. Create a **service principal** for CI (Entra ID → App registrations → new
   registration → add a client secret).
3. On the signing **account → Access control (IAM)**, assign that app the
   **"Trusted Signing Certificate Profile Signer"** role (this is the _signer_ role,
   distinct from the _Identity Verifier_ role you assign to yourself).

**GitHub secrets to add** (Settings → Secrets and variables → Actions → Secrets):

| Secret                | Value                                          |
| --------------------- | ---------------------------------------------- |
| `AZURE_TENANT_ID`     | the app registration's Directory (tenant) ID   |
| `AZURE_CLIENT_ID`     | the app registration's Application (client) ID |
| `AZURE_CLIENT_SECRET` | the client secret value                        |

**GitHub variables to add** (same page → Variables tab):

| Variable                 | Value                                                     |
| ------------------------ | --------------------------------------------------------- |
| `AZURE_SIGNING_PROFILE`  | your certificate profile name (**required**)              |
| `AZURE_SIGNING_ENDPOINT` | optional, defaults to `https://eus.codesigning.azure.net` |
| `AZURE_SIGNING_ACCOUNT`  | optional, defaults to `southforgesigning`                 |

With those set, the next `v*` tag produces a **signed** Windows installer. SmartScreen
reputation still accrues with downloads, but the "unknown publisher" warning is gone
and the publisher shows your validated name. Until the secrets are set, Windows ships
unsigned and the bypass note below applies.

## SmartScreen bypass (for the unsigned beta)

Include this in release notes so users aren't scared off:

> Windows may show "Windows protected your PC" because the installer isn't code
> signed yet. Click **More info → Run anyway** to continue. Signing is coming.

# macOS (signing + notarization)

An unsigned `.dmg` triggers Gatekeeper ("Toolport is damaged and can't be
opened"). To ship a clean install, sign with a **Developer ID Application**
certificate and notarize with Apple. One **Apple Developer Program** membership
($99/yr) covers this, the same account used for iOS works; you just create the
Developer ID cert (not an iOS distribution cert).

## What to generate (once)

1. **Developer ID Application certificate**
   - Easiest via Xcode: **Settings → Accounts → (your team) → Manage
     Certificates → + → Developer ID Application**.
   - Then in **Keychain Access**, find that cert, expand it to include its private
     key, right-click → **Export** as a `.p12` with a password.
2. **Team ID**: developer.apple.com → **Membership** (10-character code).
3. **App-specific password** for notarization: appleid.apple.com → **Sign-In and
   Security → App-Specific Passwords → +** (label it e.g. "conduit notarization").

## GitHub Actions secrets to add

The release workflow already passes these env vars to the macOS build; set them as
repository secrets (Settings → Secrets and variables → Actions):

| Secret                       | Value                                                                              |
| ---------------------------- | ---------------------------------------------------------------------------------- |
| `APPLE_CERTIFICATE`          | base64 of the `.p12`: `base64 -i cert.p12 \| pbcopy`                               |
| `APPLE_CERTIFICATE_PASSWORD` | the password you set when exporting the `.p12`                                     |
| `APPLE_SIGNING_IDENTITY`     | `Developer ID Application: Your Name (TEAMID)` (exact string from Keychain Access) |
| `APPLE_ID`                   | your Apple ID email                                                                |
| `APPLE_PASSWORD`             | the app-specific password from step 3                                              |
| `APPLE_TEAM_ID`              | the 10-char Team ID                                                                |

With those set, a tagged build produces a **signed, notarized** `.dmg`, no
Gatekeeper warning. Without them, the macOS build is simply unsigned (and users
fall back to the right-click → Open workaround in the README).

## Gotcha: the bundled gateway must be signed too

Notarization rejects any unsigned executable in the bundle, including the
`toolport-gateway` sidecar. Tauri signs bundled binaries during `tauri build` when
signing is configured, so this should be automatic. If the first notarization run
fails citing an unsigned binary, that's the gateway, we'll add an explicit sign
step for it in the workflow.

## Gatekeeper bypass (for an unsigned interim build)

> macOS may say Toolport "is damaged and can't be opened" because the app isn't
> notarized yet. Right-click the app and choose **Open**, or run
> `xattr -dr com.apple.quarantine /Applications/Toolport.app`. Notarization is
> coming.
