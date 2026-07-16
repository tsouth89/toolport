#!/usr/bin/env bash
#
# macos-package-ci.sh
#
# CI macOS sign + notarize + package for the keychain-access-group nested-gateway
# build. Runs on a GitHub macOS runner AFTER `tauri build` has produced an
# (unsigned) Toolport.app. It does everything Tauri's built-in macOS signing
# cannot: nest the gateway in its own .app, embed provisioning profiles, sign
# inside-out, notarize, and regenerate the .dmg + updater artifact over the
# re-signed app.
#
# Why we re-do packaging instead of letting Tauri sign: Tauri signs the app, then
# builds the .dmg and the updater `.app.tar.gz` (+ Ed25519 `.sig`) from that signed
# app. Our nested-gateway + profile signing changes the app bundle, which would
# invalidate Tauri's signature, dmg, and updater sig. So we build the app UNSIGNED
# with Tauri and own the whole sign/notarize/package tail here.
#
# Required env:
#   APP                         path to the built Toolport.app
#   TARGET                      rust target triple (e.g. x86_64-apple-darwin); used for artifact names
#   APPLE_CERTIFICATE           base64 of the "Developer ID Application" .p12
#   APPLE_CERTIFICATE_PASSWORD  password for that .p12
#   APPLE_SIGNING_IDENTITY      e.g. "Developer ID Application: Brandon SOuth (V4YZPC7T6G)"
#   APPLE_PROVISIONING_PROFILE_APP      base64 of the app .provisionprofile
#   APPLE_PROVISIONING_PROFILE_GATEWAY  base64 of the gateway .provisionprofile
#   APPLE_ID, APPLE_PASSWORD, APPLE_TEAM_ID            notarization credentials
#   TAURI_SIGNING_PRIVATE_KEY, TAURI_SIGNING_PRIVATE_KEY_PASSWORD   updater key (for .sig regen)
#   RUNNER_TEMP                 provided by GitHub Actions (a writable temp dir)
#
# This MUST run on macOS. It is intended for CI; for local testing use
# scripts/macos-sign-local.sh directly (it skips the cert import + notarize).

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

log()  { printf '\033[1m%s\033[0m\n' "== $* =="; }
die()  { printf '\033[31mERROR: %s\033[0m\n' "$*" >&2; exit 1; }

[[ "$(uname -s)" == "Darwin" ]] || die "macos-package-ci.sh must run on macOS"

: "${APP:?APP (path to Toolport.app) is required}"
: "${TARGET:?TARGET (rust target triple) is required}"
: "${APPLE_CERTIFICATE:?APPLE_CERTIFICATE is required}"
: "${APPLE_CERTIFICATE_PASSWORD:?APPLE_CERTIFICATE_PASSWORD is required}"
: "${APPLE_SIGNING_IDENTITY:?APPLE_SIGNING_IDENTITY is required}"
: "${APPLE_PROVISIONING_PROFILE_APP:?APPLE_PROVISIONING_PROFILE_APP is required}"
: "${APPLE_PROVISIONING_PROFILE_GATEWAY:?APPLE_PROVISIONING_PROFILE_GATEWAY is required}"
: "${APPLE_ID:?APPLE_ID is required}"
: "${APPLE_PASSWORD:?APPLE_PASSWORD is required}"
: "${APPLE_TEAM_ID:?APPLE_TEAM_ID is required}"
: "${RUNNER_TEMP:=$(mktemp -d)}"

[[ -d "$APP" ]] || die "App bundle not found: $APP (did 'tauri build' run for $TARGET?)"

WORK="$RUNNER_TEMP/toolport-sign"
mkdir -p "$WORK"
APP_PROFILE="$WORK/app.provisionprofile"
GW_PROFILE="$WORK/gateway.provisionprofile"
CERT_P12="$WORK/cert.p12"
KEYCHAIN="$WORK/toolport-signing.keychain-db"
KEYCHAIN_PASSWORD="ci-$(date +%s)-$$"

# Restore the user's keychain search list and remove our temp keychain on exit,
# so a failure can't leave the runner's signing state polluted (matters less on an
# ephemeral runner, but keeps local re-runs clean too).
cleanup() {
  security delete-keychain "$KEYCHAIN" >/dev/null 2>&1 || true
}
trap cleanup EXIT

# ---------------------------------------------------------------------------
# 1. Import the Developer ID cert into a temporary keychain.
# ---------------------------------------------------------------------------
log "Importing signing certificate into a temporary keychain"
echo "$APPLE_CERTIFICATE" | base64 --decode > "$CERT_P12"
security create-keychain -p "$KEYCHAIN_PASSWORD" "$KEYCHAIN"
# Keep it unlocked for the whole job (6h) so notarytool/codesign never re-prompt.
security set-keychain-settings -lut 21600 "$KEYCHAIN"
security unlock-keychain -p "$KEYCHAIN_PASSWORD" "$KEYCHAIN"
security import "$CERT_P12" -k "$KEYCHAIN" -P "$APPLE_CERTIFICATE_PASSWORD" \
  -T /usr/bin/codesign -T /usr/bin/security
# Allow codesign to use the key without an interactive prompt.
security set-key-partition-list -S apple-tool:,apple:,codesign: \
  -s -k "$KEYCHAIN_PASSWORD" "$KEYCHAIN" >/dev/null
# Put our keychain first on the search list so the identity resolves.
EXISTING_KEYCHAINS="$(security list-keychains -d user | sed 's/[":]//g' | xargs)"
# shellcheck disable=SC2086
security list-keychains -d user -s "$KEYCHAIN" $EXISTING_KEYCHAINS

security find-identity -v -p codesigning "$KEYCHAIN" | sed 's/^/  /'
security find-identity -v -p codesigning "$KEYCHAIN" | grep -qF "$APPLE_SIGNING_IDENTITY" \
  || die "Signing identity not found after import: $APPLE_SIGNING_IDENTITY"

# ---------------------------------------------------------------------------
# 2. Decode the provisioning profiles.
# ---------------------------------------------------------------------------
log "Decoding provisioning profiles"
echo "$APPLE_PROVISIONING_PROFILE_APP" | base64 --decode > "$APP_PROFILE"
echo "$APPLE_PROVISIONING_PROFILE_GATEWAY" | base64 --decode > "$GW_PROFILE"
# Sanity: they must be CMS-decodable plists, or the embed is garbage.
security cms -D -i "$APP_PROFILE" >/dev/null 2>&1 || die "APPLE_PROVISIONING_PROFILE_APP is not a valid provisioning profile"
security cms -D -i "$GW_PROFILE"  >/dev/null 2>&1 || die "APPLE_PROVISIONING_PROFILE_GATEWAY is not a valid provisioning profile"

# ---------------------------------------------------------------------------
# 3. Nest the gateway + embed profiles + inside-out sign (the proven local flow).
# ---------------------------------------------------------------------------
log "Signing (nest gateway + embed profiles + inside-out codesign)"
APP="$APP" IDENTITY="$APPLE_SIGNING_IDENTITY" APP_PROFILE="$APP_PROFILE" GW_PROFILE="$GW_PROFILE" \
  bash "$SCRIPT_DIR/macos-sign-local.sh" "$APP" "$APPLE_SIGNING_IDENTITY" "$APP_PROFILE" "$GW_PROFILE"

# ---------------------------------------------------------------------------
# 4. Notarize + staple the app.
#    Gatekeeper requires the .app be notarized and stapled. notarytool wants a
#    zip; ditto --keepParent preserves the .app structure.
#
#    Notarization uses a BOUNDED wait (SOU-199). Apple's Developer ID Notary
#    Service has recurring "In Progress" queue stalls, and a plain `submit
#    --wait` blocks until Apple answers, which hung v1.9.1's mac job ~2h until
#    the 6h job cap. notarize() submits, then waits with a hard timeout, and on
#    a timeout or rejection dumps the notarization log and fails fast so the
#    release can simply be re-run once Apple's queue recovers. release.yml also
#    caps this whole step with timeout-minutes as a backstop.
# ---------------------------------------------------------------------------
NOTARIZE_TIMEOUT="${NOTARIZE_TIMEOUT:-30m}"
notarize() {
  local artifact="$1" kind="$2" id status
  log "Submitting the $kind for notarization"
  id="$(xcrun notarytool submit "$artifact" \
    --apple-id "$APPLE_ID" --password "$APPLE_PASSWORD" --team-id "$APPLE_TEAM_ID" \
    --output-format json |
    python3 -c 'import sys,json; print(json.load(sys.stdin).get("id",""))')" ||
    die "notarytool submit failed for the $kind"
  [[ -n "$id" ]] || die "notarytool submit returned no submission id for the $kind"
  log "Waiting on notarization $id (timeout $NOTARIZE_TIMEOUT)"
  # Bounded wait; on timeout notarytool exits non-zero and prints no final JSON, so `status`
  # comes back empty and trips the not-Accepted branch below (a rejection yields "Invalid").
  status="$(xcrun notarytool wait "$id" \
    --apple-id "$APPLE_ID" --password "$APPLE_PASSWORD" --team-id "$APPLE_TEAM_ID" \
    --timeout "$NOTARIZE_TIMEOUT" --output-format json 2>/dev/null |
    python3 -c 'import sys,json; print(json.load(sys.stdin).get("status",""))' 2>/dev/null || true)"
  if [[ "$status" != "Accepted" ]]; then
    printf '::error::Notarization of the %s (%s) did not succeed (status: %s); Apple queue stall or rejection. Log follows:\n' \
      "$kind" "$id" "${status:-timeout}" >&2
    xcrun notarytool log "$id" \
      --apple-id "$APPLE_ID" --password "$APPLE_PASSWORD" --team-id "$APPLE_TEAM_ID" >&2 || true
    die "notarization did not succeed for the $kind; re-run the release once Apple's Notary queue recovers"
  fi
}

log "Notarizing the app"
APP_ZIP="$WORK/Toolport-notarize.zip"
ditto -c -k --keepParent "$APP" "$APP_ZIP"
notarize "$APP_ZIP" "app"
xcrun stapler staple "$APP"
xcrun stapler validate "$APP" || die "stapler validate failed on the app"

# ---------------------------------------------------------------------------
# 5. Build, sign, notarize, staple the .dmg (from the stapled app).
#    Plain UDZO image via hdiutil (no extra deps). Styling can be layered on
#    later; correctness/notarization is what matters for the release.
# ---------------------------------------------------------------------------
log "Building + notarizing the dmg"
DMG_DIR="$REPO_ROOT/src-tauri/target/$TARGET/release/bundle/dmg"
mkdir -p "$DMG_DIR"
DMG="$DMG_DIR/Toolport_${TARGET}.dmg"
rm -f "$DMG"
hdiutil create -volname "Toolport" -srcfolder "$APP" -ov -format UDZO "$DMG"
codesign --force --timestamp -s "$APPLE_SIGNING_IDENTITY" "$DMG"
notarize "$DMG" "dmg"
xcrun stapler staple "$DMG"

# ---------------------------------------------------------------------------
# 6. Regenerate the updater artifact over the re-signed app.
#    Tauri's `<app>.app.tar.gz` + `.sig` were computed over the UNSIGNED app, so
#    re-tar the signed/stapled app and re-sign with the Ed25519 updater key, or
#    auto-update would reject the bytes.
# ---------------------------------------------------------------------------
log "Regenerating the updater artifact"
MACOS_DIR="$REPO_ROOT/src-tauri/target/$TARGET/release/bundle/macos"
TARBALL="$MACOS_DIR/Toolport_${TARGET}.app.tar.gz"
rm -f "$MACOS_DIR/Toolport.app.tar.gz" "$MACOS_DIR/Toolport.app.tar.gz.sig" "$TARBALL" "$TARBALL.sig"
( cd "$MACOS_DIR" && tar -czf "$TARBALL" "$(basename "$APP")" )
# `tauri signer sign` reads the key + password from the same env vars `tauri build`
# uses; pass them explicitly so it never prompts.
TAURI_SIGNING_PRIVATE_KEY="$TAURI_SIGNING_PRIVATE_KEY" \
TAURI_SIGNING_PRIVATE_KEY_PASSWORD="${TAURI_SIGNING_PRIVATE_KEY_PASSWORD:-}" \
  npx tauri signer sign "$TARBALL"
[[ -f "$TARBALL.sig" ]] || die "updater .sig was not produced for $TARBALL"

log "DONE"
echo "  app     : $APP (signed, notarized, stapled)"
echo "  dmg     : $DMG"
echo "  updater : $TARBALL (+ .sig)"
