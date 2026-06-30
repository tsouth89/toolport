#!/usr/bin/env bash
#
# macos-sign-local.sh
#
# LOCAL macOS sign + package flow for the keychain-access-group wrapper (Phase 2).
#
# What it does:
#   1. Finds the bare conduit-gateway binary inside a built Conduit.app.
#   2. Rebuilds it as a nested helper bundle:
#        Conduit.app/Contents/Helpers/ConduitGateway.app
#      so the gateway can carry its OWN embedded provisioning profile (a bare
#      Mach-O cannot embed a .provisionprofile; only a bundle can).
#   3. Leaves a symlink at the OLD bare path
#        Conduit.app/Contents/MacOS/conduit-gateway
#      pointing at the nested binary, so existing client configs that spawn the
#      old path keep working.
#   4. Codesigns inside-out (no --deep): gateway bundle first, then the outer app,
#      each with the hardened runtime + its own entitlements + embedded profile.
#   5. Verifies + prints the keychain-access-groups entitlement and the embedded
#      profile ExpirationDate on both bundles.
#
# This script is intended to run on a Mac (VM) AFTER:
#   npx tauri build --config src-tauri/tauri.bundle.conf.json
#
# It is idempotent and safe to re-run (e.g. the "update" test). It re-creates the
# helper bundle from whichever real binary it can find, then re-signs.
#
# It does NOT touch the Tauri config or .github/workflows/release.yml. The CI
# integration is a later phase.

set -euo pipefail

# ---------------------------------------------------------------------------
# Parameters (override via env or positional args).
#   $1 = APP path, $2 = IDENTITY, $3 = APP_PROFILE, $4 = GW_PROFILE
# ---------------------------------------------------------------------------
APP="${1:-${APP:-src-tauri/target/release/bundle/macos/Conduit.app}}"
IDENTITY="${2:-${IDENTITY:-Developer ID Application: Brandon SOuth (V4YZPC7T6G)}}"
APP_PROFILE="${3:-${APP_PROFILE:-$HOME/Downloads/Conduit_Developer_ID.provisionprofile}}"
GW_PROFILE="${4:-${GW_PROFILE:-$HOME/Downloads/Conduit_Gateway_Developer_ID.provisionprofile}}"

# Entitlements live in the repo, relative to this script's location, so the
# script works regardless of the caller's CWD.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
APP_ENTITLEMENTS="$REPO_ROOT/src-tauri/Entitlements.plist"
GW_ENTITLEMENTS="$REPO_ROOT/src-tauri/Gateway.entitlements"

# Identifiers (must match the entitlements + profiles).
GW_BUNDLE_ID="com.tsout.conduit.gateway"
GW_EXECUTABLE="conduit-gateway"
HELPER_APP_NAME="ConduitGateway.app"

# A version string for the helper Info.plist. Pull it from the app's own
# Info.plist if available, else fall back.
HELPER_VERSION="${HELPER_VERSION:-}"

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
red()   { printf '\033[31m%s\033[0m\n' "$*"; }
green() { printf '\033[32m%s\033[0m\n' "$*"; }
bold()  { printf '\033[1m%s\033[0m\n' "$*"; }

die() {
  red "ERROR: $*" >&2
  exit 1
}

require_macos() {
  if [[ "$(uname -s)" != "Darwin" ]]; then
    die "This script must run on macOS (uname -s = $(uname -s)). codesign and the keychain group cannot be exercised on any other host."
  fi
}

require_tool() {
  command -v "$1" >/dev/null 2>&1 || die "Required tool not found on PATH: $1"
}

# ---------------------------------------------------------------------------
# Preflight
# ---------------------------------------------------------------------------
require_macos
require_tool codesign
require_tool find
require_tool file
require_tool security
require_tool plutil
[[ -x /usr/libexec/PlistBuddy ]] || die "PlistBuddy not found at /usr/libexec/PlistBuddy (expected on every macOS)"

bold "== Conduit macOS local sign + package =="
echo "APP          = $APP"
echo "IDENTITY     = $IDENTITY"
echo "APP_PROFILE  = $APP_PROFILE"
echo "GW_PROFILE   = $GW_PROFILE"
echo "APP entitlements = $APP_ENTITLEMENTS"
echo "GW  entitlements = $GW_ENTITLEMENTS"
echo

[[ -d "$APP" ]]                  || die "App bundle not found: $APP  (run 'npx tauri build --config src-tauri/tauri.bundle.conf.json' first)"
[[ -f "$APP_ENTITLEMENTS" ]]     || die "App entitlements not found: $APP_ENTITLEMENTS"
[[ -f "$GW_ENTITLEMENTS" ]]      || die "Gateway entitlements not found: $GW_ENTITLEMENTS"
[[ -f "$APP_PROFILE" ]]          || die "App provisioning profile not found: $APP_PROFILE"
[[ -f "$GW_PROFILE" ]]           || die "Gateway provisioning profile not found: $GW_PROFILE"

# Confirm the signing identity is actually present in the keychain.
if ! security find-identity -v -p codesigning 2>/dev/null | grep -qF "$IDENTITY"; then
  die "Signing identity not found in keychain: $IDENTITY
     (run 'security find-identity -v -p codesigning' to see what is installed)"
fi

HELPERS_DIR="$APP/Contents/Helpers"
HELPER_APP="$HELPERS_DIR/$HELPER_APP_NAME"
HELPER_BIN="$HELPER_APP/Contents/MacOS/$GW_EXECUTABLE"
SYMLINK_PATH="$APP/Contents/MacOS/$GW_EXECUTABLE"

# ---------------------------------------------------------------------------
# 1. Locate the gateway binary inside the app.
#    It is EITHER the bare Mach-O at Contents/MacOS/conduit-gateway (fresh build),
#    OR already inside the nested helper bundle (re-run). We must not pick up the
#    backward-compat symlink as the "real" binary.
# ---------------------------------------------------------------------------
bold "[1/5] Locating the gateway binary inside the app"

# Find every candidate named conduit-gateway, skipping symlinks (-type f).
# (Portable read loop instead of `mapfile`, which is bash 4+ only; macOS ships bash 3.2.)
CANDIDATES=()
while IFS= read -r _candidate; do
  [[ -n "$_candidate" ]] && CANDIDATES+=("$_candidate")
done < <(find "$APP/Contents" -name "$GW_EXECUTABLE" -type f 2>/dev/null || true)

REAL_BIN=""
# Prefer a binary already inside the helper bundle (idempotent re-run).
for c in "${CANDIDATES[@]:-}"; do
  if [[ "$c" == "$HELPER_BIN" ]]; then
    REAL_BIN="$c"
    break
  fi
done
# Otherwise take the bare one at Contents/MacOS.
if [[ -z "$REAL_BIN" ]]; then
  for c in "${CANDIDATES[@]:-}"; do
    if [[ "$c" == "$SYMLINK_PATH" ]]; then
      REAL_BIN="$c"
      break
    fi
  done
fi
# Last resort: the first real file we found.
if [[ -z "$REAL_BIN" && "${#CANDIDATES[@]}" -gt 0 ]]; then
  REAL_BIN="${CANDIDATES[0]}"
fi

[[ -n "$REAL_BIN" ]] || die "Could not find a '$GW_EXECUTABLE' binary anywhere under $APP/Contents.
     The gateway is shipped as a Tauri externalBin; expected it at $SYMLINK_PATH.
     Did 'npx tauri build --config src-tauri/tauri.bundle.conf.json' run?"

# Sanity: it should be a Mach-O, not the empty placeholder.
[[ -s "$REAL_BIN" ]] || die "Gateway binary is empty: $REAL_BIN"
if ! file "$REAL_BIN" | grep -qiE 'mach-o'; then
  die "Found '$GW_EXECUTABLE' but it is not a Mach-O binary: $REAL_BIN"
fi
green "  found: $REAL_BIN"

# Determine helper version from the app's Info.plist if not already set.
if [[ -z "$HELPER_VERSION" ]]; then
  HELPER_VERSION="$(/usr/libexec/PlistBuddy -c 'Print :CFBundleShortVersionString' "$APP/Contents/Info.plist" 2>/dev/null || echo '0.0.0')"
fi
echo "  helper version = $HELPER_VERSION"

# ---------------------------------------------------------------------------
# 2. Build the nested helper bundle.
# ---------------------------------------------------------------------------
bold "[2/5] Building nested helper bundle: $HELPER_APP"

# Stash the real binary aside so we can rebuild the bundle from a clean slate.
TMP_BIN="$(mktemp "${TMPDIR:-/tmp}/conduit-gateway.XXXXXX")"
cp -f "$REAL_BIN" "$TMP_BIN"
chmod +x "$TMP_BIN"

# Remove any prior helper bundle and the bare/symlink path, then recreate. This
# is what makes the script idempotent: every run rebuilds from $TMP_BIN.
rm -rf "$HELPER_APP"
rm -f "$SYMLINK_PATH"      # also removes a stale symlink or a leftover bare binary
mkdir -p "$HELPER_APP/Contents/MacOS"

# (a) the binary, moved into the helper bundle.
mv -f "$TMP_BIN" "$HELPER_BIN"
chmod +x "$HELPER_BIN"

# (b) Info.plist
cat > "$HELPER_APP/Contents/Info.plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>CFBundleIdentifier</key>
	<string>$GW_BUNDLE_ID</string>
	<key>CFBundleExecutable</key>
	<string>$GW_EXECUTABLE</string>
	<key>CFBundleName</key>
	<string>ConduitGateway</string>
	<key>CFBundleDisplayName</key>
	<string>Conduit Gateway</string>
	<key>CFBundlePackageType</key>
	<string>APPL</string>
	<key>CFBundleInfoDictionaryVersion</key>
	<string>6.0</string>
	<key>CFBundleShortVersionString</key>
	<string>$HELPER_VERSION</string>
	<key>CFBundleVersion</key>
	<string>$HELPER_VERSION</string>
	<key>LSBackgroundOnly</key>
	<true/>
</dict>
</plist>
PLIST

# Validate the plist we just wrote.
plutil -lint "$HELPER_APP/Contents/Info.plist" >/dev/null || die "Generated helper Info.plist failed plutil -lint"

# (c) embedded.provisionprofile (the GATEWAY profile)
cp -f "$GW_PROFILE" "$HELPER_APP/Contents/embedded.provisionprofile"
green "  helper bundle assembled"

# ---------------------------------------------------------------------------
# 3. Backward-compat symlink at the OLD bare gateway path.
#    Contents/MacOS/conduit-gateway -> ../Helpers/ConduitGateway.app/Contents/MacOS/conduit-gateway
# ---------------------------------------------------------------------------
bold "[3/5] Linking old bare path -> nested binary (backward compat)"
ln -s "../Helpers/$HELPER_APP_NAME/Contents/MacOS/$GW_EXECUTABLE" "$SYMLINK_PATH"
[[ -L "$SYMLINK_PATH" ]] || die "Failed to create backward-compat symlink at $SYMLINK_PATH"
# Resolve it to confirm it points at the real binary.
if ! readlink "$SYMLINK_PATH" >/dev/null 2>&1; then
  die "Symlink at $SYMLINK_PATH does not resolve"
fi
green "  symlink: $SYMLINK_PATH -> $(readlink "$SYMLINK_PATH")"

# ---------------------------------------------------------------------------
# 4. Codesign INSIDE-OUT (no --deep): gateway bundle first, then the outer app.
# ---------------------------------------------------------------------------
bold "[4/5] Codesigning inside-out"

echo "  signing gateway bundle ..."
codesign --force --options runtime --timestamp \
  --entitlements "$GW_ENTITLEMENTS" \
  -s "$IDENTITY" \
  "$HELPER_APP" \
  || die "codesign failed on the gateway helper bundle"

# Embed the APP profile into the outer app before signing it.
cp -f "$APP_PROFILE" "$APP/Contents/embedded.provisionprofile"

echo "  signing outer app ..."
codesign --force --options runtime --timestamp \
  --entitlements "$APP_ENTITLEMENTS" \
  -s "$IDENTITY" \
  "$APP" \
  || die "codesign failed on the outer app bundle"
green "  signed"

# ---------------------------------------------------------------------------
# 5. Verify + print.
# ---------------------------------------------------------------------------
bold "[5/5] Verifying"

print_entitlement_group() {
  local bundle="$1"
  local label="$2"
  echo "--- $label: keychain-access-groups ---"
  # codesign -d --entitlements - dumps the entitlements; grep the group line(s).
  if codesign -d --entitlements - "$bundle" 2>/dev/null | grep -A1 -i 'keychain-access-groups' ; then
    :
  else
    red "  WARNING: could not read keychain-access-groups from $bundle"
  fi
  echo
}

print_profile_expiry() {
  local profile="$1"
  local label="$2"
  [[ -f "$profile" ]] || { red "  MISSING embedded.provisionprofile for $label: $profile"; return 1; }
  # The profile is CMS-wrapped; decode it to a temp plist (PlistBuddy can't read
  # /dev/stdin) then read ExpirationDate.
  local exp tmp
  tmp="$(mktemp "${TMPDIR:-/tmp}/conduit-profile.XXXXXX")"
  exp=""
  if security cms -D -i "$profile" -o "$tmp" 2>/dev/null; then
    exp="$(/usr/libexec/PlistBuddy -c 'Print :ExpirationDate' "$tmp" 2>/dev/null || true)"
  fi
  rm -f "$tmp"
  if [[ -z "$exp" ]]; then
    red "  WARNING: could not read ExpirationDate from $profile"
  else
    echo "  $label embedded profile ExpirationDate: $exp"
  fi
}

echo
bold "codesign -dvvv (gateway):"
codesign -dvvv "$HELPER_APP" 2>&1 | sed 's/^/  /'
echo
bold "codesign -dvvv (app):"
codesign -dvvv "$APP" 2>&1 | sed 's/^/  /'
echo

print_entitlement_group "$HELPER_APP" "GATEWAY"
print_entitlement_group "$APP" "APP"

bold "Embedded provisioning profiles:"
[[ -f "$HELPER_APP/Contents/embedded.provisionprofile" ]] \
  || die "Gateway embedded.provisionprofile missing after signing"
[[ -f "$APP/Contents/embedded.provisionprofile" ]] \
  || die "App embedded.provisionprofile missing after signing"
print_profile_expiry "$HELPER_APP/Contents/embedded.provisionprofile" "GATEWAY"
print_profile_expiry "$APP/Contents/embedded.provisionprofile" "APP"
echo

bold "codesign --verify --strict --deep:"
codesign --verify --strict --deep --verbose=2 "$APP" 2>&1 | sed 's/^/  /' \
  || die "codesign --verify --strict --deep FAILED on $APP"

echo
green "OK: signed + verified."
echo "  App     : $APP"
echo "  Gateway : $HELPER_BIN"
echo "  Compat  : $SYMLINK_PATH -> $(readlink "$SYMLINK_PATH")"
