#!/usr/bin/env bash
#
# Toolport installer. One-liner:
#   curl -fsSL https://raw.githubusercontent.com/tsouth89/toolport/main/scripts/install.sh | bash
#
# Installs the latest signed release for your OS/arch:
#   - Linux (x86_64): the .deb via apt where available, else the portable AppImage
#     into ~/.local/bin with a desktop entry.
#   - macOS: copies Toolport.app from the signed .dmg into /Applications (Homebrew is
#     the cleaner path, and this script points you there).
# Windows: download the .exe from the Releases page instead.
set -euo pipefail

REPO="tsouth89/toolport"
API="https://api.github.com/repos/$REPO/releases/latest"

say() { printf '\033[1;36m>\033[0m %s\n' "$*"; }
err() {
  printf '\033[1;31mx\033[0m %s\n' "$*" >&2
  exit 1
}
need() { command -v "$1" >/dev/null 2>&1 || err "This installer needs '$1' on your PATH."; }

need curl
os="$(uname -s)"
arch="$(uname -m)"

# Fetch the latest-release metadata once (unauthenticated API is rate-limited, so don't
# hammer it), then resolve pieces out of the JSON with grep/sed (no jq dependency).
release_json="$(curl -fsSL "$API")" || err "Couldn't reach the GitHub releases API."
tag_name="$(printf '%s' "$release_json" |
  grep -o '"tag_name": *"[^"]*"' | sed 's/.*: *"\([^"]*\)".*/\1/' | head -n1)"

# Download URL for the asset whose filename ends with the given (regex) suffix.
asset_url() {
  printf '%s' "$release_json" |
    grep -o '"browser_download_url": *"[^"]*"' |
    sed 's/.*: *"\([^"]*\)".*/\1/' |
    grep -E "$1\$" | head -n1
}

install_linux() {
  [ "$arch" = "x86_64" ] ||
    err "Linux builds are x86_64 only right now (you're on $arch). Use Development mode or grab a build from the Releases page."
  tmp="$(mktemp -d)"
  trap 'rm -rf "$tmp"' EXIT

  # Prefer the .deb on Debian/Ubuntu: it links the system WebKitGTK and is the most
  # reliable package (see README). Fall back to the no-root AppImage everywhere else.
  if command -v dpkg >/dev/null 2>&1 && command -v apt-get >/dev/null 2>&1; then
    url="$(asset_url '_amd64\.deb')"
    [ -n "$url" ] || err "No .deb found in $tag_name."
    say "Downloading $(basename "$url")"
    curl -fsSL "$url" -o "$tmp/toolport.deb"
    # Use sudo only when we aren't already root (root shells / containers have no sudo).
    sudo=""
    if [ "$(id -u)" -ne 0 ]; then
      command -v sudo >/dev/null 2>&1 && sudo="sudo" ||
        err "Installing the .deb needs root: re-run as root or install sudo."
    fi
    say "Installing with apt${sudo:+ (you may be prompted for your password)}"
    $sudo apt-get install -y "$tmp/toolport.deb"
    # The .deb installs the app binary as `conduit` (the crate name) plus a Toolport
    # desktop entry; the AppImage path below installs a `toolport` command instead.
    say "Installed. Launch Toolport from your app menu, or run: conduit"
    return
  fi

  url="$(asset_url '_amd64\.AppImage')"
  [ -n "$url" ] || err "No AppImage found in $tag_name."
  bindir="${XDG_BIN_HOME:-$HOME/.local/bin}"
  mkdir -p "$bindir"
  say "Downloading $(basename "$url")"
  curl -fsSL "$url" -o "$bindir/toolport"
  chmod +x "$bindir/toolport"

  apps="$HOME/.local/share/applications"
  mkdir -p "$apps"
  cat >"$apps/toolport.desktop" <<EOF
[Desktop Entry]
Name=Toolport
Comment=One local gateway for every MCP server
Exec=$bindir/toolport
Type=Application
Categories=Development;Utility;
Terminal=false
EOF

  say "Installed the AppImage to $bindir/toolport"
  case ":$PATH:" in
    *":$bindir:"*) : ;;
    *) say "Add $bindir to your PATH to run 'toolport' from anywhere." ;;
  esac
}

install_macos() {
  say "Tip: on macOS the cleanest install is Homebrew:"
  say "     brew install --cask tsouth89/toolport/toolport"
  case "$arch" in
    arm64 | aarch64) suffix='aarch64-apple-darwin\.dmg' ;;
    x86_64) suffix='x86_64-apple-darwin\.dmg' ;;
    *) err "Unsupported macOS arch: $arch" ;;
  esac
  url="$(asset_url "$suffix")"
  [ -n "$url" ] || err "No macOS .dmg found in $tag_name."
  tmp="$(mktemp -d)"
  trap 'rm -rf "$tmp"' EXIT
  say "Downloading $(basename "$url")"
  curl -fsSL "$url" -o "$tmp/toolport.dmg"
  say "Mounting and copying Toolport.app to /Applications"
  hdiutil attach -nobrowse -readonly -mountpoint "$tmp/mnt" "$tmp/toolport.dmg" >/dev/null ||
    err "Couldn't mount the disk image."
  app="$(/bin/ls -d "$tmp"/mnt/*.app 2>/dev/null | head -n1 || true)"
  if [ -z "$app" ]; then
    hdiutil detach "$tmp/mnt" >/dev/null 2>&1 || true
    err "No .app found in the disk image."
  fi
  rm -rf "/Applications/Toolport.app"
  cp -R "$app" /Applications/
  hdiutil detach "$tmp/mnt" >/dev/null 2>&1 || true
  say "Installed to /Applications/Toolport.app. Open it from Launchpad or run: open -a Toolport"
}

say "Installing Toolport ${tag_name:-latest}"
case "$os" in
  Linux) install_linux ;;
  Darwin) install_macos ;;
  *) err "Unsupported OS: $os. On Windows, download the .exe from https://github.com/$REPO/releases/latest" ;;
esac
