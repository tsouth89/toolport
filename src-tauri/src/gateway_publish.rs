//! Versioned gateway publishing for Windows packaged installs.
//!
//! Client MCP configs point at `%APPDATA%\Roaming\Conduit\bin\toolport-gateway-{version}.exe`
//! instead of the install-dir copy NSIS must overwrite on update. Publishing copies the
//! bundled gateway to a new versioned filename (never fighting a lock on the old file),
//! records the path in `gateway-manifest.json`, and lets `repoint_stale_gateways` migrate
//! client configs.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

const MANIFEST_FILE: &str = "gateway-manifest.json";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GatewayManifest {
    pub version: String,
    pub path: String,
    pub size: u64,
}

/// True on Windows packaged builds (not `cargo run` from `target/`).
pub fn should_publish_client_gateway() -> bool {
    #[cfg(windows)]
    {
        if let Ok(exe) = std::env::current_exe() {
            let lower = exe.to_string_lossy().to_ascii_lowercase();
            return !lower.contains("\\target\\");
        }
    }
    #[cfg(not(windows))]
    let _ = ();
    false
}

fn gateway_bin_dir() -> Option<PathBuf> {
    Some(crate::registry::conduit_dir()?.join("bin"))
}

fn manifest_path() -> Option<PathBuf> {
    Some(gateway_bin_dir()?.join(MANIFEST_FILE))
}

fn versioned_dest(version: &str) -> Option<PathBuf> {
    let ext = std::env::consts::EXE_SUFFIX;
    Some(
        gateway_bin_dir()?.join(format!("toolport-gateway-{version}{ext}")),
    )
}

/// Gateway binary bundled next to the running app (install dir).
pub fn bundled_gateway_source() -> Option<PathBuf> {
    let exe = std::env::current_exe().ok()?;
    let dir = exe.parent()?;
    let ext = std::env::consts::EXE_SUFFIX;
    let version = env!("CARGO_PKG_VERSION");

    let versioned = dir.join(format!("toolport-gateway-{version}{ext}"));
    if versioned.is_file() {
        return Some(versioned);
    }

    let plain = dir.join(format!("toolport-gateway{ext}"));
    if plain.is_file() {
        return Some(plain);
    }

    let legacy = dir.join(format!("conduit-gateway{ext}"));
    if legacy.is_file() {
        return Some(legacy);
    }

    if let Some(triple) = option_env!("CONDUIT_TARGET_TRIPLE").filter(|t| !t.is_empty()) {
        for name in ["toolport-gateway", "conduit-gateway"] {
            let suffixed = dir.join(format!("{name}-{triple}{ext}"));
            if suffixed.is_file() {
                return Some(suffixed);
            }
        }
    }

    None
}

fn file_size(path: &Path) -> Option<u64> {
    std::fs::metadata(path).ok().map(|m| m.len())
}

/// Copy the install-dir gateway into `Conduit/bin` when needed and write the manifest.
pub fn publish_bundled_gateway() -> Option<PathBuf> {
    if !should_publish_client_gateway() {
        return None;
    }
    let src = bundled_gateway_source()?;
    let version = env!("CARGO_PKG_VERSION").to_string();
    let dest = versioned_dest(&version)?;
    let src_size = file_size(&src)?;

    let needs_copy = match file_size(&dest) {
        Some(dest_size) => dest_size != src_size,
        None => true,
    };
    if needs_copy {
        if let Some(parent) = dest.parent() {
            std::fs::create_dir_all(parent).ok()?;
        }
        std::fs::copy(&src, &dest).ok()?;
    }

    let manifest = GatewayManifest {
        version: version.clone(),
        path: dest.to_string_lossy().into_owned(),
        size: file_size(&dest).unwrap_or(src_size),
    };
    if let Some(path) = manifest_path() {
        if let Ok(json) = serde_json::to_string_pretty(&manifest) {
            let _ = crate::registry::atomic_write(&path, &json);
        }
    }

    Some(dest)
}

/// Published client gateway path from the manifest, when it matches this build.
pub fn published_gateway_path() -> Option<PathBuf> {
    if !should_publish_client_gateway() {
        return None;
    }
    let path = manifest_path()?;
    let raw = std::fs::read_to_string(&path).ok()?;
    let manifest: GatewayManifest = serde_json::from_str(&raw).ok()?;
    if manifest.version != env!("CARGO_PKG_VERSION") {
        return None;
    }
    let p = PathBuf::from(&manifest.path);
    if p.is_file() {
        Some(p)
    } else {
        None
    }
}

/// Resolve the path MCP clients should spawn: publish if needed, else read manifest.
pub fn client_gateway_path() -> Option<PathBuf> {
    if !should_publish_client_gateway() {
        return None;
    }
    if let Some(p) = published_gateway_path() {
        return Some(p);
    }
    publish_bundled_gateway()
}

/// Terminate client-spawned gateway processes so the installer can replace locked binaries
/// and so clients respawn the just-installed version instead of keeping the old one until the
/// user relaunches them. Does not touch parent apps (Cursor, Codex, etc.). Returns how many
/// image patterns `taskkill` reported killing.
///
/// The `*` globs are load-bearing: the published gateway clients actually run is VERSIONED
/// (`toolport-gateway-1.7.2.exe`), so matching only the bare `toolport-gateway.exe` (the old
/// behavior) killed nothing on a real update. `taskkill /IM` accepts a wildcard on the image
/// name; nothing else on the system is named `*-gateway*`, so the match stays scoped to ours.
#[cfg(windows)]
pub fn stop_spawned_gateways() -> u32 {
    let mut stopped = 0u32;
    for image in ["toolport-gateway*.exe", "conduit-gateway*.exe"] {
        let status = std::process::Command::new("taskkill")
            .args(["/F", "/IM", image])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status();
        if status.map(|s| s.success()).unwrap_or(false) {
            stopped += 1;
        }
    }
    stopped
}

#[cfg(not(windows))]
pub fn stop_spawned_gateways() -> u32 {
    0
}

/// Terminate only gateway processes running a version OTHER than the installed one, and
/// report the image names killed. Unlike [`stop_spawned_gateways`] this leaves current
/// gateways alone, so it is safe to run on every launch.
///
/// Why this exists (SOU-306): the launch-time cleanup used to be gated on
/// `repoint_stale_gateways()` returning a non-empty list. That call is idempotent, so once
/// client configs point at the new binary it returns empty forever and the cleanup never
/// runs again. The gate was a proxy for "is a running gateway on an old version?", and the
/// two come apart exactly when the repoint already happened - after a manual install, or on
/// any launch after the first. Six 1.9.3 gateways survived a 1.9.4 update that way, two of
/// them across an app restart.
///
/// This matters because the gateway is where fixes like SOU-292 live: a user who updates to
/// get one, while their client keeps an old gateway alive, still has the bug and reasonably
/// concludes the update did nothing. Clients respawn the gateway on their next request, so
/// killing is enough; nothing needs relaunching here.
#[cfg(windows)]
pub fn stop_stale_gateways() -> Vec<String> {
    let images = running_gateway_images();
    let mut killed = Vec::new();
    for image in stale_gateway_images(&images, env!("CARGO_PKG_VERSION")) {
        let ok = std::process::Command::new("taskkill")
            .args(["/F", "/IM", &image])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .map(|s| s.success())
            .unwrap_or(false);
        if ok {
            killed.push(image);
        }
    }
    killed
}

/// Which of `images` are gateways running a version other than `current`.
///
/// Split from the process enumeration and the killing so the decision is testable without
/// spawning anything: getting this wrong is expensive in both directions - too eager and a
/// launch kills the gateway it just published, too shy and the stale one survives and the
/// user silently keeps running old code.
fn stale_gateway_images(images: &[String], current: &str) -> Vec<String> {
    // Names the current install may legitimately be running under. The unversioned forms are
    // kept because a dev/unpackaged run uses them and carries no version to compare, so
    // killing them would take out a running `tauri dev` gateway. `conduit-gateway` is the
    // pre-rename form, kept so an in-place upgrade from an old install can't self-kill.
    let keep = [
        format!("toolport-gateway-{current}.exe"),
        format!("conduit-gateway-{current}.exe"),
        "toolport-gateway.exe".to_string(),
        "conduit-gateway.exe".to_string(),
    ];
    images
        .iter()
        .filter(|image| !keep.iter().any(|k| k.eq_ignore_ascii_case(image)))
        .cloned()
        .collect()
}

/// Distinct image names of running gateway processes, e.g. `toolport-gateway-1.9.3.exe`.
/// Matched on the `*-gateway*` shape rather than an exact name because the published binary
/// clients actually run is versioned; nothing else on the system uses that shape.
#[cfg(windows)]
fn running_gateway_images() -> Vec<String> {
    let Ok(out) = std::process::Command::new("tasklist")
        .args(["/FO", "CSV", "/NH"])
        .output()
    else {
        return Vec::new();
    };
    let text = String::from_utf8_lossy(&out.stdout);
    let mut names: Vec<String> = Vec::new();
    for line in text.lines() {
        // CSV rows look like: "image.exe","1234","Console","1","12,345 K"
        let Some(name) = line.trim().strip_prefix('"').and_then(|r| r.split('"').next())
        else {
            continue;
        };
        let lower = name.to_ascii_lowercase();
        let ours = (lower.starts_with("toolport-gateway") || lower.starts_with("conduit-gateway"))
            && lower.ends_with(".exe");
        if ours && !names.iter().any(|n: &String| n.eq_ignore_ascii_case(name)) {
            names.push(name.to_string());
        }
    }
    names
}

#[cfg(not(windows))]
pub fn stop_stale_gateways() -> Vec<String> {
    Vec::new()
}

/// Last path segment, regardless of OS path separator (client configs store Windows paths).
fn path_basename(stored: &str) -> &str {
    stored.rsplit(['\\', '/']).next().unwrap_or(stored)
}

/// Whether a stored client config still points at an install-dir (unversioned) gateway.
pub fn is_unversioned_install_gateway_path(stored: &str) -> bool {
    let lower = stored.to_ascii_lowercase();
    if lower.contains("conduit-gateway") {
        return true;
    }
    let name_lower = path_basename(stored).to_ascii_lowercase();
    if name_lower != "toolport-gateway.exe" && name_lower != "conduit-gateway.exe" {
        return false;
    }
    // Unversioned basename outside Conduit/bin → install dir or other stale layout.
    !(lower.contains("\\conduit\\bin\\") || lower.contains("/conduit/bin/"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unversioned_install_path_detected() {
        assert!(is_unversioned_install_gateway_path(
            r"C:\Users\me\AppData\Local\Toolport\toolport-gateway.exe"
        ));
        assert!(!is_unversioned_install_gateway_path(
            r"C:\Users\me\AppData\Roaming\Conduit\bin\toolport-gateway-1.6.0.exe"
        ));
        assert!(is_unversioned_install_gateway_path(
            "/Applications/Toolport.app/Contents/MacOS/conduit-gateway"
        ));
    }

    #[test]
    fn stale_gateway_images_keeps_current_and_kills_older() {
        // Regression for SOU-306. A 1.9.4 update left six 1.9.3 gateways running because the
        // cleanup was gated on a repoint that had already happened, so users kept running old
        // gateway code and did not receive the fix they had just updated for.
        let running = vec![
            "toolport-gateway-1.9.3.exe".to_string(),
            "toolport-gateway-1.9.4.exe".to_string(),
            "toolport-gateway-1.8.0.exe".to_string(),
            "conduit-gateway-1.7.2.exe".to_string(),
        ];
        let stale = stale_gateway_images(&running, "1.9.4");

        assert!(
            !stale.contains(&"toolport-gateway-1.9.4.exe".to_string()),
            "must never kill the version it just published"
        );
        assert!(stale.contains(&"toolport-gateway-1.9.3.exe".to_string()));
        assert!(stale.contains(&"toolport-gateway-1.8.0.exe".to_string()));
        assert!(
            stale.contains(&"conduit-gateway-1.7.2.exe".to_string()),
            "the pre-rename image is still stale when its version differs"
        );
        assert_eq!(stale.len(), 3);
    }

    #[test]
    fn stale_gateway_images_spares_unversioned_and_a_clean_launch() {
        // Unversioned images are dev/unpackaged runs with no version to compare; killing them
        // would take out a running `tauri dev` gateway.
        let dev = vec![
            "toolport-gateway.exe".to_string(),
            "conduit-gateway.exe".to_string(),
        ];
        assert!(stale_gateway_images(&dev, "1.9.4").is_empty());

        // The common case: nothing stale, so a normal launch kills nothing.
        let current = vec!["toolport-gateway-1.9.4.exe".to_string()];
        assert!(stale_gateway_images(&current, "1.9.4").is_empty());

        // And the pre-rename image at the current version is the same install, not a leftover.
        let renamed = vec!["conduit-gateway-1.9.4.exe".to_string()];
        assert!(stale_gateway_images(&renamed, "1.9.4").is_empty());
    }

    #[test]
    fn manifest_roundtrip_fields() {
        let m = GatewayManifest {
            version: "1.6.0".into(),
            path: r"C:\x\toolport-gateway-1.6.0.exe".into(),
            size: 42,
        };
        let json = serde_json::to_string(&m).unwrap();
        let back: GatewayManifest = serde_json::from_str(&json).unwrap();
        assert_eq!(m, back);
    }
}
