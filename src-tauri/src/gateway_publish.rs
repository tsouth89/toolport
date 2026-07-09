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

/// Terminate client-spawned gateway processes so the installer can replace locked binaries.
/// Does not touch parent apps (Cursor, Codex, etc.). Returns how many images were targeted.
#[cfg(windows)]
pub fn stop_spawned_gateways() -> u32 {
    let mut stopped = 0u32;
    for image in ["toolport-gateway.exe", "conduit-gateway.exe"] {
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

/// Whether a stored client config still points at an install-dir (unversioned) gateway.
pub fn is_unversioned_install_gateway_path(stored: &str) -> bool {
    let lower = stored.to_ascii_lowercase();
    if lower.contains("conduit-gateway") {
        return true;
    }
    let path = Path::new(stored);
    let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
        return false;
    };
    let name_lower = name.to_ascii_lowercase();
    if name_lower != "toolport-gateway.exe" && name_lower != "conduit-gateway.exe" {
        return false;
    }
    // Unversioned basename outside Conduit/bin → install dir or other stale layout.
    !lower.contains("\\conduit\\bin\\")
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
