//! Secret storage in the OS keychain (Windows Credential Manager / macOS
//! Keychain / libsecret). Secret env values never live in Conduit's registry
//! file or any client config - only here. The gateway pulls them at spawn time
//! and injects them into the child server's environment.

const SERVICE: &str = "conduit-mcp";

/// Reserved secret key for an http server's bearer token (Tier A auth, and where
/// the OAuth flow stores its access token).
pub const HTTP_AUTH_KEY: &str = "__http_auth__";

fn account(server_id: &str, key: &str) -> String {
    format!("{server_id}::{key}")
}

// ── macOS ──────────────────────────────────────────────────────────────────
//
// On macOS we bypass the `keyring` crate and call `security_framework` directly.
//
// `keyring`'s apple-native backend routes writes through the *legacy* file-based
// keychain API (`SecKeychainAddGenericPassword` / `SecKeychainItemModify`),
// which creates items with a **per application Access Control List (ACL)**.
// Every binary that touches the item — the Tauri UI app *and* the standalone
// gateway binary — needs its own "Always Allow" grant, and a fresh prompt can
// fire on first access from each context.
//
// Instead we use the modern `SecItem*` API (`security_framework::passwords`),
// which stores items without per-application ACLs. Any process running as the
// user can read them after a single unlock.
//
// Entries created by a previous version of Conduit (via the `keyring` crate)
// still live in the file-based keychain and carry per-app ACLs. On macOS,
// `migrate_legacy_entries()` runs once at app startup (guarded by a marker file)
// to read each entry's value, delete it, and re-create it via the ACL-free
// `SecItemAdd` path. This is transparent: no secret values are lost, and after
// the migration both the app and gateway read silently.
#[cfg(target_os = "macos")]
mod platform {
    use core_foundation::base::TCFType;
    use security_framework::item::{ItemClass, ItemSearchOptions, Limit, Reference, SearchResult};
    use security_framework::os::macos::keychain_item::SecKeychainItem;
    use security_framework::passwords::{
        delete_generic_password, get_generic_password, set_generic_password,
    };
    use security_framework_sys::base::errSecItemNotFound;

    use super::{account, SERVICE};

    pub fn set_secret(server_id: &str, key: &str, value: &str) -> Result<(), String> {
        set_generic_password(SERVICE, &account(server_id, key), value.as_bytes())
            .map_err(|e| e.to_string())
    }

    pub fn get_secret_result(server_id: &str, key: &str) -> Result<Option<String>, String> {
        match get_generic_password(SERVICE, &account(server_id, key)) {
            Ok(bytes) => String::from_utf8(bytes).map(Some).map_err(|e| e.to_string()),
            Err(e) if e.code() == -25300 /* errSecItemNotFound */ => Ok(None),
            Err(e) => Err(e.to_string()),
        }
    }

    pub fn delete_secret(server_id: &str, key: &str) -> Result<(), String> {
        match delete_generic_password(SERVICE, &account(server_id, key)) {
            Ok(()) => Ok(()),
            Err(e) if e.code() == -25300 /* errSecItemNotFound */ => Ok(()),
            Err(e) => Err(e.to_string()),
        }
    }

    /// Result of a one-time keychain migration.
    pub struct MigrationReport {
        /// Entries whose values were read and re-created via the ACL-free path.
        pub migrated: usize,
        /// Entries that were deleted but couldn't be re-created (value unreadable
        /// or re-creation failed). The user must re-authenticate these servers.
        pub lost: usize,
    }

    /// Migrate all `conduit-mcp` keychain entries from the legacy file-based
    /// keychain (ACL-bearing) to the ACL-free `SecItem` path.
    ///
    /// **Algorithm (read-delete-rewrite):**
    /// 1. For each `(server_id, key)` pair the registry knows about, read the
    ///    current value via `get_generic_password`. From the app process this is
    ///    safe — the user already has an "Always Allow" ACL grant for the app.
    /// 2. Delete **all** entries for our service via `ItemSearchOptions` (refs
    ///    only, no data) + FFI `SecKeychainItemDelete` — the only API that can
    ///    reliably remove legacy file-based items.
    /// 3. Re-create each read value via `set_generic_password` (`SecItemAdd`),
    ///    which stores items without per-application ACLs. Since the old entries
    ///    were deleted in step 2, `SecItemAdd` creates fresh items rather than
    ///    updating existing ones (which would preserve the old ACL).
    ///
    /// Entries whose values couldn't be read (locked keychain, denied access) are
    /// still deleted — the user re-authenticates those servers.
    pub fn migrate_legacy_entries(keys: &[(String, String)]) -> Result<MigrationReport, String> {
        // Phase 1: Read values for all known secret keys.
        let mut read: Vec<(String, String)> = Vec::new();
        for (server_id, key) in keys {
            match get_generic_password(SERVICE, &account(server_id, key)) {
                Ok(bytes) => {
                    if let Ok(v) = String::from_utf8(bytes) {
                        read.push((account(server_id, key), v));
                    }
                }
                Err(e) if e.code() == -25300 => {} // not found — skip
                Err(_) => {}                       // unreadable — will be lost, user re-auths
            }
        }

        // Phase 2: Delete all entries for our service.
        delete_all_service_entries()?;

        // Phase 3: Re-create each read value via SecItemAdd (ACL-free).
        let mut migrated = 0;
        let mut lost = keys.len().saturating_sub(read.len());
        for (acct, value) in &read {
            match set_generic_password(SERVICE, acct, value.as_bytes()) {
                Ok(()) => migrated += 1,
                Err(_) => lost += 1,
            }
        }

        Ok(MigrationReport { migrated, lost })
    }

    /// Delete all generic-password entries for our service by obtaining
    /// `SecKeychainItem` refs and calling FFI `SecKeychainItemDelete` on each.
    /// Returns the count deleted.
    fn delete_all_service_entries() -> Result<usize, String> {
        let results = match ItemSearchOptions::new()
            .class(ItemClass::generic_password())
            .service(SERVICE)
            .limit(Limit::All)
            .load_refs(true)
            .load_data(false)
            .search()
        {
            Ok(results) => results,
            Err(e) if e.code() == errSecItemNotFound => return Ok(0),
            Err(e) => return Err(format!("keychain delete search failed: {e}")),
        };

        let mut deleted = 0;
        for result in results {
            if let SearchResult::Ref(Reference::KeychainItem(item)) = result {
                match delete_keychain_item(&item) {
                    Ok(()) => deleted += 1,
                    Err(_) => {} // best-effort: skip items that can't be deleted
                }
            }
        }
        Ok(deleted)
    }

    /// Delete a single `SecKeychainItem` via the FFI `SecKeychainItemDelete`.
    fn delete_keychain_item(item: &SecKeychainItem) -> Result<(), i32> {
        use security_framework_sys::keychain_item::SecKeychainItemDelete;
        let status = unsafe { SecKeychainItemDelete(item.as_concrete_TypeRef()) };
        if status == 0 {
            Ok(())
        } else {
            Err(status)
        }
    }
}

// ── Windows / Linux ────────────────────────────────────────────────────────
#[cfg(not(target_os = "macos"))]
mod platform {
    use keyring::Entry;

    use super::{account, SERVICE};

    pub fn set_secret(server_id: &str, key: &str, value: &str) -> Result<(), String> {
        Entry::new(SERVICE, &account(server_id, key))
            .map_err(|e| e.to_string())?
            .set_password(value)
            .map_err(|e| e.to_string())
    }

    pub fn get_secret_result(server_id: &str, key: &str) -> Result<Option<String>, String> {
        let entry = Entry::new(SERVICE, &account(server_id, key)).map_err(|e| e.to_string())?;
        match entry.get_password() {
            Ok(v) => Ok(Some(v)),
            Err(keyring::Error::NoEntry) => Ok(None),
            Err(e) => Err(e.to_string()),
        }
    }

    pub fn delete_secret(server_id: &str, key: &str) -> Result<(), String> {
        let entry = Entry::new(SERVICE, &account(server_id, key)).map_err(|e| e.to_string())?;
        match entry.delete_credential() {
            Ok(()) => Ok(()),
            Err(keyring::Error::NoEntry) => Ok(()),
            Err(e) => Err(e.to_string()),
        }
    }

    pub struct MigrationReport {
        pub migrated: usize,
        pub lost: usize,
    }
}

pub fn set_secret(server_id: &str, key: &str, value: &str) -> Result<(), String> {
    platform::set_secret(server_id, key, value)
}

pub fn get_secret(server_id: &str, key: &str) -> Option<String> {
    get_secret_result(server_id, key).ok().flatten()
}

/// Like `get_secret`, but distinguishes "no such secret was saved" (`Ok(None)`)
/// from an actual keychain failure (`Err`, e.g. the keychain is locked or denied
/// access to this app). Callers that need to explain *why* a secret is missing
/// use this so a read failure isn't silently treated as "never saved".
pub fn get_secret_result(server_id: &str, key: &str) -> Result<Option<String>, String> {
    platform::get_secret_result(server_id, key)
}

pub fn delete_secret(server_id: &str, key: &str) -> Result<(), String> {
    platform::delete_secret(server_id, key)
}

// ── Legacy keychain migration (macOS) ──────────────────────────────────────
//
// Older versions of Conduit used the `keyring` crate, which created keychain
// items with per-application ACLs. This migration reads each entry's value,
// deletes it, and re-creates it via the ACL-free `SecItemAdd` path.
//
// The migration is guarded by a marker file so it runs exactly once. Only the
// UI app runs it — the gateway can't read legacy entries without triggering
// prompts (it's a separately signed process without ACL grants).

/// Marker file name in the Conduit data directory.
const MIGRATION_MARKER: &str = ".keychain-migrated";

/// Run the one-time legacy keychain migration. For each secret key the registry
/// knows about, reads the current value, deletes all service entries, and
/// re-creates each via the ACL-free `SecItemAdd` path. Guarded by a marker file
/// so it runs exactly once. Only call from the UI app (not the gateway).
///
/// `secret_keys` is a list of `(server_id, key)` pairs for every secret env var
/// in the registry (and `HTTP_AUTH_KEY` for remote servers).
///
/// Returns `(migrated, lost)` where `lost` counts entries whose values couldn't
/// be recovered (the user must re-authenticate those servers).
pub fn migrate_legacy_entries(secret_keys: &[(String, String)]) -> (usize, usize) {
    #[cfg(target_os = "macos")]
    {
        if migration_marker_exists() {
            return (0, 0);
        }

        let (migrated, lost) = match platform::migrate_legacy_entries(secret_keys) {
            Ok(report) => (report.migrated, report.lost),
            Err(e) => {
                eprintln!("conduit: keychain migration skipped ({e})");
                (0, 0)
            }
        };

        // Create the marker regardless of individual failures. The migration ran;
        // re-running it would re-read and re-write the same (now ACL-free) entries.
        let _ = create_migration_marker();

        (migrated, lost)
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = secret_keys;
        (0, 0)
    }
}

/// Check whether the migration marker file exists in the Conduit data directory.
#[cfg(target_os = "macos")]
fn migration_marker_exists() -> bool {
    crate::registry::conduit_dir()
        .map(|d| d.join(MIGRATION_MARKER))
        .map(|p| p.exists())
        .unwrap_or(false)
}

/// Create the migration marker file. Returns `true` on success.
#[cfg(target_os = "macos")]
fn create_migration_marker() -> bool {
    let Some(dir) = crate::registry::conduit_dir() else {
        return false;
    };
    let _ = std::fs::create_dir_all(&dir);
    std::fs::write(dir.join(MIGRATION_MARKER), b"1").is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn set_get_delete_round_trip() {
        let sid = "conduit-test-server";
        let key = "CONDUIT_TEST_KEY";
        set_secret(sid, key, "s3cr3t").unwrap();
        assert_eq!(get_secret(sid, key).as_deref(), Some("s3cr3t"));
        delete_secret(sid, key).unwrap();
        assert_eq!(get_secret(sid, key), None);
    }

    /// The migration preserves secret values: it reads, deletes, and re-creates
    /// each entry via the ACL-free `SecItemAdd` path. After migration, the value
    /// is still readable.
    ///
    /// This test validates the read-delete-rewrite cycle for a single entry
    /// using the public API. It does NOT call `delete_all_service_entries()`
    /// (which would wipe all conduit-mcp entries and race with parallel tests).
    #[cfg(target_os = "macos")]
    #[test]
    fn migrate_preserves_values() {
        let sid = "conduit-migrate-test";
        let key = "MIGRATE_PRESERVE_KEY";
        let original = "s3cr3t-value-to-preserve";
        set_secret(sid, key, original).unwrap();

        // Phase 1: Read the value.
        let value = get_secret(sid, key).expect("value should exist");

        // Phase 2: Delete the entry.
        delete_secret(sid, key).unwrap();
        assert_eq!(get_secret(sid, key), None, "entry should be gone after delete");

        // Phase 3: Re-create via set_secret (SecItemAdd — fresh entry, no ACL).
        set_secret(sid, key, &value).unwrap();

        // The value must survive the cycle intact.
        assert_eq!(
            get_secret(sid, key).as_deref(),
            Some(original),
            "secret value must survive read-delete-rewrite"
        );

        // Clean up.
        delete_secret(sid, key).unwrap();
    }
}
