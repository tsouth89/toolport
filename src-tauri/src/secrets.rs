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
        let acct = account(server_id, key);
        set_generic_password(SERVICE, &acct, value.as_bytes()).map_err(|e| e.to_string())?;
        // Grant the standalone gateway binary silent read access to this item, so a
        // client-spawned gateway reads it with no keychain prompt. Best-effort: if
        // it fails the secret is still stored, the gateway just falls back to the
        // one-time "Always Allow" prompt.
        if let Err(e) = apply_shared_access(&acct) {
            eprintln!("conduit: keychain shared-access not applied for {acct}: {e}");
        }
        Ok(())
    }

    /// Give both the Conduit app and the `conduit-gateway` binary silent read
    /// access to a keychain item by attaching a `SecAccess` whose trusted-apps list
    /// names both binaries.
    ///
    /// Why this and not `keychain-access-groups`: the modern `SecItemAdd` item is
    /// trusted only by its creator (the app), so the separately-signed gateway
    /// triggers a keychain prompt on first read. `keychain-access-groups` is the
    /// modern way to share, but it's a *restricted* entitlement that needs an
    /// embedded provisioning profile, which a bare CLI binary (the gateway, spawned
    /// standalone by clients) cannot carry, so AMFI kills it at launch (-34018 /
    /// amfid -413). The legacy trusted-application ACL works for Developer ID
    /// distribution with no profile. APIs are deprecated-but-functional.
    fn apply_shared_access(account_str: &str) -> Result<(), String> {
        use core_foundation::array::CFArray;
        use core_foundation::base::{CFType, CFTypeRef, TCFType};
        use core_foundation::string::CFString;
        use std::ffi::{c_void, CString};
        use std::os::raw::c_char;

        #[link(name = "Security", kind = "framework")]
        extern "C" {
            fn SecTrustedApplicationCreateFromPath(
                path: *const c_char,
                app: *mut *mut c_void,
            ) -> i32;
            fn SecAccessCreate(
                descriptor: *const c_void,
                trustedlist: *const c_void,
                access_ref: *mut *mut c_void,
            ) -> i32;
            fn SecKeychainItemSetAccess(item: *mut c_void, access: *mut c_void) -> i32;
        }

        // The two binaries that must read the secret silently.
        let app_path = std::env::current_exe().map_err(|e| e.to_string())?;
        let gw_path = crate::clients::resolve_gateway_path()
            .ok_or_else(|| "could not resolve gateway path".to_string())?;

        let trusted_app = |p: &std::path::Path| -> Result<CFType, String> {
            let c = CString::new(p.to_string_lossy().into_owned()).map_err(|e| e.to_string())?;
            let mut app: *mut c_void = std::ptr::null_mut();
            let st = unsafe { SecTrustedApplicationCreateFromPath(c.as_ptr(), &mut app) };
            if st != 0 || app.is_null() {
                return Err(format!(
                    "SecTrustedApplicationCreateFromPath({}) failed: {st}",
                    p.display()
                ));
            }
            Ok(unsafe { CFType::wrap_under_create_rule(app as CFTypeRef) })
        };

        let trusted = CFArray::from_CFTypes(&[trusted_app(&app_path)?, trusted_app(&gw_path)?]);
        let label = CFString::new("conduit-mcp");
        let mut access: *mut c_void = std::ptr::null_mut();
        let st = unsafe {
            SecAccessCreate(
                label.as_concrete_TypeRef() as *const c_void,
                trusted.as_concrete_TypeRef() as *const c_void,
                &mut access,
            )
        };
        if st != 0 || access.is_null() {
            return Err(format!("SecAccessCreate failed: {st}"));
        }
        // Own the access so it's released on return (SetAccess retains it itself).
        let _access_owned = unsafe { CFType::wrap_under_create_rule(access as CFTypeRef) };

        // Find the freshly written item and attach the access to it.
        let results = ItemSearchOptions::new()
            .class(ItemClass::generic_password())
            .service(SERVICE)
            .account(account_str)
            .limit(Limit::All)
            .load_refs(true)
            .load_data(false)
            .search()
            .map_err(|e| format!("acl item search failed: {e}"))?;

        let mut applied = false;
        for result in results {
            if let SearchResult::Ref(Reference::KeychainItem(item)) = result {
                let st = unsafe {
                    SecKeychainItemSetAccess(item.as_concrete_TypeRef() as *mut c_void, access)
                };
                if st != 0 {
                    return Err(format!("SecKeychainItemSetAccess failed: {st}"));
                }
                applied = true;
            }
        }
        if applied {
            Ok(())
        } else {
            Err("no keychain item found to grant shared access".into())
        }
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

    /// Migrate all `conduit-mcp` keychain entries from the legacy file-based
    /// keychain (ACL-bearing) to the ACL-free `SecItem` path.
    ///
    /// **Algorithm (per-key read-delete-rewrite):**
    ///
    /// For each `(server_id, key)` pair:
    /// 1. **Read** the current value via `get_generic_password`. Safe from the
    ///    app process, which has ACL grants from the old version.
    /// 2. **Delete** that specific entry by account-filtered ref search +
    ///    FFI `SecKeychainItemDelete` (the only API that reliably removes legacy
    ///    file-based items). Scoped to one account so an interruption costs one
    ///    key, not all of them.
    /// 3. **Re-create** the value via `set_generic_password` (`SecItemAdd`),
    ///    which stores items without per-application ACLs. Since the old entry
    ///    was just deleted, `SecItemAdd` creates a fresh item rather than hitting
    ///    `SecItemUpdate` (which would preserve the old ACL).
    ///
    /// Keys that don't exist in the keychain (e.g. `__oauth_state__` for a
    /// non-OAuth server) are counted as `not_found`, not a failure.
    pub fn migrate_legacy_entries(
        keys: &[(String, String)],
    ) -> Result<super::MigrationReport, String> {
        let mut migrated = 0;
        let mut failed = 0;
        let mut not_found = 0;

        for (server_id, key) in keys {
            let acct = account(server_id, key);
            match get_generic_password(SERVICE, &acct) {
                Ok(bytes) => match String::from_utf8(bytes) {
                    Ok(value) => {
                        // Delete just this entry, then rewrite via SecItemAdd.
                        // Per-account scoping means an interruption between delete
                        // and rewrite costs one key, not the entire keychain.
                        let _ = delete_entry_by_account(&acct);
                        match set_generic_password(SERVICE, &acct, value.as_bytes()) {
                            Ok(()) => migrated += 1,
                            Err(_) => failed += 1,
                        }
                    }
                    Err(_) => failed += 1, // non-UTF-8 value — can't round-trip
                },
                Err(e) if e.code() == -25300 => not_found += 1, // expected for reserved keys
                Err(_) => failed += 1,                          // locked keychain, denied access
            }
        }

        Ok(super::MigrationReport {
            migrated,
            failed,
            not_found,
        })
    }

    /// Delete all generic-password entries matching a specific account string.
    /// Uses an account-filtered ref search + FFI `SecKeychainItemDelete` — the
    /// only API that can reliably remove legacy file-based items (`SecItemDelete`
    /// returns `errSecAuthFailed` for ACL-bearing entries on some macOS versions).
    fn delete_entry_by_account(account_str: &str) -> Result<usize, String> {
        let results = match ItemSearchOptions::new()
            .class(ItemClass::generic_password())
            .service(SERVICE)
            .account(account_str)
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
                if delete_keychain_item(&item).is_ok() {
                    deleted += 1;
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

/// Marker file name in the Conduit data directory. Only the macOS migration reads
/// it, so it's cfg-gated to avoid a dead-code warning on Windows/Linux builds.
#[cfg(target_os = "macos")]
const MIGRATION_MARKER: &str = ".keychain-migrated";

/// Result of the one-time keychain migration.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct MigrationReport {
    /// Entries whose values were read and re-created via the ACL-free path.
    pub migrated: usize,
    /// Entries that existed but couldn't be read or re-created (locked
    /// keychain, denied access, non-UTF-8 value). The user must
    /// re-authenticate these servers.
    pub failed: usize,
    /// Keys that had no keychain entry — expected for reserved keys like
    /// `__oauth_state__` on non-OAuth servers. Not an error.
    pub not_found: usize,
}

/// Run the one-time legacy keychain migration. For each secret key the registry
/// knows about, reads the current value, deletes the entry, and re-creates it
/// via the ACL-free `SecItemAdd` path. Guarded by a marker file so it runs
/// exactly once. Only call from the UI app (not the gateway).
///
/// `secret_keys` is a list of `(server_id, key)` pairs for every secret env var
/// in the registry (and `HTTP_AUTH_KEY` for remote servers).
///
/// The marker file is **only** written when the platform migration returns `Ok`.
/// If it returns `Err` (e.g. the keychain was locked so the search failed), the
/// marker is not written and the migration retries on the next launch.
pub fn migrate_legacy_entries(secret_keys: &[(String, String)]) -> MigrationReport {
    #[cfg(target_os = "macos")]
    {
        if migration_marker_exists() {
            return MigrationReport::default();
        }

        let report = match platform::migrate_legacy_entries(secret_keys) {
            Ok(report) => report,
            Err(e) => {
                // Don't write the marker — the migration didn't run, so it
                // should retry on the next launch.
                eprintln!("conduit: keychain migration skipped, will retry next launch ({e})");
                return MigrationReport::default();
            }
        };

        let _ = create_migration_marker();
        report
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = secret_keys;
        MigrationReport::default()
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

    // Round-trips through the real OS keychain. Headless Linux CI has no Secret
    // Service (D-Bus), so skip it there; it still runs on macOS and Windows.
    #[test]
    #[cfg_attr(target_os = "linux", ignore = "no Secret Service in headless CI")]
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
    /// This test exercises the **full platform migration function**
    /// (`platform::migrate_legacy_entries`), including the per-key
    /// delete-and-rewrite cycle. It creates a test entry, runs the migration
    /// for that key, and verifies the value survives.
    #[cfg(target_os = "macos")]
    #[test]
    fn migrate_preserves_values() {
        let sid = "conduit-migrate-test";
        let key = "MIGRATE_PRESERVE_KEY";
        let original = "s3cr3t-value-to-preserve";

        // Pre-create the entry so the migration has something to migrate.
        set_secret(sid, key, original).unwrap();

        // Run the full platform migration for this one key.
        let keys = vec![(sid.to_string(), key.to_string())];
        let report = platform::migrate_legacy_entries(&keys).expect("migration should succeed");

        assert_eq!(report.migrated, 1, "one entry should have been migrated");
        assert_eq!(report.failed, 0, "no entries should have failed");
        assert_eq!(report.not_found, 0, "no entries should have been not-found");

        // The value must survive the read-delete-rewrite cycle intact.
        assert_eq!(
            get_secret(sid, key).as_deref(),
            Some(original),
            "secret value must survive migration"
        );

        // Clean up.
        delete_secret(sid, key).unwrap();
    }

    /// The migration correctly reports `not_found` for keys that don't exist in
    /// the keychain (e.g. `__oauth_state__` on a non-OAuth server). This should
    /// not be counted as a failure.
    #[cfg(target_os = "macos")]
    #[test]
    fn migrate_reports_not_found_for_missing_keys() {
        let sid = "conduit-missing-test";
        let key = "THIS_KEY_DOES_NOT_EXIST";

        // Ensure the entry doesn't exist.
        let _ = delete_secret(sid, key);

        let keys = vec![(sid.to_string(), key.to_string())];
        let report = platform::migrate_legacy_entries(&keys).expect("migration should succeed");

        assert_eq!(report.migrated, 0, "nothing to migrate");
        assert_eq!(report.failed, 0, "missing keys are not failures");
        assert_eq!(
            report.not_found, 1,
            "one key should be reported as not-found"
        );
    }
}
