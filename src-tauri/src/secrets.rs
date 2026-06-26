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
// Conduit stores secrets in the macOS **Data Protection keychain** (the modern
// keychain used by iOS and by macOS apps built against the 10.15+ SDK). Items
// in this keychain have **no per-application ACLs** and **no file-based keychain
// prompts** — any process running as the user can read them after a single
// unlock. This is what eliminates the repeated password prompts that plagued
// the older `keyring`-based storage.
//
// Older versions of Conduit used the `keyring` crate, which routes through the
// legacy file-based keychain API (`SecKeychainAddGenericPassword`). That API
// attaches per-application ACLs, and even the ACL-free `SecItemAdd` path (PR #21)
// still lands in the file-based keychain unless `kSecUseDataProtectionKeychain`
// is set — which requires the `OSX_10_15` feature on the `security-framework`
// crate.
//
// `migrate_legacy_entries()` runs once at app startup (guarded by a marker file)
// to move entries from the file-based keychain to the DataProtection keychain.
#[cfg(target_os = "macos")]
mod platform {
    use core_foundation::base::TCFType;
    use security_framework::item::{ItemClass, ItemSearchOptions, Limit, Reference, SearchResult};
    use security_framework::os::macos::keychain_item::SecKeychainItem;
    use security_framework::passwords::{
        delete_generic_password_options, generic_password, get_generic_password,
        set_generic_password_options,
    };
    use security_framework::passwords_options::PasswordOptions;
    use security_framework_sys::base::errSecItemNotFound;

    use super::{account, SERVICE};

    /// Build `PasswordOptions` that target the DataProtection keychain
    /// (`kSecUseDataProtectionKeychain = true`). Items in this keychain have
    /// no per-application ACLs and don't trigger keychain prompts — any
    /// process running as the user can read them after a single unlock.
    fn dp_options(service: &str, acct: &str) -> PasswordOptions {
        let mut opts = PasswordOptions::new_generic_password(service, acct);
        opts.use_protected_keychain();
        opts
    }

    pub fn set_secret(server_id: &str, key: &str, value: &str) -> Result<(), String> {
        let opts = dp_options(SERVICE, &account(server_id, key));
        set_generic_password_options(value.as_bytes(), opts).map_err(|e| e.to_string())
    }

    pub fn get_secret_result(server_id: &str, key: &str) -> Result<Option<String>, String> {
        let opts = dp_options(SERVICE, &account(server_id, key));
        match generic_password(opts) {
            Ok(bytes) => String::from_utf8(bytes).map(Some).map_err(|e| e.to_string()),
            Err(e) if e.code() == errSecItemNotFound => Ok(None),
            Err(e) => Err(e.to_string()),
        }
    }

    pub fn delete_secret(server_id: &str, key: &str) -> Result<(), String> {
        let opts = dp_options(SERVICE, &account(server_id, key));
        match delete_generic_password_options(opts) {
            Ok(()) => Ok(()),
            Err(e) if e.code() == errSecItemNotFound => Ok(()),
            Err(e) => Err(e.to_string()),
        }
    }

    // ── Migration ──────────────────────────────────────────────────────────

    /// Migrate all `conduit-mcp` keychain entries from the legacy file-based
    /// keychain to the DataProtection keychain.
    ///
    /// **Algorithm (per-key read-delete-rewrite):**
    ///
    /// For each `(server_id, key)` pair:
    /// 1. **Read** the value from the *file-based* keychain (no DP flag) via
    ///    `get_generic_password`. This finds entries created by older versions
    ///    of Conduit (ACL-bearing or ACL-free in the file-based keychain). On
    ///    macOS 12+, a unified search may also find DP entries as a fallback;
    ///    this is safe (see comment below).
    /// 2. **Delete** the file-based entry by account-filtered ref search +
    ///    FFI `SecKeychainItemDelete`.
    /// 3. **Re-create** the value via `set_secret` (DP keychain). This creates
    ///    a fresh item in the DP keychain — no ACLs, no prompts.
    ///
    /// Keys that don't exist in the file-based keychain are counted as
    /// `not_found`, not a failure.
    pub fn migrate_legacy_entries(
        keys: &[(String, String)],
    ) -> Result<super::MigrationReport, String> {
        let mut migrated = 0;
        let mut failed = 0;
        let mut not_found = 0;

        for (server_id, key) in keys {
            let acct = account(server_id, key);

            // Read from the file-based keychain (no DP flag). On macOS 12+,
            // SecItemCopyMatching may perform a unified search that also finds
            // DP entries as a fallback if no file-based item exists. This is
            // safe: the delete step targets only file-based items (DP items
            // have no SecKeychainItemRef), and the rewrite via set_secret
            // hits SecItemUpdate on any existing DP item rather than creating
            // a duplicate.
            match get_generic_password(SERVICE, &acct) {
                Ok(bytes) => match String::from_utf8(bytes) {
                    Ok(value) => {
                        // Delete the file-based entry, then rewrite to DP.
                        let _ = delete_entry_by_account(&acct);
                        match set_secret(server_id, key, &value) {
                            Ok(()) => migrated += 1,
                            Err(_) => failed += 1,
                        }
                    }
                    Err(_) => failed += 1, // non-UTF-8 value — can't round-trip
                },
                Err(e) if e.code() == errSecItemNotFound => not_found += 1, // expected for reserved keys
                Err(_) => failed += 1,                          // locked keychain, denied access
            }
        }

        Ok(super::MigrationReport {
            migrated,
            failed,
            not_found,
        })
    }

    /// Delete all generic-password entries matching a specific account string
    /// from the **file-based** keychain. Uses an account-filtered ref search +
    /// FFI `SecKeychainItemDelete` — the only API that can reliably remove
    /// legacy file-based items (`SecItemDelete` returns `errSecAuthFailed` for
    /// ACL-bearing entries on some macOS versions).
    ///
    /// Does NOT search the DP keychain — DP entries are deleted via
    /// `delete_secret` (which uses `SecItemDelete` with the DP flag).
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
// items with per-application ACLs. PR #21 switched to `SecItemAdd` (ACL-free)
// and PR #26 added a one-time migration to rewrite existing entries. But
// without the `OSX_10_15` feature, `SecItemAdd` still writes to the file-based
// keychain, which prompts on cross-process access.
//
// This migration (the second) moves entries from the file-based keychain to
// the DataProtection keychain via `kSecUseDataProtectionKeychain`. This is the
// only path that eliminates cross-process prompts entirely.
//
// The migration is guarded by a marker file so it runs exactly once. Only the
// UI app runs it — the gateway can't read legacy entries without triggering
// prompts (it's a separately signed process without ACL grants).

/// Marker file name in the Conduit data directory. Only the macOS migration
/// reads it, so it's cfg-gated to avoid a dead-code warning on Windows/Linux
/// builds.
///
/// This is the **second** migration marker — the first (`.keychain-migrated`
/// from PR #26) moved entries from ACL-bearing to ACL-free but still within the
/// file-based keychain. This one moves them to the DataProtection keychain,
/// which is the only path that eliminates cross-process prompts entirely.
#[cfg(target_os = "macos")]
const MIGRATION_MARKER: &str = ".keychain-dp-migrated";

/// Result of the one-time keychain migration.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct MigrationReport {
    /// Entries whose values were read from the file-based keychain and
    /// re-created in the DataProtection keychain.
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
/// knows about, reads the value from the file-based keychain, deletes the
/// entry, and re-creates it via the DataProtection keychain path. Guarded by a
/// marker file so it runs exactly once. Only call from the UI app (not the
/// gateway).
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

    /// The DP keychain requires a `keychain-access-groups` entitlement on the
    /// binary. Adhoc-signed dev builds don't have it, so DP keychain operations
    /// fail with `errSecMissingEntitlement` (-34018). Tests that exercise the
    /// DP path skip gracefully when the entitlement isn't present — they can
    /// only run on a properly signed build.
    #[cfg(target_os = "macos")]
    fn dp_keychain_available() -> bool {
        match platform::set_secret("__conduit_test__", "__dp_probe__", "x") {
            Ok(()) => {
                // Clean up the probe entry. Retry once if the first delete
                // fails (transient keychain error) to avoid leaving orphans.
                if platform::delete_secret("__conduit_test__", "__dp_probe__").is_err() {
                    let _ = platform::delete_secret("__conduit_test__", "__dp_probe__");
                }
                true
            }
            Err(_) => false,
        }
    }

    #[cfg(target_os = "macos")]
    /// Write/delete to the **file-based** keychain (no DP flag). Used by tests
    /// to create legacy entries that the migration reads from.
    fn filebased_set(sid: &str, key: &str, val: &str) {
        use security_framework::passwords::set_generic_password;
        let acct = account(sid, key);
        set_generic_password(SERVICE, &acct, val.as_bytes())
            .expect("filebased_set: should write to login keychain");
    }

    #[cfg(target_os = "macos")]
    fn filebased_delete(sid: &str, key: &str) {
        use security_framework::passwords::delete_generic_password;
        let acct = account(sid, key);
        let _ = delete_generic_password(SERVICE, &acct);
    }

    #[cfg(target_os = "macos")]
    /// Write raw bytes to the file-based keychain (no DP flag). Used to inject
    /// non-UTF-8 values for testing the migration's non-UTF-8 failure path.
    fn filebased_set_bytes(sid: &str, key: &str, bytes: &[u8]) {
        use security_framework::passwords::set_generic_password;
        let acct = account(sid, key);
        set_generic_password(SERVICE, &acct, bytes)
            .expect("filebased_set_bytes: should write to login keychain");
    }

    #[test]
    fn set_get_delete_round_trip() {
        // On macOS, this exercises the DataProtection keychain path, which
        // requires a signing entitlement. Skip on adhoc-signed dev builds.
        #[cfg(target_os = "macos")]
        if !dp_keychain_available() {
            eprintln!("skipping: DP keychain not available (adhoc-signed build)");
            return;
        }
        let sid = "conduit-test-server";
        let key = "CONDUIT_TEST_KEY";
        set_secret(sid, key, "s3cr3t").unwrap();
        assert_eq!(get_secret(sid, key).as_deref(), Some("s3cr3t"));
        delete_secret(sid, key).unwrap();
        assert_eq!(get_secret(sid, key), None);
    }

    /// The migration preserves secret values: it reads from the file-based
    /// keychain, deletes the entry, and re-creates it in the DataProtection
    /// keychain. After migration, the value is readable via the DP path.
    ///
    /// This test exercises the **full platform migration function**
    /// (`platform::migrate_legacy_entries`), including the per-key
    /// delete-and-rewrite cycle. It creates a file-based entry, runs the
    /// migration for that key, and verifies the value survives in the DP
    /// keychain.
    #[cfg(target_os = "macos")]
    #[test]
    fn migrate_preserves_values() {
        if !dp_keychain_available() {
            eprintln!("skipping: DP keychain not available (adhoc-signed build)");
            return;
        }
        let sid = "conduit-migrate-test";
        let key = "MIGRATE_PRESERVE_KEY";
        let original = "s3cr3t-value-to-preserve";

        // Pre-create the entry in the **file-based** keychain (what old
        // versions of Conduit created). The migration reads from here.
        filebased_delete(sid, key); // clean any prior state
        filebased_set(sid, key, original);

        // Run the full platform migration for this one key.
        let keys = vec![(sid.to_string(), key.to_string())];
        let report = platform::migrate_legacy_entries(&keys).expect("migration should succeed");

        assert_eq!(report.migrated, 1, "one entry should have been migrated");
        assert_eq!(report.failed, 0, "no entries should have failed");
        assert_eq!(report.not_found, 0, "no entries should have been not-found");

        // The value must survive the migration, now readable from the DP keychain.
        assert_eq!(
            get_secret(sid, key).as_deref(),
            Some(original),
            "secret value must survive migration"
        );

        // Clean up both keychains.
        delete_secret(sid, key).unwrap();
        filebased_delete(sid, key);
    }

    /// The migration correctly reports `not_found` for keys that don't exist in
    /// the file-based keychain (e.g. `__oauth_state__` on a non-OAuth server).
    /// This should not be counted as a failure.
    #[cfg(target_os = "macos")]
    #[test]
    fn migrate_reports_not_found_for_missing_keys() {
        let sid = "conduit-missing-test";
        let key = "THIS_KEY_DOES_NOT_EXIST";

        // Ensure the entry doesn't exist in either keychain.
        filebased_delete(sid, key);
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

    /// The migration counts non-UTF-8 values as `failed` rather than migrating
    /// them. The file-based entry is NOT deleted in this case (the `failed`
    /// branch is reached before the delete call), so the original secret
    /// survives in the file-based keychain.
    #[cfg(target_os = "macos")]
    #[test]
    fn migrate_fails_on_non_utf8_value() {
        let sid = "conduit-nonutf8-test";
        let key = "NON_UTF8_SECRET";

        // Inject a non-UTF-8 value into the file-based keychain.
        filebased_delete(sid, key);
        filebased_set_bytes(sid, key, &[0xff, 0xfe, 0xfd]);

        let keys = vec![(sid.to_string(), key.to_string())];
        let report = platform::migrate_legacy_entries(&keys).expect("migration should succeed");

        assert_eq!(report.migrated, 0, "non-UTF-8 entry should not be migrated");
        assert_eq!(report.failed, 1, "non-UTF-8 entry should be counted as failed");
        assert_eq!(report.not_found, 0, "entry exists, should not be not-found");

        // Clean up.
        filebased_delete(sid, key);
    }
}
