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
// `SecItemAdd` path. This is best-effort: if the rewrite fails, the legacy item
// is restored when possible and the marker stays unset so the migration retries.
// After a successful migration, both the app and gateway read silently.
#[cfg(target_os = "macos")]
mod platform {
    use core_foundation::base::TCFType;
    use keyring::Entry;
    use security_framework::item::{ItemClass, ItemSearchOptions, Limit, Reference, SearchResult};
    use security_framework::os::macos::keychain_item::SecKeychainItem;
    use security_framework::passwords::{
        delete_generic_password, get_generic_password, set_generic_password,
    };
    use security_framework_sys::base::errSecItemNotFound;

    use super::{account, SERVICE};

    pub fn set_secret(server_id: &str, key: &str, value: &str) -> Result<(), String> {
        let acct = account(server_id, key);
        // Store via the modern `SecItemAdd` path (no kSecAttrAccess). Items created
        // this way have NO per-application ACL, so any process running as the user
        // can read them silently — including the separately-signed `conduit-gateway`
        // binary. This is "set it and forget it": the permission survives app
        // updates because there is no code-signature-based ACL to invalidate.
        //
        // Previous versions attached a shared-access ACL via SecAccessCreate +
        // kSecAttrAccess to let the gateway read without a prompt. That worked on
        // the first launch, but every app update changed the binary's code signature
        // and invalidated the ACL's trusted-app list, causing macOS to prompt for
        // the keychain password on every startup.
        set_generic_password(SERVICE, &acct, value.as_bytes()).map_err(|e| e.to_string())
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
                        // Delete just this entry, then rewrite via set_secret, which
                        // stores it via the ACL-free path. Per-account scoping
                        // means an interruption costs one key, not the keychain.
                        match delete_entry_by_account(&acct) {
                            // Ok(0): no legacy file-based item found. The value was
                            // readable via get_generic_password, so it already lives
                            // in the ACL-free SecItem store. Count as migrated.
                            Ok(0) => migrated += 1,
                            Ok(_) => match set_secret(server_id, key, &value) {
                                Ok(()) => migrated += 1,
                                Err(_) => {
                                    // Best-effort rollback: if the ACL-free write fails,
                                    // restore the legacy item so we do not silently lose
                                    // the secret before the marker is withheld.
                                    let _ = Entry::new(SERVICE, &acct)
                                        .and_then(|entry| entry.set_password(&value));
                                    failed += 1;
                                }
                            },
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
// items with per-application ACLs. A later version created items via
// `add_with_shared_access`, which ALSO attached a code-signature-based ACL.
// Both approaches cause repeated password prompts on app updates.
//
// This migration reads each entry's value, deletes it, and re-creates it via
// the ACL-free `SecItemAdd` path. It is guarded by a marker file so it runs
// once per marker version. Only the UI app runs it — the gateway can't rewrite
// entries without triggering prompts (it's a separately signed process).
// Bumping the marker name (".keychain-acl-migrated" → ".keychain-acl-stripped")
// makes the migration re-run once on upgrade so EXISTING secrets are rewritten
// ACL-free.

/// Marker file name in the Conduit data directory. Only the macOS migration reads
/// it, so it's cfg-gated to avoid a dead-code warning on Windows/Linux builds.
///
/// Bumped from `.keychain-acl-migrated` → `.keychain-acl-stripped` so the
/// migration re-runs once on upgrade. The prior version created items WITH a
/// shared-access ACL (via `add_with_shared_access`); this run rewrites them
/// ACL-free so app updates no longer invalidate the trusted-app list and cause
/// repeated password prompts.
#[cfg(target_os = "macos")]
const MIGRATION_MARKER: &str = ".keychain-acl-stripped";

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
/// The marker file is written only when the platform migration reports zero
/// migration failures. If any key could not be safely re-written, the marker is
/// not written and the migration retries on the next launch.
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

        if report.failed == 0 {
            let _ = create_migration_marker();
        }
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
    use serial_test::serial;

    // Round-trips through the real OS keychain. Headless Linux CI has no Secret
    // Service (D-Bus), so skip it there; it still runs on macOS and Windows.
    #[test]
    #[cfg_attr(target_os = "linux", ignore = "no Secret Service in headless CI")]
    #[serial]
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
    #[serial]
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

    /// The migration is idempotent: running it a second time over already-migrated
    /// (ACL-free) entries re-reads, re-deletes, and re-creates them without data
    /// loss. This exercises the path where the new marker triggers a re-run on
    /// entries that were already written via the ACL-free path.
    #[cfg(target_os = "macos")]
    #[test]
    #[serial]
    fn migrate_is_idempotent() {
        let sid = "conduit-idempotent-test";
        let key = "IDEMPOTENT_KEY";
        let original = "idempotent-secret-value";

        set_secret(sid, key, original).unwrap();
        let keys = vec![(sid.to_string(), key.to_string())];

        // First migration.
        let r1 = platform::migrate_legacy_entries(&keys).expect("first migration");
        assert_eq!(r1.migrated, 1);
        assert_eq!(get_secret(sid, key).as_deref(), Some(original));

        // Second migration — same entry, should produce the same result.
        let r2 = platform::migrate_legacy_entries(&keys).expect("second migration");
        assert_eq!(r2.migrated, 1, "re-migration should rewrite the entry again");
        assert_eq!(get_secret(sid, key).as_deref(), Some(original));

        delete_secret(sid, key).unwrap();
    }

    /// Setting the same key twice overwrites the old value. The SecItemUpdate path
    /// inside set_generic_password must not create a duplicate or preserve the
    /// old value.
    #[test]
    #[cfg_attr(target_os = "linux", ignore = "no Secret Service in headless CI")]
    #[serial]
    fn set_secret_overwrites_existing() {
        let sid = "conduit-overwrite-test";
        let key = "OVERWRITE_KEY";
        set_secret(sid, key, "first").unwrap();
        set_secret(sid, key, "second").unwrap();
        assert_eq!(
            get_secret(sid, key).as_deref(),
            Some("second"),
            "second write must overwrite the first"
        );
        delete_secret(sid, key).unwrap();
    }

    /// Deleting a key that doesn't exist must succeed (idempotent delete), not error.
    #[test]
    #[cfg_attr(target_os = "linux", ignore = "no Secret Service in headless CI")]
    #[serial]
    fn delete_missing_key_is_ok() {
        let sid = "conduit-delete-missing-test";
        let key = "THIS_KEY_NEVER_EXISTED";
        // Delete twice — both should succeed.
        delete_secret(sid, key).unwrap();
        delete_secret(sid, key).unwrap();
    }

    /// An empty-string value round-trips through the keychain. macOS's SecItem
    /// path treats empty data as a valid value; this confirms our code does too.
    #[test]
    #[cfg_attr(target_os = "linux", ignore = "no Secret Service in headless CI")]
    #[serial]
    fn empty_string_value_round_trips() {
        let sid = "conduit-empty-test";
        let key = "EMPTY_VALUE_KEY";
        set_secret(sid, key, "").unwrap();
        assert_eq!(
            get_secret(sid, key).as_deref(),
            Some(""),
            "empty string must round-trip"
        );
        delete_secret(sid, key).unwrap();
    }

    /// The migration handles an empty key list gracefully (no-op, no error).
    #[cfg(target_os = "macos")]
    #[test]
    #[serial]
    fn migrate_empty_key_list() {
        let report = platform::migrate_legacy_entries(&[])
            .expect("empty migration should succeed");
        assert_eq!(report.migrated, 0);
        assert_eq!(report.failed, 0);
        assert_eq!(report.not_found, 0);
    }

    /// Multiple keys for the same server are migrated independently. Each key
    /// is read, deleted, and re-created on its own; an interruption in one does
    /// not corrupt the others.
    #[cfg(target_os = "macos")]
    #[test]
    #[serial]
    fn migrate_handles_multiple_keys_for_one_server() {
        let sid = "conduit-multi-key-test";
        let keys = vec![
            (sid.to_string(), "KEY_A".to_string()),
            (sid.to_string(), "KEY_B".to_string()),
            (sid.to_string(), "KEY_C".to_string()),
        ];
        set_secret(sid, "KEY_A", "value-a").unwrap();
        set_secret(sid, "KEY_B", "value-b").unwrap();
        set_secret(sid, "KEY_C", "value-c").unwrap();

        let report = platform::migrate_legacy_entries(&keys).expect("migration");
        assert_eq!(report.migrated, 3, "all three keys migrated");
        assert_eq!(report.failed, 0);

        assert_eq!(get_secret(sid, "KEY_A").as_deref(), Some("value-a"));
        assert_eq!(get_secret(sid, "KEY_B").as_deref(), Some("value-b"));
        assert_eq!(get_secret(sid, "KEY_C").as_deref(), Some("value-c"));

        delete_secret(sid, "KEY_A").unwrap();
        delete_secret(sid, "KEY_B").unwrap();
        delete_secret(sid, "KEY_C").unwrap();
    }

    /// The migration correctly reports `not_found` for keys that don't exist in
    /// the keychain (e.g. `__oauth_state__` on a non-OAuth server). This should
    /// not be counted as a failure.
    #[cfg(target_os = "macos")]
    #[test]
    #[serial]
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

    /// When a value is readable but there's no legacy file-based item to delete
    /// (Ok(0) from delete_entry_by_account), the item already lives in the ACL-free
    /// SecItem store. The migration must count it as migrated, not failed — otherwise
    /// already-migrated entries would cause the marker to never be written on re-run.
    #[cfg(target_os = "macos")]
    #[test]
    #[serial]
    fn migrate_counts_already_aclfree_as_migrated() {
        let sid = "conduit-already-migrated-test";
        let key = "ALREADY_FREE_KEY";
        let value = "already-acl-free-value";

        // Write via set_secret, which uses the ACL-free SecItemAdd path.
        set_secret(sid, key, value).unwrap();

        // Run the migration: it will read the value, find no legacy item to
        // delete (Ok(0)), and must count this as migrated — not failed.
        let keys = vec![(sid.to_string(), key.to_string())];
        let report = platform::migrate_legacy_entries(&keys).expect("migration should succeed");

        assert_eq!(
            report.migrated, 1,
            "already-ACL-free item must count as migrated"
        );
        assert_eq!(report.failed, 0, "no failures for already-clean items");
        assert_eq!(get_secret(sid, key).as_deref(), Some(value));

        delete_secret(sid, key).unwrap();
    }
}
