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
        // Preferred path: create the item WITH a shared-access ACL (this app + the
        // gateway) in one atomic SecItemAdd. Setting the ACL at creation needs no
        // prompt; setting it AFTER creation (SecKeychainItemSetAccess) prompts for
        // the keychain password. With the ACL in place the separately-signed gateway
        // reads the secret with no prompt either.
        match add_with_shared_access(&acct, value) {
            Ok(()) => Ok(()),
            Err(e) => {
                // Never let secret storage fail: fall back to the plain ACL-free
                // write (the gateway then falls back to a one-time "Always Allow").
                eprintln!("conduit: shared-access write failed ({e}); using plain write");
                let _ = delete_generic_password(SERVICE, &acct);
                set_generic_password(SERVICE, &acct, value.as_bytes()).map_err(|e| e.to_string())
            }
        }
    }

    /// Create a generic-password item that BOTH the Conduit app and the
    /// `conduit-gateway` binary can read with no keychain prompt: build a legacy
    /// `SecAccess` whose trusted-applications list names both binaries and pass it
    /// as `kSecAttrAccess` on `SecItemAdd`. Setting the ACL atomically at creation
    /// avoids the keychain-password prompt that a post-hoc `SecKeychainItemSetAccess`
    /// would raise.
    ///
    /// Why this and not `keychain-access-groups`: that's a *restricted* entitlement
    /// requiring an embedded provisioning profile, which a bare CLI binary (the
    /// gateway, spawned standalone by clients) cannot carry, so AMFI SIGKILLs it at
    /// launch (-34018 / amfid -413). The legacy trusted-application ACL works for
    /// Developer ID distribution with no profile. APIs are deprecated-but-functional.
    fn add_with_shared_access(account_str: &str, value: &str) -> Result<(), String> {
        use core_foundation::array::CFArray;
        use core_foundation::base::{CFType, CFTypeRef, TCFType};
        use core_foundation::data::CFData;
        use core_foundation::dictionary::CFDictionary;
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
            fn SecItemAdd(attributes: *const c_void, result: *mut *const c_void) -> i32;
            fn SecItemDelete(query: *const c_void) -> i32;
            static kSecClass: CFTypeRef;
            static kSecClassGenericPassword: CFTypeRef;
            static kSecAttrService: CFTypeRef;
            static kSecAttrAccount: CFTypeRef;
            static kSecValueData: CFTypeRef;
            static kSecAttrAccess: CFTypeRef;
        }

        // 1. Build a SecAccess trusting the two binaries (this app + the gateway).
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
        let access_cf = unsafe { CFType::wrap_under_create_rule(access as CFTypeRef) };

        // The kSec* keys are CFString constants; pull them into safe CFType values.
        let (k_class, k_generic, k_service, k_account, k_value, k_access) = unsafe {
            (
                CFType::wrap_under_get_rule(kSecClass),
                CFType::wrap_under_get_rule(kSecClassGenericPassword),
                CFType::wrap_under_get_rule(kSecAttrService),
                CFType::wrap_under_get_rule(kSecAttrAccount),
                CFType::wrap_under_get_rule(kSecValueData),
                CFType::wrap_under_get_rule(kSecAttrAccess),
            )
        };
        let service_cf = CFString::new(SERVICE).as_CFType();
        let account_cf = CFString::new(account_str).as_CFType();

        // 2. Remove any existing item for this account (SecItemAdd rejects dups).
        let del = CFDictionary::from_CFType_pairs(&[
            (k_class.clone(), k_generic.clone()),
            (k_service.clone(), service_cf.clone()),
            (k_account.clone(), account_cf.clone()),
        ]);
        unsafe {
            SecItemDelete(del.as_concrete_TypeRef() as *const c_void);
        }

        // 3. Add the item WITH the shared-access ACL, atomically (no prompt).
        let data_cf = CFData::from_buffer(value.as_bytes()).as_CFType();
        let add = CFDictionary::from_CFType_pairs(&[
            (k_class, k_generic),
            (k_service, service_cf),
            (k_account, account_cf),
            (k_value, data_cf),
            (k_access, access_cf),
        ]);
        let st = unsafe {
            SecItemAdd(add.as_concrete_TypeRef() as *const c_void, std::ptr::null_mut())
        };
        if st != 0 {
            return Err(format!("SecItemAdd with shared access failed: {st}"));
        }
        Ok(())
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
                        // recreates it WITH the shared-access ACL (app + gateway) so
                        // the gateway reads it with no prompt. Per-account scoping
                        // means an interruption costs one key, not the keychain.
                        let _ = delete_entry_by_account(&acct);
                        match set_secret(server_id, key, &value) {
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

/// Encrypted-file secret backend for headless / no-keychain environments. It is
/// activated by setting `CONDUIT_SECRET_KEY` to any non-empty string: a 32-byte key is
/// derived from it (SHA-256) and secrets live in `secrets.enc` as one XChaCha20-Poly1305
/// sealed JSON map, re-sealed on every write. With the env var unset the OS keychain is
/// used exactly as before, so desktop installs are untouched. The same env var must be
/// present for both the app (writes) and the gateway (reads).
mod file {
    use super::account;
    use base64::Engine;
    use chacha20poly1305::aead::{Aead, KeyInit};
    use chacha20poly1305::{XChaCha20Poly1305, XNonce};
    use sha2::{Digest, Sha256};
    use std::collections::BTreeMap;
    use std::path::PathBuf;

    const NONCE_LEN: usize = 24;

    /// account -> secret value.
    type Store = BTreeMap<String, String>;

    /// The 32-byte key derived from `CONDUIT_SECRET_KEY`, or None when it's unset/empty
    /// (the signal to use the OS keychain instead).
    fn key_material() -> Option<[u8; 32]> {
        let secret = std::env::var("CONDUIT_SECRET_KEY").ok()?;
        if secret.is_empty() {
            return None;
        }
        let mut key = [0u8; 32];
        key.copy_from_slice(&Sha256::digest(secret.as_bytes()));
        Some(key)
    }

    pub fn active() -> bool {
        key_material().is_some()
    }

    fn path() -> Result<PathBuf, String> {
        crate::registry::conduit_dir()
            .map(|d| d.join("secrets.enc"))
            .ok_or_else(|| "no conduit data directory".to_string())
    }

    /// Seal `plain` as base64(`nonce` || ciphertext) under `key` with a fresh nonce.
    pub(super) fn seal(key: &[u8; 32], plain: &[u8]) -> Result<String, String> {
        let cipher = XChaCha20Poly1305::new_from_slice(key).map_err(|e| e.to_string())?;
        let mut nonce = [0u8; NONCE_LEN];
        getrandom::getrandom(&mut nonce).map_err(|e| e.to_string())?;
        let ct = cipher
            .encrypt(XNonce::from_slice(&nonce), plain)
            .map_err(|_| "encryption failed".to_string())?;
        let mut blob = nonce.to_vec();
        blob.extend_from_slice(&ct);
        Ok(base64::engine::general_purpose::STANDARD.encode(&blob))
    }

    /// Reverse of `seal`: authenticate and decrypt. Fails on a wrong key or tamper.
    pub(super) fn open(key: &[u8; 32], encoded: &str) -> Result<Vec<u8>, String> {
        let blob = base64::engine::general_purpose::STANDARD
            .decode(encoded.trim())
            .map_err(|e| e.to_string())?;
        if blob.len() < NONCE_LEN {
            return Err("secrets.enc is truncated or corrupt".to_string());
        }
        let (nonce, ct) = blob.split_at(NONCE_LEN);
        let cipher = XChaCha20Poly1305::new_from_slice(key).map_err(|e| e.to_string())?;
        cipher
            .decrypt(XNonce::from_slice(nonce), ct)
            .map_err(|_| "could not decrypt secrets.enc (wrong CONDUIT_SECRET_KEY?)".to_string())
    }

    fn load() -> Result<Store, String> {
        let key = key_material().ok_or("CONDUIT_SECRET_KEY is not set")?;
        let encoded = match std::fs::read_to_string(path()?) {
            Ok(s) => s,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Store::new()),
            Err(e) => return Err(e.to_string()),
        };
        serde_json::from_slice(&open(&key, &encoded)?).map_err(|e| e.to_string())
    }

    fn save(store: &Store) -> Result<(), String> {
        let key = key_material().ok_or("CONDUIT_SECRET_KEY is not set")?;
        let plain = serde_json::to_vec(store).map_err(|e| e.to_string())?;
        crate::registry::atomic_write(&path()?, &seal(&key, &plain)?)
    }

    pub fn set_secret(server_id: &str, key: &str, value: &str) -> Result<(), String> {
        let mut store = load()?;
        store.insert(account(server_id, key), value.to_string());
        save(&store)
    }

    pub fn get_secret_result(server_id: &str, key: &str) -> Result<Option<String>, String> {
        Ok(load()?.get(&account(server_id, key)).cloned())
    }

    pub fn delete_secret(server_id: &str, key: &str) -> Result<(), String> {
        let mut store = load()?;
        if store.remove(&account(server_id, key)).is_some() {
            save(&store)?;
        }
        Ok(())
    }
}

pub fn set_secret(server_id: &str, key: &str, value: &str) -> Result<(), String> {
    if file::active() {
        return file::set_secret(server_id, key, value);
    }
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
    if file::active() {
        return file::get_secret_result(server_id, key);
    }
    platform::get_secret_result(server_id, key)
}

pub fn delete_secret(server_id: &str, key: &str) -> Result<(), String> {
    if file::active() {
        return file::delete_secret(server_id, key);
    }
    platform::delete_secret(server_id, key)
}

// ── Legacy keychain migration (macOS) ──────────────────────────────────────
//
// Older versions of Conduit used the `keyring` crate, which created keychain
// items with per-application ACLs. This migration reads each entry's value,
// deletes it, and re-creates it via the ACL-free `SecItemAdd` path.
//
// The migration is guarded by a marker file so it runs once per marker version.
// Only the UI app runs it — the gateway can't rewrite entries without triggering
// prompts (it's a separately signed process). Bumping the marker name
// (".keychain-migrated" -> ".keychain-acl-migrated") makes the migration re-run
// once on upgrade so EXISTING secrets are rewritten WITH the shared-access ACL,
// not just legacy keyring-API entries.

/// Marker file name in the Conduit data directory. Only the macOS migration reads
/// it, so it's cfg-gated to avoid a dead-code warning on Windows/Linux builds.
#[cfg(target_os = "macos")]
const MIGRATION_MARKER: &str = ".keychain-acl-migrated";

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

    #[test]
    fn file_backend_seal_open_round_trip() {
        let key = [7u8; 32];
        let sealed = file::seal(&key, b"s3cr3t value").unwrap();
        // A fresh nonce per seal means the same plaintext seals to different bytes.
        assert_ne!(sealed, file::seal(&key, b"s3cr3t value").unwrap());
        // The right key recovers the plaintext; a wrong key is rejected.
        assert_eq!(file::open(&key, &sealed).unwrap(), b"s3cr3t value");
        let mut wrong = key;
        wrong[0] ^= 0xff;
        assert!(file::open(&wrong, &sealed).is_err());
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
