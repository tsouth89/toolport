//! Secret storage in the OS keychain (Windows Credential Manager / macOS
//! Keychain / libsecret). Secret env values never live in Toolport's registry
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
// On macOS we bypass the `keyring` crate and call `security_framework` /
// `SecItem*` directly.
//
// **Per-server secret storage uses the DATA-PROTECTION keychain** with a
// team-scoped access group (`V4YZPC7T6G.com.tsout.conduit.shared`). Items are
// created via raw `SecItemAdd` with `kSecUseDataProtectionKeychain=true`,
// `kSecAttrAccessGroup=<shared group>`, and
// `kSecAttrAccessible=kSecAttrAccessibleAfterFirstUnlock`. Both the Tauri UI app
// (`com.tsout.conduit`) and the standalone gateway binary
// (`com.tsout.conduit.gateway`) embed the SAME access group in their
// entitlements (`Entitlements.plist` / `Gateway.entitlements`), so BOTH read the
// item with no prompt and no per-application ACL. This replaces the older
// legacy-keychain `SecAccess`/trusted-application ACL approach.
//
// IMPORTANT: the data-protection keychain requires a code-signed binary with a
// valid Application Identifier (from an embedded provisioning profile / the
// `application-identifier` entitlement). On an UNSIGNED binary every DP-keychain
// call returns `errSecMissingEntitlement` (-34018). The DP-keychain round-trip
// tests are therefore `#[ignore]`d and only pass on a signed build (see Phase 7
// of the keychain-access-group rollout). Plain `cargo test` on an unsigned/dev
// build cannot exercise this path.
//
// `migrate_legacy_to_dpk()` runs once at app startup (guarded by a NEW marker
// file, `.keychain-dpk-migrated`) to move per-server secrets out of the legacy
// file-based keychain and into the data-protection store: read the old value,
// write it to the new store, verify the round-trip, and ONLY THEN delete the old
// legacy item. Any failure leaves the old item in place, so no secret is lost.
//
// The `keyring`-crate / `SecKeychainItem` legacy helpers below
// (`get_generic_password`, `delete_entry_by_account`, the master-key `mod file`
// path) are retained: the master key for the encrypted-file backend still lives
// in the legacy keychain, and migration reads the old legacy items through them.
#[cfg(target_os = "macos")]
mod platform {
    use core_foundation::base::TCFType;
    use security_framework::item::{ItemClass, ItemSearchOptions, Limit, Reference, SearchResult};
    use security_framework::os::macos::keychain_item::SecKeychainItem;
    use security_framework::passwords::get_generic_password;
    use security_framework_sys::base::errSecItemNotFound;

    use super::{account, SERVICE};

    /// Team-scoped keychain access group shared by the Toolport app and the
    /// gateway. Both binaries declare this group in their entitlements
    /// (`keychain-access-groups`), which is what lets each read the other's
    /// data-protection-keychain items with no prompt. The `V4YZPC7T6G` prefix is
    /// the Apple Developer Team ID; it MUST match the entitlement files
    /// (`Entitlements.plist` / `Gateway.entitlements`) exactly.
    pub const SHARED_ACCESS_GROUP: &str = "V4YZPC7T6G.com.tsout.conduit.shared";

    /// Reserved keychain account for the single 32-byte master key that encrypts
    /// the file backend (`secrets.enc`). Distinct from every server-secret account
    /// (which is `server_id::key`), so it never collides with a real secret. This
    /// is the ONLY keychain item Toolport creates once the file backend is the
    /// default on macOS — per-server secrets then live only in `secrets.enc`.
    pub const MASTER_KEY_ACCOUNT: &str = "__conduit_master_key__";

    /// Read the 32-byte master key from the keychain, if present.
    ///
    /// Returns `Ok(None)` when no master-key item exists yet (`errSecItemNotFound`,
    /// -25300) — the signal that the file backend is not yet the default. Returns
    /// `Err` on a stored value that isn't exactly 32 bytes after base64-decode
    /// (corrupt item) or any other keychain failure. This is **read-only**: both
    /// the app and the gateway call it. Only the app ever creates the key (via
    /// `ensure_master_key`).
    pub fn read_master_key() -> Result<Option<[u8; 32]>, String> {
        use base64::Engine;
        match get_generic_password(SERVICE, MASTER_KEY_ACCOUNT) {
            Ok(bytes) => {
                let encoded = String::from_utf8(bytes).map_err(|e| e.to_string())?;
                let raw = base64::engine::general_purpose::STANDARD
                    .decode(encoded.trim())
                    .map_err(|e| e.to_string())?;
                if raw.len() != 32 {
                    return Err(format!(
                        "master key in keychain is {} bytes, expected 32",
                        raw.len()
                    ));
                }
                let mut key = [0u8; 32];
                key.copy_from_slice(&raw);
                Ok(Some(key))
            }
            Err(e) if e.code() == -25300 /* errSecItemNotFound */ => Ok(None),
            Err(e) => Err(e.to_string()),
        }
    }

    /// Return the master key, creating it if it doesn't exist yet.
    ///
    /// If a key is already stored, returns it. Otherwise generates 32 random bytes
    /// and stores them base64-encoded via the EXISTING `add_with_shared_access`
    /// path, so the shared-access ACL lets BOTH the app and the separately-signed
    /// gateway read the master key with no prompt. **Only the app's startup calls
    /// this** — the gateway is read-only and must never create the key (it calls
    /// `read_master_key` instead).
    pub fn ensure_master_key() -> Result<[u8; 32], String> {
        use base64::Engine;
        if let Some(key) = read_master_key()? {
            return Ok(key);
        }
        let mut key = [0u8; 32];
        getrandom::getrandom(&mut key).map_err(|e| e.to_string())?;
        let encoded = base64::engine::general_purpose::STANDARD.encode(key);
        add_with_shared_access(MASTER_KEY_ACCOUNT, &encoded)?;
        Ok(key)
    }

    /// Store a per-server secret in the **data-protection keychain** under the
    /// shared access group, via raw `SecItemAdd`.
    ///
    /// Builds a dictionary with `kSecClass=kSecClassGenericPassword`,
    /// `kSecAttrService`, `kSecAttrAccount`, `kSecValueData`,
    /// `kSecUseDataProtectionKeychain=true`, `kSecAttrAccessGroup=<shared group>`,
    /// and `kSecAttrAccessible=kSecAttrAccessibleAfterFirstUnlock`. A
    /// `SecItemDelete` with the SAME query keys (incl. the access group + the
    /// data-protection flag) runs first for idempotency, then `SecItemAdd` creates
    /// a fresh item.
    ///
    /// The high-level `security_framework::passwords` API targets the *legacy*
    /// keychain and cannot set the access group or the data-protection flag, so
    /// this MUST be raw FFI.
    ///
    /// Returns `Err` on an unsigned/dev build: the data-protection keychain
    /// rejects every call with `errSecMissingEntitlement` (-34018) when the binary
    /// has no Application Identifier (no embedded provisioning profile).
    pub fn set_secret(server_id: &str, key: &str, value: &str) -> Result<(), String> {
        dpk::set(&account(server_id, key), value)
    }

    /// Create a generic-password item in the **legacy** keychain that BOTH the
    /// Toolport app and the `toolport-gateway` binary can read with no keychain
    /// prompt: build a legacy `SecAccess` whose trusted-applications list names
    /// both binaries and pass it as `kSecAttrAccess` on `SecItemAdd`. Setting the
    /// ACL atomically at creation avoids the keychain-password prompt that a
    /// post-hoc `SecKeychainItemSetAccess` would raise.
    ///
    /// **Scope after the data-protection rewrite:** per-server secrets now use the
    /// data-protection keychain + the team-scoped access group (`dpk::set`). This
    /// legacy trusted-application path is retained ONLY for the encrypted-file
    /// backend's master key (`ensure_master_key`), which the gateway must read as
    /// a *bare CLI binary* that cannot carry the provisioning profile required for
    /// an access-group entitlement (a profile-less binary with a restricted
    /// `keychain-access-groups` entitlement is SIGKILLed by AMFI at launch,
    /// -34018 / amfid -413). The legacy ACL works for Developer ID distribution
    /// with no profile; the APIs are deprecated-but-functional.
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
        // The app (this process) must be trustable; if it isn't there's nothing
        // usable to write. The gateway is best-effort: add it when its path resolves
        // and a trusted-application can be built for it, otherwise proceed app-only
        // (the item stays ACL-protected, NOT world-readable; the gateway just falls
        // back to a one-time "Always Allow" until the next rewrite names it). This
        // also keeps unit tests working, where the gateway binary isn't on disk.
        let app_path = std::env::current_exe().map_err(|e| e.to_string())?;
        let mut trusted_apps: Vec<CFType> = Vec::with_capacity(2);
        trusted_apps.push(trusted_app(&app_path)?);
        match crate::clients::resolve_gateway_path() {
            Some(gw_path) => match trusted_app(&gw_path) {
                Ok(t) => trusted_apps.push(t),
                Err(e) => eprintln!("conduit: gateway not added to keychain ACL ({e}); app-only"),
            },
            None => eprintln!("conduit: gateway path unresolved; keychain ACL is app-only"),
        }
        let trusted = CFArray::from_CFTypes(&trusted_apps);
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

    /// Test-only: seed an item in the **legacy** keychain (the one the
    /// legacy -> data-protection migration reads FROM) so a signed-build test can
    /// exercise `migrate_legacy_to_dpk`. Writes via `add_with_shared_access`,
    /// which targets the legacy keychain under the same SERVICE/account the
    /// migration scans with `get_generic_password`.
    #[cfg(test)]
    pub fn seed_legacy_for_test(server_id: &str, key: &str, value: &str) -> Result<(), String> {
        add_with_shared_access(&account(server_id, key), value)
    }

    pub fn get_secret_result(server_id: &str, key: &str) -> Result<Option<String>, String> {
        dpk::get(&account(server_id, key))
    }

    pub fn delete_secret(server_id: &str, key: &str) -> Result<(), String> {
        dpk::delete(&account(server_id, key))
    }

    /// Raw `SecItem*` FFI bound to the **data-protection keychain** with the
    /// shared access group. All three operations carry
    /// `kSecUseDataProtectionKeychain=true` and `kSecAttrAccessGroup=<shared
    /// group>` so the app and gateway see the same items.
    ///
    /// `kSecAttrAccessible` / `kSecAttrAccessibleAfterFirstUnlock` /
    /// `kSecMatchLimitOne` are NOT re-exported by `security_framework_sys` (and
    /// `kSecUseDataProtectionKeychain` is feature-gated behind `OSX_10_15` there),
    /// so this block declares every `kSec*` constant it needs itself via
    /// `#[link(name = "Security")]`. `kCFBooleanTrue` for the data-protection flag
    /// comes from `core_foundation::boolean::CFBoolean::true_value()`.
    mod dpk {
        use core_foundation::base::{CFType, CFTypeRef, TCFType};
        use core_foundation::boolean::CFBoolean;
        use core_foundation::data::CFData;
        use core_foundation::dictionary::CFDictionary;
        use core_foundation::string::CFString;
        use std::os::raw::c_void;

        use super::{SERVICE, SHARED_ACCESS_GROUP};

        const ERR_SEC_ITEM_NOT_FOUND: i32 = -25300;

        #[link(name = "Security", kind = "framework")]
        extern "C" {
            fn SecItemAdd(attributes: *const c_void, result: *mut *const c_void) -> i32;
            fn SecItemCopyMatching(query: *const c_void, result: *mut *const c_void) -> i32;
            fn SecItemDelete(query: *const c_void) -> i32;

            static kSecClass: CFTypeRef;
            static kSecClassGenericPassword: CFTypeRef;
            static kSecAttrService: CFTypeRef;
            static kSecAttrAccount: CFTypeRef;
            static kSecValueData: CFTypeRef;
            static kSecAttrAccessGroup: CFTypeRef;
            static kSecAttrAccessible: CFTypeRef;
            static kSecAttrAccessibleAfterFirstUnlock: CFTypeRef;
            static kSecUseDataProtectionKeychain: CFTypeRef;
            static kSecReturnData: CFTypeRef;
            static kSecMatchLimit: CFTypeRef;
            static kSecMatchLimitOne: CFTypeRef;
        }

        /// The kSec* constants are CFString/CFType singletons; wrap them under the
        /// get rule (no ownership transfer) into safe `CFType`s.
        fn k(raw: CFTypeRef) -> CFType {
            unsafe { CFType::wrap_under_get_rule(raw) }
        }

        /// The shared base query keys present in EVERY operation: class,
        /// service, account, the access group, and the data-protection flag.
        fn base_query(account_str: &str) -> Vec<(CFType, CFType)> {
            unsafe {
                vec![
                    (k(kSecClass), k(kSecClassGenericPassword)),
                    (k(kSecAttrService), CFString::new(SERVICE).as_CFType()),
                    (k(kSecAttrAccount), CFString::new(account_str).as_CFType()),
                    (
                        k(kSecAttrAccessGroup),
                        CFString::new(SHARED_ACCESS_GROUP).as_CFType(),
                    ),
                    (
                        k(kSecUseDataProtectionKeychain),
                        CFBoolean::true_value().as_CFType(),
                    ),
                ]
            }
        }

        /// `SecItemDelete` for idempotency, then `SecItemAdd`. Returns Err on any
        /// non-success add status (notably -34018 `errSecMissingEntitlement` on an
        /// unsigned build).
        pub fn set(account_str: &str, value: &str) -> Result<(), String> {
            // 1. Delete any existing item (same keys incl. access group + DP flag).
            let del = CFDictionary::from_CFType_pairs(&base_query(account_str));
            unsafe {
                SecItemDelete(del.as_concrete_TypeRef() as *const c_void);
            }

            // 2. Add the fresh item with the value + accessibility class.
            let mut pairs = base_query(account_str);
            pairs.push((
                k(unsafe { kSecValueData }),
                CFData::from_buffer(value.as_bytes()).as_CFType(),
            ));
            pairs.push((
                k(unsafe { kSecAttrAccessible }),
                k(unsafe { kSecAttrAccessibleAfterFirstUnlock }),
            ));
            let add = CFDictionary::from_CFType_pairs(&pairs);
            let st =
                unsafe { SecItemAdd(add.as_concrete_TypeRef() as *const c_void, std::ptr::null_mut()) };
            if st != 0 {
                return Err(format!("SecItemAdd (data-protection keychain) failed: {st}"));
            }
            Ok(())
        }

        /// `SecItemCopyMatching` with `kSecReturnData=true` and
        /// `kSecMatchLimit=kSecMatchLimitOne`. `errSecItemNotFound` (-25300) maps
        /// to `Ok(None)`; the returned CFData is decoded to a `String`.
        pub fn get(account_str: &str) -> Result<Option<String>, String> {
            let mut pairs = base_query(account_str);
            pairs.push((k(unsafe { kSecReturnData }), CFBoolean::true_value().as_CFType()));
            pairs.push((k(unsafe { kSecMatchLimit }), k(unsafe { kSecMatchLimitOne })));
            let query = CFDictionary::from_CFType_pairs(&pairs);

            let mut result: *const c_void = std::ptr::null_mut();
            let st = unsafe {
                SecItemCopyMatching(query.as_concrete_TypeRef() as *const c_void, &mut result)
            };
            if st == ERR_SEC_ITEM_NOT_FOUND {
                return Ok(None);
            }
            if st != 0 {
                return Err(format!(
                    "SecItemCopyMatching (data-protection keychain) failed: {st}"
                ));
            }
            if result.is_null() {
                return Ok(None);
            }
            // SecItemCopyMatching returns a CFDataRef (we requested return-data);
            // it's a +1 (create-rule) reference we own. `as _` resolves to
            // `CFData::Ref` (the concrete `CFDataRef`) from the function arg type.
            let data = unsafe { CFData::wrap_under_create_rule(result as _) };
            String::from_utf8(data.bytes().to_vec())
                .map(Some)
                .map_err(|e| e.to_string())
        }

        /// `SecItemDelete` against the data-protection keychain.
        /// `errSecItemNotFound` maps to `Ok(())`.
        pub fn delete(account_str: &str) -> Result<(), String> {
            let query = CFDictionary::from_CFType_pairs(&base_query(account_str));
            let st = unsafe { SecItemDelete(query.as_concrete_TypeRef() as *const c_void) };
            if st == 0 || st == ERR_SEC_ITEM_NOT_FOUND {
                Ok(())
            } else {
                Err(format!("SecItemDelete (data-protection keychain) failed: {st}"))
            }
        }
    }

    /// Migrate per-server secrets OUT of the **legacy file-based keychain** and
    /// INTO the **data-protection keychain** (shared access group).
    ///
    /// **Per-key flow (write -> verify -> only-then-delete, no data loss):**
    ///
    /// For each `(server_id, key)` pair:
    /// 1. **Read** the OLD value from the legacy keychain via the existing
    ///    `get_generic_password`. Safe from the app process, which has ACL grants
    ///    from the old version.
    /// 2. **Write** it to the NEW data-protection store (`set_secret` ->
    ///    `dpk::set`).
    /// 3. **Verify** by reading it back from the new store (`dpk::get`); the
    ///    round-tripped value must equal the original.
    /// 4. **Only then delete** the old legacy item via the existing
    ///    `delete_entry_by_account` (account-filtered ref search +
    ///    `SecKeychainItemDelete`, the only API that reliably removes legacy
    ///    file-based items).
    ///
    /// On ANY failure for a key (read/write/verify error, or a verify mismatch),
    /// the old legacy item is LEFT IN PLACE — no secret is lost — and the key is
    /// counted as `failed`. Keys that don't exist in the legacy keychain (e.g.
    /// `__oauth_state__` on a non-OAuth server) are counted as `not_found`, not a
    /// failure.
    ///
    /// **Signed-build-only:** step 2/3 hit the data-protection keychain, which
    /// returns `errSecMissingEntitlement` (-34018) on an unsigned binary, so this
    /// can only succeed on a signed build with the embedded provisioning profile.
    ///
    /// Wired into app startup via `migrate_secrets_to_dpk`, which guards it behind
    /// `DPK_MIGRATION_MARKER` so it runs once per install. The app process is the
    /// only caller (the gateway is read-only).
    pub fn migrate_legacy_to_dpk(
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
                        // write (new store) -> verify (new store) -> only then
                        // delete the OLD legacy item. Leave the legacy item in
                        // place on any failure so no secret is lost.
                        let moved = set_secret(server_id, key, &value).is_ok()
                            && matches!(
                                dpk::get(&acct),
                                Ok(Some(ref v)) if *v == value
                            );
                        if moved {
                            let _ = delete_entry_by_account(&acct);
                            migrated += 1;
                        } else {
                            failed += 1;
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

    /// Migrate per-server secrets OUT of individual keychain items and INTO the
    /// encrypted file backend (`secrets.enc`), so they stop living as separate
    /// ACL'd keychain items that prompt on every app update.
    ///
    /// Per-key flow (no secret loss, with rollback):
    /// 1. **Read** the value from the OLD keychain item (`get_generic_password`).
    /// 2. **Write** it into the file backend (`super::file::set_secret`).
    /// 3. **Verify** by reading it back from the file backend; the round-tripped
    ///    value must equal the original.
    /// 4. **Only then delete** the old keychain item (`delete_entry_by_account`).
    ///
    /// On ANY failure for a key (read/write/verify error, or a verify mismatch),
    /// the old keychain item is LEFT IN PLACE — no data loss — and the key is
    /// counted as `failed`. `errSecItemNotFound` is counted as `not_found`
    /// (expected for reserved keys on servers that don't use them).
    ///
    /// Requires the master key to already exist (so `super::file::active()` is
    /// true); the caller ensures that before invoking this.
    pub fn migrate_keychain_to_file(
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
                        // write -> verify -> delete. Leave the keychain item in
                        // place on any failure so no secret is lost.
                        let moved = super::file::set_secret(server_id, key, &value).is_ok()
                            && matches!(
                                super::file::get_secret_result(server_id, key),
                                Ok(Some(ref v)) if *v == value
                            );
                        if moved {
                            let _ = delete_entry_by_account(&acct);
                            migrated += 1;
                        } else {
                            failed += 1;
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

    /// The 32-byte key that encrypts `secrets.enc`, or None when the file backend
    /// is inactive (the signal to use the OS keychain directly).
    ///
    /// The file backend is **headless-only**: it activates IFF `CONDUIT_SECRET_KEY`
    /// is set + non-empty (the key is SHA-256 of it; the app and gateway must agree
    /// on the env var). On every desktop OS this returns None, so secrets live in
    /// the OS keychain — on macOS that is the *data-protection* keychain under the
    /// team-scoped shared access group (`platform`), which keeps keys off disk and
    /// lets the separately-signed gateway read them with no prompt.
    ///
    /// We deliberately do NOT derive the key from a keychain master item on
    /// desktop. Doing so would activate `secrets.enc` on disk and shadow the
    /// data-protection keychain — the "keys never on disk" property we sell — and
    /// reading that master item across an app update is itself a prompt source.
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
// Older versions of Toolport used the `keyring` crate, which created keychain
// items with per-application ACLs. This migration reads each entry's value,
// deletes it, and re-creates it via the ACL-free `SecItemAdd` path.
//
// The migration is guarded by a marker file so it runs once per marker version.
// Only the UI app runs it — the gateway can't rewrite entries without triggering
// prompts (it's a separately signed process). Bumping the marker name
// (".keychain-migrated" -> ".keychain-acl-migrated") makes the migration re-run
// once on upgrade so EXISTING secrets are rewritten WITH the shared-access ACL,
// not just legacy keyring-API entries.

/// Marker file name for the legacy ACL migration (keychain -> ACL-free keychain).
/// Left untouched for backward compatibility, but the current macOS path migrates
/// secrets into the file backend instead (see `FILE_MIGRATION_MARKER`).
#[cfg(target_os = "macos")]
#[allow(dead_code)]
const MIGRATION_MARKER: &str = ".keychain-acl-migrated";

/// Marker file name for the keychain -> encrypted-file migration. A NEW name so
/// the migration runs exactly once on upgrade to the file-backend-by-default
/// build, even on installs that already ran the older ACL migration.
#[cfg(target_os = "macos")]
const FILE_MIGRATION_MARKER: &str = ".secrets-file-migrated";

/// Marker file name for the legacy-keychain -> data-protection-keychain
/// migration (the team-scoped shared access group). A NEW name (the older
/// markers are left untouched) so this runs exactly once on upgrade to the
/// data-protection-keychain build. App-only; written only on a clean pass.
#[cfg(target_os = "macos")]
const DPK_MIGRATION_MARKER: &str = ".keychain-dpk-migrated";

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

/// Run the one-time macOS secret migration to the encrypted file backend.
///
/// On macOS this:
/// 1. **Ensures the master key** (`platform::ensure_master_key`) FIRST, so the
///    file backend becomes active (`file::active()` is true). If ensuring the
///    key fails (e.g. the keychain is locked), it logs and returns the default
///    report WITHOUT writing the marker, so the whole thing retries next launch.
/// 2. If the file-migration marker is absent, **moves each secret** from its old
///    per-server keychain item into `secrets.enc` via
///    `platform::migrate_keychain_to_file` (read -> write-file -> verify -> only
///    then delete the keychain item; on any failure the keychain item is left in
///    place so nothing is lost). The marker is written ONLY when that pass
///    returns `Ok`.
///
/// Only call from the UI app (not the gateway): the gateway is read-only and
/// must never create the master key or rewrite entries.
///
/// `secret_keys` is a list of `(server_id, key)` pairs for every secret env var
/// in the registry (and reserved keys like `HTTP_AUTH_KEY` for remote servers).
pub fn migrate_legacy_entries(secret_keys: &[(String, String)]) -> MigrationReport {
    #[cfg(target_os = "macos")]
    {
        // 1. Ensure the master key exists before anything else. This is what
        //    flips the file backend on for this install. If it fails (locked
        //    keychain), don't write the marker — retry on the next launch.
        if let Err(e) = platform::ensure_master_key() {
            eprintln!(
                "conduit: could not ensure secrets master key, will retry next launch ({e})"
            );
            return MigrationReport::default();
        }

        // 2. One-time migration of per-server secrets into the file backend.
        if file_migration_marker_exists() {
            return MigrationReport::default();
        }

        let report = match platform::migrate_keychain_to_file(secret_keys) {
            Ok(report) => report,
            Err(e) => {
                // Don't write the marker — the migration didn't run, so it
                // should retry on the next launch.
                eprintln!("conduit: secret migration skipped, will retry next launch ({e})");
                return MigrationReport::default();
            }
        };

        let _ = create_file_migration_marker();
        report
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = secret_keys;
        MigrationReport::default()
    }
}

/// Whether the keychain -> file migration marker exists in the Toolport data dir.
#[cfg(target_os = "macos")]
fn file_migration_marker_exists() -> bool {
    crate::registry::conduit_dir()
        .map(|d| d.join(FILE_MIGRATION_MARKER))
        .map(|p| p.exists())
        .unwrap_or(false)
}

/// Create the keychain -> file migration marker file. Returns `true` on success.
#[cfg(target_os = "macos")]
fn create_file_migration_marker() -> bool {
    let Some(dir) = crate::registry::conduit_dir() else {
        return false;
    };
    let _ = std::fs::create_dir_all(&dir);
    std::fs::write(dir.join(FILE_MIGRATION_MARKER), b"1").is_ok()
}

/// Run the one-time macOS migration of per-server secrets from the legacy
/// file-based keychain INTO the data-protection keychain (the team-scoped shared
/// access group), guarded by `DPK_MIGRATION_MARKER` so it runs once per install.
///
/// This is the migration that replaces the old ACL / encrypted-file paths: after
/// it runs, every secret lives in the data-protection keychain, which the
/// separately-signed gateway reads with NO prompt across app updates.
///
/// Only the UI app calls this (the gateway is read-only and must never rewrite
/// entries). Best-effort and lossless: `migrate_legacy_to_dpk` reads each legacy
/// item, writes + verifies the data-protection copy, then deletes the legacy item;
/// an item it can't move is left in the legacy keychain. The marker is written
/// only on a fully clean pass (`failed == 0`), so a transient denial or locked
/// keychain is retried on the next launch rather than stranding a secret.
pub fn migrate_secrets_to_dpk(secret_keys: &[(String, String)]) -> MigrationReport {
    #[cfg(target_os = "macos")]
    {
        if dpk_migration_marker_exists() {
            return MigrationReport::default();
        }
        let report = match platform::migrate_legacy_to_dpk(secret_keys) {
            Ok(report) => report,
            Err(e) => {
                eprintln!(
                    "conduit: data-protection keychain migration skipped, will retry next launch ({e})"
                );
                return MigrationReport::default();
            }
        };
        // Only mark complete once nothing failed, so a denied prompt or locked
        // keychain gets another chance next launch instead of being marked done.
        if report.failed == 0 {
            let _ = create_dpk_migration_marker();
        }
        report
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = secret_keys;
        MigrationReport::default()
    }
}

/// Whether the legacy -> data-protection keychain migration marker exists.
#[cfg(target_os = "macos")]
fn dpk_migration_marker_exists() -> bool {
    crate::registry::conduit_dir()
        .map(|d| d.join(DPK_MIGRATION_MARKER))
        .map(|p| p.exists())
        .unwrap_or(false)
}

/// Create the legacy -> data-protection keychain migration marker. Returns `true`
/// on success.
#[cfg(target_os = "macos")]
fn create_dpk_migration_marker() -> bool {
    let Some(dir) = crate::registry::conduit_dir() else {
        return false;
    };
    let _ = std::fs::create_dir_all(&dir);
    std::fs::write(dir.join(DPK_MIGRATION_MARKER), b"1").is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    /// Serializes tests that read or mutate the process-global `CONDUIT_SECRET_KEY`
    /// env var (and thus `file::active()`). Without this, a test that sets the var
    /// races with a sibling that assumes the keychain path, causing spurious
    /// failures under the default multi-threaded test runner.
    static ENV_LOCK: Mutex<()> = Mutex::new(());

    // Round-trips through the real OS keychain. Headless Linux CI has no Secret
    // Service (D-Bus), so skip it there; it still runs on Windows.
    //
    // On macOS this now targets the DATA-PROTECTION keychain (shared access
    // group), which returns errSecMissingEntitlement (-34018) on an unsigned
    // binary, so it's `#[ignore]`d there: run only on a signed build with the
    // embedded provisioning profile (see Phase 7).
    #[test]
    #[cfg_attr(target_os = "linux", ignore = "no Secret Service in headless CI")]
    #[cfg_attr(
        target_os = "macos",
        ignore = "data-protection keychain needs a signed build w/ provisioning profile (Phase 7)"
    )]
    fn set_get_delete_round_trip() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let sid = "conduit-test-server";
        let key = "CONDUIT_TEST_KEY";
        set_secret(sid, key, "s3cr3t").unwrap();
        assert_eq!(get_secret(sid, key).as_deref(), Some("s3cr3t"));
        delete_secret(sid, key).unwrap();
        assert_eq!(get_secret(sid, key), None);
    }

    /// Cross-platform: setting `CONDUIT_SECRET_KEY` activates the file backend.
    /// Runs on every OS (the env-var precedence is platform-independent).
    ///
    /// NOTE: mutates a process-global env var, so it's `#[serial]`-free but kept
    /// self-contained — it sets and then unsets the var, restoring prior state.
    #[test]
    fn file_active_when_env_key_set() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let prev = std::env::var("CONDUIT_SECRET_KEY").ok();
        std::env::set_var("CONDUIT_SECRET_KEY", "unit-test-passphrase");
        assert!(
            file::active(),
            "file backend must be active when CONDUIT_SECRET_KEY is set"
        );
        // Restore prior state so other tests aren't affected.
        match prev {
            Some(v) => std::env::set_var("CONDUIT_SECRET_KEY", v),
            None => std::env::remove_var("CONDUIT_SECRET_KEY"),
        }
    }

    /// macOS: ensuring the master key returns 32 bytes and is idempotent — a
    /// second `ensure` returns the SAME key, and a plain `read` returns it too.
    #[cfg(target_os = "macos")]
    #[test]
    fn master_key_ensure_then_read_is_idempotent() {
        let first = platform::ensure_master_key().expect("ensure should succeed");
        assert_eq!(first.len(), 32);
        let second = platform::ensure_master_key().expect("ensure should be idempotent");
        assert_eq!(first, second, "ensure must return the same key each time");
        let read = platform::read_master_key()
            .expect("read should succeed")
            .expect("master key should exist after ensure");
        assert_eq!(first, read, "read must return the ensured key");
    }

    /// macOS: the file backend is headless-only. Without `CONDUIT_SECRET_KEY`,
    /// `active()` stays false even after a keychain master key exists, so desktop
    /// secrets route to the data-protection keychain, never to `secrets.enc`.
    #[cfg(target_os = "macos")]
    #[test]
    fn master_key_does_not_activate_file_backend() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let prev = std::env::var("CONDUIT_SECRET_KEY").ok();
        std::env::remove_var("CONDUIT_SECRET_KEY");
        // Creating a master key must NOT flip the file backend on (best-effort:
        // the create may no-op on an unsigned build, which is fine for this test).
        let _ = platform::ensure_master_key();
        assert!(
            !file::active(),
            "file backend must stay inactive on desktop without CONDUIT_SECRET_KEY"
        );
        if let Some(v) = prev {
            std::env::set_var("CONDUIT_SECRET_KEY", v);
        }
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

    /// The data-protection keychain round-trips a per-server secret: write via
    /// `platform::set_secret` (`dpk::set`), read it back via
    /// `platform::get_secret_result` (`dpk::get`), then delete it
    /// (`dpk::delete`). After delete, the read returns `None`.
    ///
    /// Signed-build-only: every call carries `kSecUseDataProtectionKeychain`, so
    /// an unsigned binary gets errSecMissingEntitlement (-34018). Run only on a
    /// signed build with the embedded provisioning profile (see Phase 7).
    #[cfg(target_os = "macos")]
    #[test]
    #[ignore = "data-protection keychain needs a signed build w/ provisioning profile (Phase 7)"]
    fn dpk_set_get_delete_round_trip() {
        let sid = "conduit-dpk-test";
        let key = "DPK_ROUND_TRIP_KEY";
        let original = "s3cr3t-value-in-data-protection-keychain";

        platform::set_secret(sid, key, original).unwrap();
        assert_eq!(
            platform::get_secret_result(sid, key).unwrap().as_deref(),
            Some(original),
            "value must round-trip through the data-protection keychain"
        );

        platform::delete_secret(sid, key).unwrap();
        assert_eq!(
            platform::get_secret_result(sid, key).unwrap(),
            None,
            "value must be gone after delete"
        );
    }

    /// The legacy -> data-protection migration preserves secret values: it reads
    /// the old legacy item, writes + verifies the new DP item, then deletes the
    /// legacy one. After migration the value reads back from the DP store.
    ///
    /// This exercises `platform::migrate_legacy_to_dpk`, whose write/verify steps
    /// hit the data-protection keychain (errSecMissingEntitlement -34018 on an
    /// unsigned binary). Signed-build-only: run only on a signed build with the
    /// embedded provisioning profile (see Phase 7). Seeding a *legacy* keychain
    /// item to migrate FROM also requires the keychain to be writable in that
    /// context, which this harness sets up on the signed build.
    #[cfg(target_os = "macos")]
    #[test]
    #[ignore = "data-protection keychain needs a signed build w/ provisioning profile (Phase 7)"]
    fn migrate_legacy_to_dpk_preserves_values() {
        let sid = "conduit-migrate-test";
        let key = "MIGRATE_PRESERVE_KEY";
        let original = "s3cr3t-value-to-preserve";

        // Seed the OLD legacy keychain item (the migration reads it via
        // `get_generic_password`). `add_with_shared_access` writes to the legacy
        // keychain under the same SERVICE/account the migration scans.
        platform::seed_legacy_for_test(sid, key, original).unwrap();

        let keys = vec![(sid.to_string(), key.to_string())];
        let report = platform::migrate_legacy_to_dpk(&keys).expect("migration should succeed");

        assert_eq!(report.migrated, 1, "one entry should have been migrated");
        assert_eq!(report.failed, 0, "no entries should have failed");
        assert_eq!(report.not_found, 0, "no entries should have been not-found");

        // The value must now read back from the DATA-PROTECTION store.
        assert_eq!(
            platform::get_secret_result(sid, key).unwrap().as_deref(),
            Some(original),
            "secret value must survive migration into the data-protection store"
        );

        // Clean up the DP item.
        platform::delete_secret(sid, key).unwrap();
    }

    /// The migration correctly reports `not_found` for keys that don't exist in
    /// the legacy keychain (e.g. `__oauth_state__` on a non-OAuth server). This
    /// should not be counted as a failure.
    ///
    /// The not-found path only reads the legacy keychain (`get_generic_password`)
    /// and never reaches the data-protection write, so this part is exercisable
    /// unsigned. Kept `#[ignore]` for consistency with the DP-migration suite
    /// (signed-build-only).
    #[cfg(target_os = "macos")]
    #[test]
    #[ignore = "part of the data-protection migration suite; run on a signed build (Phase 7)"]
    fn migrate_legacy_to_dpk_reports_not_found_for_missing_keys() {
        let sid = "conduit-missing-test";
        let key = "THIS_KEY_DOES_NOT_EXIST";

        // Ensure neither store has the entry.
        let _ = platform::delete_secret(sid, key);

        let keys = vec![(sid.to_string(), key.to_string())];
        let report =
            platform::migrate_legacy_to_dpk(&keys).expect("migration should succeed");

        assert_eq!(report.migrated, 0, "nothing to migrate");
        assert_eq!(report.failed, 0, "missing keys are not failures");
        assert_eq!(
            report.not_found, 1,
            "one key should be reported as not-found"
        );
    }
}
