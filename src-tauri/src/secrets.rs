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
// which stores items in the data-protection keychain without per-application
// ACLs. Any process running as the user can read them after a single unlock.
//
// Note: entries created by a previous version of Conduit (via the `keyring`
// crate) still live in the legacy keychain and carry ACLs. After upgrading,
// users should delete them from Keychain Access and re-authenticate their
// servers to create ACL-free entries through this path.
#[cfg(target_os = "macos")]
mod platform {
    use security_framework::passwords::{
        delete_generic_password, get_generic_password, set_generic_password,
    };

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
}
