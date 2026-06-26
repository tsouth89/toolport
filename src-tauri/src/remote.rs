//! Remote (http) server connection with automatic OAuth token refresh.
//!
//! When a connection fails with an auth error and we have a stored refresh
//! token, we transparently refresh the access token and retry once. The OAuth
//! state (token endpoint, client id, refresh token) is vaulted alongside the
//! access token.

use serde::{Deserialize, Serialize};

use crate::downstream::{DownstreamServer, HttpTransport};
use crate::registry::ServerEntry;
use crate::{oauth, secrets};

const STATE_KEY: &str = "__oauth_state__";

#[derive(Serialize, Deserialize)]
struct OAuthState {
    token_endpoint: String,
    client_id: String,
    refresh_token: Option<String>,
    /// The RFC 8707 resource indicator (the MCP server URL) the token is bound
    /// to. Optional for back-compat with states vaulted before this existed.
    #[serde(default)]
    resource: Option<String>,
}

/// Persist what's needed to refresh this server's token later.
pub fn store_oauth_state(
    server_id: &str,
    token_endpoint: &str,
    client_id: &str,
    refresh_token: Option<String>,
    resource: Option<String>,
) -> Result<(), String> {
    let state = OAuthState {
        token_endpoint: token_endpoint.to_string(),
        client_id: client_id.to_string(),
        refresh_token,
        resource,
    };
    let json = serde_json::to_string(&state).map_err(|e| e.to_string())?;
    secrets::set_secret(server_id, STATE_KEY, &json)
}

fn load_state(server_id: &str) -> Option<OAuthState> {
    secrets::get_secret(server_id, STATE_KEY)
        .and_then(|s| serde_json::from_str(&s).ok())
}

/// Use the stored refresh token to mint a fresh access token, vault it, and
/// return it.
pub fn refresh_token(server_id: &str) -> Result<String, String> {
    let state = load_state(server_id).ok_or("no stored OAuth state to refresh")?;
    let rt = state
        .refresh_token
        .as_deref()
        .ok_or("no refresh token available")?;
    let tokens = oauth::refresh(
        &state.token_endpoint,
        &state.client_id,
        rt,
        state.resource.as_deref(),
    )?;
    secrets::set_secret(server_id, secrets::HTTP_AUTH_KEY, &tokens.access_token)?;
    // Persist a rotated refresh token if the server issued one.
    let new_state = OAuthState {
        token_endpoint: state.token_endpoint,
        client_id: state.client_id,
        refresh_token: tokens.refresh_token.or(state.refresh_token),
        resource: state.resource,
    };
    if let Ok(json) = serde_json::to_string(&new_state) {
        let _ = secrets::set_secret(server_id, STATE_KEY, &json);
    }
    Ok(tokens.access_token)
}

pub fn is_auth_error(e: &str) -> bool {
    let lower = e.to_lowercase();
    e.contains("401")
        || e.contains("403")
        || lower.contains("unauthorized")
        || lower.contains("needs authentication")
}

/// A vaulted bearer token must not ride over cleartext to a public host. Allow
/// http only for loopback/private hosts (local dev on a trusted network); require
/// https for anything public, so the token can't be sniffed off the wire.
fn require_secure_for_auth(url: &str) -> Result<(), String> {
    if url.trim().to_ascii_lowercase().starts_with("https://") {
        return Ok(());
    }
    let host = oauth::host_of_url(url).unwrap_or_default();
    if oauth::host_is_private(&host) {
        return Ok(());
    }
    Err(format!(
        "refusing to send the saved auth token to a non-HTTPS URL ({url}); \
         use https for an authenticated remote server"
    ))
}

/// Build an HTTP transport, refusing to attach a token to a cleartext public URL.
fn authed_transport(url: &str, token: Option<String>) -> Result<HttpTransport, String> {
    if token.is_some() {
        require_secure_for_auth(url)?;
    }
    Ok(HttpTransport::with_auth(url, token))
}

/// The first custom secret env var that has a value vaulted in the keychain.
/// For HTTP servers that don't use OAuth (e.g. Magica with a `BEARER` API key),
/// this is the token we send as `Authorization: Bearer ***`.
fn first_vaulted_secret(server: &ServerEntry) -> Option<String> {
    for e in &server.env {
        if e.secret && e.value.is_none() {
            if let Some(v) = secrets::get_secret(&server.id, &e.key) {
                return Some(v);
            }
        }
    }
    None
}

/// Connect to a remote server, injecting any vaulted token. On an auth error,
/// refresh the token once and retry.
///
/// Token lookup order for HTTP servers:
/// 1. `__http_auth__` — the key used by the OAuth flow and the "paste token" UI.
/// 2. The first vaulted custom secret env var (e.g. `BEARER`) — for servers like
///    Magica that declare a manual API-key env var in the registry but don't use
///    OAuth. Without this fallback, "Manage secrets" tokens were silently ignored
///    for HTTP servers.
pub fn connect_remote(server: &ServerEntry) -> Result<DownstreamServer, String> {
    let url = server.url.as_deref().unwrap_or("");
    let server_id = &server.id;
    let auth = secrets::get_secret(server_id, secrets::HTTP_AUTH_KEY)
        .or_else(|| first_vaulted_secret(server));
    let transport = authed_transport(url, auth)?;
    match DownstreamServer::connect(server_id.to_string(), Box::new(transport)) {
        Ok(ds) => Ok(ds),
        Err(e) if is_auth_error(&e) => match refresh_token(server_id) {
            Ok(fresh) => {
                let transport = authed_transport(url, Some(fresh))?;
                DownstreamServer::connect(server_id.to_string(), Box::new(transport))
            }
            Err(_) => Err(e),
        },
        Err(e) => Err(e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classifies_auth_errors() {
        assert!(is_auth_error("HTTP 401 (needs authentication): ..."));
        assert!(is_auth_error("got 403 Forbidden"));
        assert!(!is_auth_error("HTTP 500: server error"));
        assert!(!is_auth_error("connection refused"));
    }

    #[test]
    fn auth_requires_https_for_public_hosts() {
        // IP literals so the private-host check needs no DNS (hermetic test).
        // A token must not ride cleartext to a public host.
        assert!(require_secure_for_auth("http://8.8.8.8/mcp").is_err());
        // https to anywhere is fine.
        assert!(require_secure_for_auth("https://8.8.8.8/mcp").is_ok());
        // Loopback / private over http is acceptable (local dev).
        assert!(require_secure_for_auth("http://127.0.0.1:8080/mcp").is_ok());
        assert!(require_secure_for_auth("http://192.168.1.10/mcp").is_ok());
    }
}
