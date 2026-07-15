//! Remote (http) server connection with automatic OAuth token refresh.
//!
//! When a connection fails with an auth error and we have a stored refresh
//! token, we transparently refresh the access token and retry once. The OAuth
//! state (token endpoint, client id, refresh token) is vaulted alongside the
//! access token.

use serde::{Deserialize, Serialize};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::downstream::{
    DownstreamServer, HttpTransport, RefreshFn, ServerRequestHandler, Transport,
};
use crate::registry::ServerEntry;
use crate::{oauth, secrets};

const STATE_KEY: &str = "__oauth_state__";
pub const OAUTH_STATE_KEY: &str = STATE_KEY;
/// Refresh before the exact deadline so the token cannot expire while an MCP
/// request is in flight.
const PROACTIVE_REFRESH_SKEW_SECS: u64 = 60;

#[derive(Serialize, Deserialize)]
struct OAuthState {
    token_endpoint: String,
    client_id: String,
    refresh_token: Option<String>,
    /// The RFC 8707 resource indicator (the MCP server URL) the token is bound
    /// to. Optional for back-compat with states vaulted before this existed.
    #[serde(default)]
    resource: Option<String>,
    /// Unix timestamp when Toolport received the latest token response.
    /// Optional for states vaulted by older Toolport versions.
    #[serde(default)]
    issued_at: Option<u64>,
    /// Unix access-token expiry derived from the provider's `expires_in`.
    /// Optional because OAuth providers are allowed to omit the lifetime.
    #[serde(default)]
    expires_at: Option<u64>,
}

#[derive(Debug, PartialEq, Eq)]
enum RefreshDecision {
    NotNeeded,
    Refresh,
    Reauthenticate,
}

struct RefreshedToken {
    access_token: String,
    expires_at: Option<u64>,
}

fn now_epoch_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn refresh_decision(state: &OAuthState, now: u64) -> RefreshDecision {
    let Some(expires_at) = state.expires_at else {
        // Backward-compatible and provider-compatible: without a known expiry,
        // retain the existing reactive refresh on 401/403.
        return RefreshDecision::NotNeeded;
    };
    if now.saturating_add(PROACTIVE_REFRESH_SKEW_SECS) < expires_at {
        RefreshDecision::NotNeeded
    } else if state.refresh_token.is_some() {
        RefreshDecision::Refresh
    } else {
        RefreshDecision::Reauthenticate
    }
}

/// Persist what's needed to refresh this server's token later.
pub fn store_oauth_state(
    server_id: &str,
    token_endpoint: &str,
    client_id: &str,
    refresh_token: Option<String>,
    resource: Option<String>,
    issued_at: u64,
    expires_at: Option<u64>,
) -> Result<(), String> {
    let state = OAuthState {
        token_endpoint: token_endpoint.to_string(),
        client_id: client_id.to_string(),
        refresh_token,
        resource,
        issued_at: Some(issued_at),
        expires_at,
    };
    let json = serde_json::to_string(&state).map_err(|e| e.to_string())?;
    secrets::set_secret(server_id, STATE_KEY, &json)
}

fn load_state(server_id: &str) -> Option<OAuthState> {
    secrets::get_secret(server_id, STATE_KEY)
        .and_then(|s| serde_json::from_str(&s).ok())
}

/// Remove refresh metadata when the user clears OAuth or replaces it with a
/// manually pasted bearer token. Otherwise stale vaulted state could silently
/// recreate a credential the user explicitly removed.
pub fn clear_oauth_state(server_id: &str) -> Result<(), String> {
    secrets::delete_secret(server_id, STATE_KEY)
}

/// Use the stored refresh token to mint a fresh access token, vault it, and
/// return it.
fn refresh_token_with_expiry(server_id: &str) -> Result<RefreshedToken, String> {
    let state = load_state(server_id).ok_or("no stored OAuth state to refresh")?;
    let rt = state
        .refresh_token
        .as_deref()
        .ok_or("no refresh token available")?;
    // Block a rebind to the internal network unless the token endpoint is itself a
    // local/LAN host (a self-hosted auth server). Fail closed (block) if the stored
    // endpoint host can't be parsed.
    let block_private = oauth::host_of_url(&state.token_endpoint)
        .map(|h| !oauth::host_is_private(&h))
        .unwrap_or(true);
    let tokens = oauth::refresh(
        &state.token_endpoint,
        &state.client_id,
        rt,
        state.resource.as_deref(),
        block_private,
    )?;
    secrets::set_secret(server_id, secrets::HTTP_AUTH_KEY, &tokens.access_token)?;
    // Persist a rotated refresh token if the server issued one.
    let new_state = OAuthState {
        token_endpoint: state.token_endpoint,
        client_id: state.client_id,
        refresh_token: tokens.refresh_token.or(state.refresh_token),
        resource: state.resource,
        issued_at: Some(tokens.issued_at),
        expires_at: tokens.expires_at,
    };
    let json = serde_json::to_string(&new_state).map_err(|e| e.to_string())?;
    secrets::set_secret(server_id, STATE_KEY, &json)?;
    Ok(RefreshedToken {
        access_token: tokens.access_token,
        expires_at: tokens.expires_at,
    })
}

pub fn refresh_token(server_id: &str) -> Result<String, String> {
    refresh_token_with_expiry(server_id).map(|token| token.access_token)
}

/// Refresh before the known expiry. A legacy/provider state with no expiry is a
/// no-op and continues to use the 401/403 fallback. If the deadline is close but
/// no refresh token exists, return an auth-classified error so the existing
/// per-server "Needs sign-in" UI appears before a failed tool call.
fn refresh_token_if_needed(server_id: &str) -> Result<Option<String>, String> {
    let Some(state) = load_state(server_id) else {
        return Ok(None);
    };
    match refresh_decision(&state, now_epoch_seconds()) {
        RefreshDecision::NotNeeded => Ok(None),
        RefreshDecision::Refresh => refresh_token(server_id)
            .map(Some)
            .map_err(|e| format!("OAuth token refresh failed; needs authentication: {e}")),
        RefreshDecision::Reauthenticate => Err(
            "OAuth access token expires soon and no refresh token is available; needs authentication"
                .to_string(),
        ),
    }
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
/// When authed, the transport gets a refresh callback: on a mid-session 401/403 it
/// mints a fresh access token from the stored refresh token and retries, so a
/// short-lived token expiring no longer breaks the session until reconnect.
fn authed_transport(
    url: &str,
    token: Option<String>,
    server_id: &str,
    block_private: bool,
) -> Result<HttpTransport, String> {
    if token.is_some() {
        require_secure_for_auth(url)?;
    }
    let refresh: Option<RefreshFn> = if token.is_some() {
        let sid = server_id.to_string();
        // Keep the proactive deadline in memory. This avoids a keychain read on
        // every tool call while still updating the deadline after each refresh.
        let refresh_at = load_state(server_id)
            .and_then(|state| state.expires_at)
            .map(|expires_at| expires_at.saturating_sub(PROACTIVE_REFRESH_SKEW_SECS));
        let next_refresh_at = Mutex::new(refresh_at);
        Some(Box::new(move |force| {
            if !force {
                let deadline = *next_refresh_at
                    .lock()
                    .map_err(|_| "OAuth refresh deadline lock poisoned".to_string())?;
                match deadline {
                    Some(refresh_at) if now_epoch_seconds() >= refresh_at => {}
                    _ => return Ok(None),
                }
            }

            let refreshed = refresh_token_with_expiry(&sid)
                .map_err(|e| format!("OAuth token refresh failed; needs authentication: {e}"))?;
            let deadline = refreshed
                .expires_at
                .map(|expires_at| expires_at.saturating_sub(PROACTIVE_REFRESH_SKEW_SECS));
            *next_refresh_at
                .lock()
                .map_err(|_| "OAuth refresh deadline lock poisoned".to_string())? = deadline;
            Ok(Some(refreshed.access_token))
        }))
    } else {
        None
    };
    // The resolver enforces the SSRF policy at connect time (DNS-rebind safe); it
    // mirrors `guard_connect_target`: link-local/metadata blocked for all, private
    // blocked only for untrusted-provenance servers.
    Ok(HttpTransport::guarded(url, token, refresh, block_private))
}

/// Provenance Toolport doesn't trust to point at the user's private network. Shared
/// imports (`"shared"`) and public-registry entries (`"registry"`) are
/// attacker-influenceable; user-added, client-imported, curated-catalog, and team
/// servers are not, so their local URLs (e.g. a localhost MCP server) still connect.
fn is_untrusted_source(source: Option<&str>) -> bool {
    matches!(source, Some("shared") | Some("registry"))
}

/// True if `host` is a link-local / cloud-metadata literal or a name resolving
/// to one. Covers IPv4 `169.254.x`, IPv6 `fe80::/10`, IPv4-mapped forms, and the
/// AWS IPv6 metadata address `fd00:ec2::254` (see `oauth::ip_is_link_local`).
/// `169.254.169.254` and its IPv6 peers are the classic SSRF target for stealing
/// cloud credentials.
fn host_is_link_local(host: &str) -> bool {
    use std::net::{IpAddr, ToSocketAddrs};
    let h = host.trim();
    if let Ok(ip) = h.parse::<IpAddr>() {
        return oauth::ip_is_link_local(&ip);
    }
    (h, 0u16)
        .to_socket_addrs()
        .map(|addrs| addrs.map(|a| a.ip()).any(|ip| oauth::ip_is_link_local(&ip)))
        .unwrap_or(false)
}

/// SSRF guard run before connecting to a remote server. Link-local / cloud-metadata
/// is refused for EVERY server (never a valid MCP target, and the classic way to
/// steal cloud credentials). Other private/loopback hosts are refused only for
/// untrusted-provenance servers, so the user's own localhost server still works.
fn guard_connect_target(server: &ServerEntry) -> Result<(), String> {
    let host = oauth::host_of_url(server.url.as_deref().unwrap_or("")).unwrap_or_default();
    if host_is_link_local(&host) {
        return Err(format!(
            "Toolport refused to connect to {host}: link-local / cloud-metadata addresses \
             (169.254.x) are never a valid MCP server and are a common SSRF target."
        ));
    }
    if is_untrusted_source(server.source.as_deref()) && oauth::host_is_private(&host) {
        return Err(format!(
            "Toolport refused to connect \"{}\" to the private address {host}: it came from \
             an untrusted source ({}). If you trust it, add the server yourself.",
            server.name,
            server.source.as_deref().unwrap_or("unknown")
        ));
    }
    Ok(())
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
    connect_remote_with_handler(server, None)
}

/// Like [`connect_remote`], but wires server-initiated JSON-RPC (sampling, roots, …)
/// through `handler` when the downstream server asks mid-call.
pub fn connect_remote_with_handler(
    server: &ServerEntry,
    server_handler: Option<ServerRequestHandler>,
) -> Result<DownstreamServer, String> {
    guard_connect_target(server)?;
    let url = server.url.as_deref().unwrap_or("");
    let server_id = &server.id;
    // Untrusted-provenance servers also get private/loopback refused at the resolver,
    // matching `guard_connect_target`'s pre-check but closing the DNS-rebind TOCTOU.
    let block_private = is_untrusted_source(server.source.as_deref());
    let stored_auth = secrets::get_secret(server_id, secrets::HTTP_AUTH_KEY)
        .or_else(|| first_vaulted_secret(server));
    let auth = match refresh_token_if_needed(server_id)? {
        Some(fresh) => Some(fresh),
        None => stored_auth,
    };
    let mut transport = authed_transport(url, auth, server_id, block_private)?;
    if let Some(ref handler) = server_handler {
        transport.set_server_request_handler(handler.clone());
    }
    match DownstreamServer::connect(server_id.to_string(), Box::new(transport)) {
        Ok(ds) => Ok(ds),
        Err(e) if is_auth_error(&e) => match refresh_token(server_id) {
            Ok(fresh) => {
                let mut transport = authed_transport(url, Some(fresh), server_id, block_private)?;
                if let Some(handler) = server_handler.clone() {
                    transport.set_server_request_handler(handler);
                }
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

    fn oauth_state(expires_at: Option<u64>, refresh_token: Option<&str>) -> OAuthState {
        OAuthState {
            token_endpoint: "https://auth.example.com/token".into(),
            client_id: "client".into(),
            refresh_token: refresh_token.map(str::to_string),
            resource: Some("https://mcp.example.com".into()),
            issued_at: Some(1_000),
            expires_at,
        }
    }

    #[test]
    fn refresh_decision_uses_expiry_safety_window() {
        assert_eq!(
            refresh_decision(&oauth_state(Some(1_061), Some("refresh")), 1_000),
            RefreshDecision::NotNeeded
        );
        assert_eq!(
            refresh_decision(&oauth_state(Some(1_060), Some("refresh")), 1_000),
            RefreshDecision::Refresh
        );
        assert_eq!(
            refresh_decision(&oauth_state(Some(999), Some("refresh")), 1_000),
            RefreshDecision::Refresh
        );
    }

    #[test]
    fn refresh_decision_requests_reauth_without_refresh_token() {
        assert_eq!(
            refresh_decision(&oauth_state(Some(1_060), None), 1_000),
            RefreshDecision::Reauthenticate
        );
        assert_eq!(
            refresh_decision(&oauth_state(None, None), 1_000),
            RefreshDecision::NotNeeded
        );
    }

    #[test]
    fn oauth_state_from_older_versions_keeps_unknown_expiry() {
        let state: OAuthState = serde_json::from_str(
            r#"{"token_endpoint":"https://auth.example.com/token","client_id":"client","refresh_token":"refresh","resource":"https://mcp.example.com"}"#,
        )
        .unwrap();

        assert_eq!(state.issued_at, None);
        assert_eq!(state.expires_at, None);
        assert_eq!(refresh_decision(&state, 1_000), RefreshDecision::NotNeeded);
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

    #[test]
    fn link_local_detection() {
        assert!(host_is_link_local("169.254.169.254")); // v4 cloud metadata
        assert!(host_is_link_local("169.254.0.1"));
        assert!(host_is_link_local("fe80::1")); // v6 link-local
        assert!(host_is_link_local("fd00:ec2::254")); // AWS v6 metadata (ULA)
        assert!(host_is_link_local("::ffff:169.254.169.254")); // IPv4-mapped metadata
        assert!(!host_is_link_local("127.0.0.1"));
        assert!(!host_is_link_local("::1")); // v6 loopback is not metadata
        assert!(!host_is_link_local("10.0.0.1"));
        assert!(!host_is_link_local("8.8.8.8"));
        assert!(!host_is_link_local("2606:4700:4700::1111")); // public v6
    }

    #[test]
    fn untrusted_sources() {
        assert!(is_untrusted_source(Some("shared")));
        assert!(is_untrusted_source(Some("registry")));
        assert!(!is_untrusted_source(Some("user")));
        assert!(!is_untrusted_source(Some("manual")));
        assert!(!is_untrusted_source(Some("curated")));
        assert!(!is_untrusted_source(Some("imported:cursor")));
        assert!(!is_untrusted_source(None));
    }

    fn remote_server(url: &str, source: Option<&str>) -> ServerEntry {
        ServerEntry {
            id: "t".into(),
            name: "Test".into(),
            transport: "http".into(),
            command: None,
            args: vec![],
            env: vec![],
            url: Some(url.into()),
            source: source.map(String::from),
            disabled_tools: vec![],
            cwd: None,
            unknown_fields: serde_json::Map::new(),
        }
    }

    #[test]
    fn guard_blocks_metadata_even_for_user_added() {
        let s = remote_server("http://169.254.169.254/latest/meta-data/", Some("user"));
        assert!(guard_connect_target(&s).is_err());
    }

    #[test]
    fn guard_blocks_private_for_untrusted_source() {
        let s = remote_server("http://127.0.0.1:6379/", Some("shared"));
        assert!(guard_connect_target(&s).is_err());
    }

    #[test]
    fn guard_allows_localhost_for_user_added() {
        let s = remote_server("http://127.0.0.1:8080/mcp", Some("user"));
        assert!(guard_connect_target(&s).is_ok());
    }

    #[test]
    fn guard_allows_public_host_for_any_source() {
        let s = remote_server("https://8.8.8.8/mcp", Some("shared"));
        assert!(guard_connect_target(&s).is_ok());
    }
}
