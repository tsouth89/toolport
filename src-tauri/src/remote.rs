//! Remote (http) server connection with automatic OAuth token refresh.
//!
//! When a connection fails with an auth error and we have a stored refresh
//! token, we transparently refresh the access token and retry once. The OAuth
//! state (token endpoint, client id, refresh token) is vaulted alongside the
//! access token.

use serde::{Deserialize, Serialize};
use std::sync::atomic::AtomicU8;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::downstream::{
    DownstreamServer, HttpTransport, ProgressSink, RefreshFn, ResourceUpdatedSink,
    ScopeReauthorizeFn, ServerRequestHandler, Transport,
};
use crate::registry::ServerEntry;
use crate::{oauth, secrets};

const STATE_KEY: &str = "__oauth_state__";
pub const OAUTH_STATE_KEY: &str = STATE_KEY;
/// Refresh before the exact deadline so the token cannot expire while an MCP
/// request is in flight.
const PROACTIVE_REFRESH_SKEW_SECS: u64 = 60;
/// Avoid hammering a temporarily unavailable OAuth endpoint on every tool call
/// while still retrying within the pre-expiry safety window.
const PROACTIVE_REFRESH_RETRY_SECS: u64 = 15;

#[derive(Serialize, Deserialize)]
struct OAuthState {
    /// Validated authorization-server issuer that owns the client credentials.
    /// Optional for states vaulted before Toolport recorded issuer binding.
    #[serde(default)]
    issuer: Option<String>,
    token_endpoint: String,
    client_id: String,
    refresh_token: Option<String>,
    /// The RFC 8707 resource indicator (the MCP server URL) the token is bound
    /// to. Optional for back-compat with states vaulted before this existed.
    #[serde(default)]
    resource: Option<String>,
    /// Scope set requested for the current authorization. Optional for vaulted
    /// states written before Toolport supported runtime scope step-up.
    #[serde(default)]
    scope: Option<String>,
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
    issuer: Option<String>,
    token_endpoint: &str,
    client_id: &str,
    refresh_token: Option<String>,
    resource: Option<String>,
    scope: Option<String>,
    issued_at: u64,
    expires_at: Option<u64>,
) -> Result<(), String> {
    let state = OAuthState {
        issuer,
        token_endpoint: token_endpoint.to_string(),
        client_id: client_id.to_string(),
        refresh_token,
        resource,
        scope,
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

fn issuer_bound_token_endpoint<'a>(
    expected_issuer: &str,
    endpoints: &'a oauth::Endpoints,
) -> Result<&'a str, String> {
    if endpoints.issuer == expected_issuer {
        Ok(&endpoints.token_endpoint)
    } else {
        Err(
            "the server's OAuth issuer changed; needs authentication before credentials can be reused"
                .to_string(),
        )
    }
}

/// Remove refresh metadata when the user clears OAuth or replaces it with a
/// manually pasted bearer token. Otherwise stale vaulted state could silently
/// recreate a credential the user explicitly removed.
pub fn clear_oauth_state(server_id: &str) -> Result<(), String> {
    // Attempt both, then surface the first failure. Swallowing the
    // client-credentials delete would leave state that silently reacquires with
    // the long-lived secret after the user believed they had cleared auth; only
    // attempting the second on success would leave the other key behind.
    let headless = secrets::delete_secret(server_id, CC_STATE_KEY);
    let interactive = secrets::delete_secret(server_id, STATE_KEY);
    headless.and(interactive)
}

// ── Client-credentials flow (SBS-524) ──────────────────────────────────────

const CC_STATE_KEY: &str = "__oauth_cc_state__";

/// What a later reacquisition needs, resolved once at connect time.
///
/// The reacquire seam (`refresh_token_with_expiry`) is reached from the request
/// path with only a server id, so everything needed to mint another token is
/// captured here rather than looked up from the registry again. That also means a
/// reacquisition uses the same issuer and method the first one did, instead of
/// silently following a metadata document that changed underneath it.
///
/// Holds no secret: the client secret stays in the vault under its own key.
#[derive(Serialize, Deserialize)]
struct ClientCredentialsState {
    issuer: String,
    token_endpoint: String,
    client_id: String,
    /// The negotiated `token_endpoint_auth_method` identifier.
    method: String,
    #[serde(default)]
    scope: Option<String>,
    /// RFC 8707 resource indicator (the MCP server URL).
    resource: String,
    #[serde(default)]
    expires_at: Option<u64>,
}

/// Discover, negotiate an auth method, and mint an access token for a headless
/// server. Vaults the token and the state a later reacquisition needs.
///
/// Fails closed rather than falling back to the interactive flow: a server that
/// silently opened a browser would be unusable in the environment this exists for.
fn acquire_client_credentials(
    server_id: &str,
    resource: &str,
    config: &crate::registry::ClientCredentials,
) -> Result<RefreshedToken, String> {
    let secret = secrets::get_secret(server_id, secrets::CLIENT_SECRET_KEY).ok_or(
        "no client secret is vaulted for this server; add one before connecting \
         (client-credentials auth never falls back to a browser sign-in)",
    )?;
    let configured = match config.token_endpoint_auth_method.as_deref() {
        Some(raw) => Some(oauth::ClientAuthMethod::parse(raw).ok_or_else(|| {
            format!("unknown token_endpoint_auth_method {raw:?} configured for this server")
        })?),
        None => None,
    };

    let endpoints = oauth::discover(resource)?;
    let method = oauth::select_client_auth_method(
        configured,
        endpoints.token_endpoint_auth_methods_supported.as_deref(),
    )?;
    // Prefer the user's explicit scopes; otherwise take what discovery advertises
    // for this protected resource, matching the interactive flow.
    let scope = config.scope.clone().or_else(|| endpoints.scope.clone());

    let block_private = oauth::host_of_url(&endpoints.token_endpoint)
        .map(|h| !oauth::host_is_definitely_private(&h))
        .unwrap_or(true);
    let tokens = oauth::client_credentials_token(
        &endpoints.token_endpoint,
        &config.client_id,
        &secret,
        method,
        scope.as_deref(),
        Some(resource),
        block_private,
    )?;

    // State first, then the access token: a failure between the two leaves the
    // next attempt able to reacquire, where the reverse order could strand a
    // token with no way to mint its successor. Same ordering as the refresh path.
    let state = ClientCredentialsState {
        issuer: endpoints.issuer,
        token_endpoint: endpoints.token_endpoint,
        client_id: config.client_id.clone(),
        method: method.as_str().to_string(),
        scope,
        resource: resource.to_string(),
        expires_at: tokens.expires_at,
    };
    let json = serde_json::to_string(&state).map_err(|e| e.to_string())?;
    secrets::set_secret(server_id, CC_STATE_KEY, &json)?;
    secrets::set_secret(server_id, secrets::HTTP_AUTH_KEY, &tokens.access_token)?;
    Ok(RefreshedToken {
        access_token: tokens.access_token,
        expires_at: tokens.expires_at,
    })
}

/// Mint a replacement token from vaulted client-credentials state.
///
/// There is no refresh token to redeem (RFC 6749 §4.4.3), so this re-runs the
/// grant. It reuses the recorded token endpoint and method rather than
/// rediscovering, and re-verifies the issuer when it does discover, so a resource
/// that changed authorization server fails closed instead of sending the secret
/// somewhere new.
fn reacquire_client_credentials(server_id: &str) -> Result<RefreshedToken, String> {
    let state: ClientCredentialsState = secrets::get_secret(server_id, CC_STATE_KEY)
        .and_then(|s| serde_json::from_str(&s).ok())
        .ok_or("no client-credentials state to reacquire from")?;
    let secret = secrets::get_secret(server_id, secrets::CLIENT_SECRET_KEY)
        .ok_or("the vaulted client secret is gone; re-add it for this server")?;
    let method = oauth::ClientAuthMethod::parse(&state.method)
        .ok_or_else(|| format!("vaulted auth method {:?} is not recognized", state.method))?;

    let endpoints = oauth::discover(&state.resource).map_err(|e| {
        format!("could not verify the stored OAuth issuer before reusing the client secret: {e}")
    })?;
    let token_endpoint = issuer_bound_token_endpoint(&state.issuer, &endpoints)?;

    let block_private = oauth::host_of_url(token_endpoint)
        .map(|h| !oauth::host_is_definitely_private(&h))
        .unwrap_or(true);
    let tokens = oauth::client_credentials_token(
        token_endpoint,
        &state.client_id,
        &secret,
        method,
        state.scope.as_deref(),
        Some(&state.resource),
        block_private,
    )?;

    let next = ClientCredentialsState {
        token_endpoint: token_endpoint.to_string(),
        expires_at: tokens.expires_at,
        ..state
    };
    let json = serde_json::to_string(&next).map_err(|e| e.to_string())?;
    secrets::set_secret(server_id, CC_STATE_KEY, &json)?;
    secrets::set_secret(server_id, secrets::HTTP_AUTH_KEY, &tokens.access_token)?;
    Ok(RefreshedToken {
        access_token: tokens.access_token,
        expires_at: tokens.expires_at,
    })
}

/// Drop vaulted client-credentials state so the next connect re-acquires.
///
/// Called whenever the configuration changes. The state records the issuer,
/// method and scopes resolved at acquisition time, so leaving it in place after
/// an edit would keep minting tokens against the OLD configuration and the user's
/// change would appear to do nothing.
pub fn reset_client_credentials(server_id: &str) -> Result<(), String> {
    // Errors propagate. A failed delete leaves state that would keep minting
    // tokens under the OLD configuration, so reporting success here would tell
    // the user their change had taken effect when it had not. Deleting a key that
    // is not there is already `Ok` in every backend, so this does not fail on a
    // server being configured for the first time.
    secrets::delete_secret(server_id, CC_STATE_KEY)?;
    // The access token was minted under the previous configuration too.
    secrets::delete_secret(server_id, secrets::HTTP_AUTH_KEY)
}

/// Expiry of the vaulted client-credentials token, if this server uses that flow.
fn client_credentials_expiry(server_id: &str) -> Option<u64> {
    let state: ClientCredentialsState = secrets::get_secret(server_id, CC_STATE_KEY)
        .and_then(|s| serde_json::from_str(&s).ok())?;
    // A server that reports no lifetime keeps the reactive 401/403 behaviour,
    // matching the interactive flow. Returning 0 here would reacquire on every
    // single connect.
    state.expires_at
}

/// Is this server configured for the headless flow?
fn uses_client_credentials(server: &ServerEntry) -> bool {
    server
        .client_credentials
        .as_ref()
        .is_some_and(|c| !c.client_id.trim().is_empty())
}

/// Use the stored refresh token to mint a fresh access token, vault it, and
/// return it.
fn refresh_token_with_expiry(server_id: &str) -> Result<RefreshedToken, String> {
    // Client-credentials servers have no refresh token by construction, so they
    // reacquire instead. Checked first because this is the seam BOTH the proactive
    // pre-expiry path and the reactive 401/403 retry go through; branching here
    // means neither has to know which flow a server uses.
    if secrets::get_secret(server_id, CC_STATE_KEY).is_some() {
        return reacquire_client_credentials(server_id);
    }
    let state = load_state(server_id).ok_or("no stored OAuth state to refresh")?;
    let rt = state
        .refresh_token
        .as_deref()
        .ok_or("no refresh token available")?;
    // Credentials minted under a known issuer may only be sent to endpoints from
    // that issuer's current validated metadata. If the MCP resource changes its
    // authorization server, fail closed so the UI asks the user to authenticate
    // and register a fresh client instead of reusing the old credentials.
    let refreshed_endpoints = match (state.issuer.as_deref(), state.resource.as_deref()) {
        (Some(expected_issuer), Some(resource)) => {
            let endpoints = oauth::discover(resource).map_err(|e| {
                format!("could not verify the stored OAuth issuer; needs authentication: {e}")
            })?;
            issuer_bound_token_endpoint(expected_issuer, &endpoints)?;
            Some(endpoints)
        }
        _ => None,
    };
    let token_endpoint = refreshed_endpoints
        .as_ref()
        .map(|e| e.token_endpoint.as_str())
        .unwrap_or(&state.token_endpoint);

    // Block a rebind to the internal network unless the token endpoint is itself a
    // local/LAN host (a self-hosted auth server). Fail closed (block) if the stored
    // endpoint host can't be parsed OR can't be positively confirmed local, so an
    // unresolvable stored endpoint stays screened rather than opening the guard (#422).
    let block_private = oauth::host_of_url(token_endpoint)
        .map(|h| !oauth::host_is_definitely_private(&h))
        .unwrap_or(true);
    let tokens = oauth::refresh(
        token_endpoint,
        &state.client_id,
        rt,
        state.resource.as_deref(),
        block_private,
    )?;
    // Persist rotated refresh metadata first. If replacing the access token then
    // fails, the next attempt still has the new refresh token and can recover;
    // the reverse order could strand a new access token with an invalidated old
    // refresh token after a second-write failure.
    let new_state = OAuthState {
        issuer: state.issuer,
        token_endpoint: token_endpoint.to_string(),
        client_id: state.client_id,
        refresh_token: tokens.refresh_token.or(state.refresh_token),
        resource: state.resource,
        scope: state.scope,
        issued_at: Some(tokens.issued_at),
        expires_at: tokens.expires_at,
    };
    let json = serde_json::to_string(&new_state).map_err(|e| e.to_string())?;
    secrets::set_secret(server_id, STATE_KEY, &json)?;
    secrets::set_secret(server_id, secrets::HTTP_AUTH_KEY, &tokens.access_token)?;
    Ok(RefreshedToken {
        access_token: tokens.access_token,
        expires_at: tokens.expires_at,
    })
}

/// Complete an interactive step-up flow for a runtime `insufficient_scope`
/// challenge. A fresh authorization (and client registration when needed) is
/// intentional here: refresh-token grants cannot obtain user consent for new
/// permissions. Persist the full new state before replacing the access token so
/// a partial keychain write cannot strand rotated credentials.
fn reauthorize_for_scope(
    server_id: &str,
    resource: &str,
    required_scope: &str,
) -> Result<RefreshedToken, String> {
    let previous = load_state(server_id)
        .ok_or("saved OAuth state is unavailable; authenticate again to grant additional scope")?;
    let requested = oauth::scope_union(previous.scope.as_deref(), Some(required_scope));
    let result = oauth::authenticate_with_scope(resource, requested.as_deref())?;
    store_oauth_state(
        server_id,
        Some(result.issuer),
        &result.token_endpoint,
        &result.client_id,
        result.refresh_token,
        Some(resource.to_string()),
        result.scope,
        result.issued_at,
        result.expires_at,
    )?;
    secrets::set_secret(server_id, secrets::HTTP_AUTH_KEY, &result.access_token)?;
    Ok(RefreshedToken {
        access_token: result.access_token,
        expires_at: result.expires_at,
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
    // Same pre-expiry rule for the headless flow, minus the "no refresh token"
    // branch: reacquiring needs no user interaction, so a near-deadline token is
    // simply replaced rather than surfaced as "needs sign-in".
    if let Some(expires_at) = client_credentials_expiry(server_id) {
        if now_epoch_seconds().saturating_add(PROACTIVE_REFRESH_SKEW_SECS) >= expires_at {
            return Ok(reacquire_client_credentials(server_id)
                .ok()
                .map(|t| t.access_token));
        }
        return Ok(None);
    }
    let Some(state) = load_state(server_id) else {
        return Ok(None);
    };
    match refresh_decision(&state, now_epoch_seconds()) {
        RefreshDecision::NotNeeded => Ok(None),
        // The token may still be valid throughout the safety window. A transient
        // refresh failure falls back to it; a real 401/403 forces another refresh.
        RefreshDecision::Refresh => Ok(refresh_token(server_id).ok()),
        RefreshDecision::Reauthenticate => Err(
            "OAuth access token expires soon and no refresh token is available; needs authentication"
                .to_string(),
        ),
    }
}

/// True when `code` appears in `s` as a standalone number rather than as a run of
/// digits inside a longer one.
///
/// A bare substring test reads an auth failure out of an OS error number
/// (`os error 10401`), a port (`127.0.0.1:4013`), or a duration (`4030ms`).
fn mentions_status(s: &str, code: &str) -> bool {
    s.match_indices(code).any(|(i, _)| {
        let before = s[..i].chars().next_back();
        let after = s[i + code.len()..].chars().next();
        !before.is_some_and(|c| c.is_ascii_digit()) && !after.is_some_and(|c| c.is_ascii_digit())
    })
}

pub fn is_auth_error(e: &str) -> bool {
    let lower = e.to_lowercase();
    mentions_status(e, "401")
        || mentions_status(e, "403")
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
    // Shared by ordinary refresh and scope step-up so a newly-authorized token's
    // expiry replaces the previous token's proactive deadline immediately.
    let refresh_at = load_state(server_id)
        .and_then(|state| state.expires_at)
        .map(|expires_at| expires_at.saturating_sub(PROACTIVE_REFRESH_SKEW_SECS));
    let next_refresh_at = Arc::new(Mutex::new(refresh_at));
    // The request path and the background subscription listener can refresh or
    // step up concurrently. Serialize credential-changing flows so an older
    // refresh result cannot overwrite a newer interactive authorization state.
    let credential_update = Arc::new(Mutex::new(()));
    let refresh: Option<RefreshFn> = if token.is_some() {
        let sid = server_id.to_string();
        // Keep the proactive deadline in memory. This avoids a keychain read on
        // every tool call while still updating the deadline after each refresh.
        let next_refresh_at = Arc::clone(&next_refresh_at);
        let credential_update = Arc::clone(&credential_update);
        Some(Box::new(move |force| {
            let _update = credential_update
                .lock()
                .map_err(|_| "OAuth credential-update lock poisoned".to_string())?;
            if !force {
                let deadline = *next_refresh_at
                    .lock()
                    .map_err(|_| "OAuth refresh deadline lock poisoned".to_string())?;
                match deadline {
                    Some(refresh_at) if now_epoch_seconds() >= refresh_at => {}
                    _ => return Ok(None),
                }
            }

            let refreshed = match refresh_token_with_expiry(&sid) {
                Ok(refreshed) => refreshed,
                Err(e) => {
                    if !force {
                        *next_refresh_at
                            .lock()
                            .map_err(|_| "OAuth refresh deadline lock poisoned".to_string())? =
                            Some(now_epoch_seconds().saturating_add(PROACTIVE_REFRESH_RETRY_SECS));
                    }
                    return Err(format!(
                        "OAuth token refresh failed; needs authentication: {e}"
                    ));
                }
            };
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
    let scope_reauthorize: Option<ScopeReauthorizeFn> = if token.is_some() && load_state(server_id).is_some() {
        let sid = server_id.to_string();
        let resource = url.to_string();
        let next_refresh_at = Arc::clone(&next_refresh_at);
        let credential_update = Arc::clone(&credential_update);
        Some(Box::new(move |scope| {
            let _update = credential_update
                .lock()
                .map_err(|_| "OAuth credential-update lock poisoned".to_string())?;
            let token = reauthorize_for_scope(&sid, &resource, scope)?;
            let deadline = token
                .expires_at
                .map(|expires_at| expires_at.saturating_sub(PROACTIVE_REFRESH_SKEW_SECS));
            *next_refresh_at
                .lock()
                .map_err(|_| "OAuth refresh deadline lock poisoned".to_string())? = deadline;
            Ok(token.access_token)
        }))
    } else {
        None
    };
    // The resolver enforces the SSRF policy at connect time (DNS-rebind safe); it
    // mirrors `guard_connect_target`: link-local/metadata blocked for all, private
    // blocked only for untrusted-provenance servers.
    let mut transport = HttpTransport::guarded(url, token, refresh, block_private);
    transport.set_scope_reauthorize(scope_reauthorize);
    // Declared per request only while the flow is actually in use, which is what
    // the extension requires. Keyed off vaulted state rather than registry config
    // so it is true of the credential actually being sent: a server configured for
    // the flow but not yet provisioned has nothing to declare.
    if secrets::get_secret(server_id, CC_STATE_KEY).is_some() {
        transport.declare_extension(
            crate::downstream::OAUTH_CLIENT_CREDENTIALS_EXTENSION,
            serde_json::json!({}),
        );
    }
    Ok(transport)
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
    connect_remote_with_handler(server, None, None, None, None)
}

/// Like [`connect_remote`], but wires server-initiated JSON-RPC (sampling, roots, …)
/// through `handler` when the downstream server asks mid-call, and optionally fans
/// `notifications/resources/updated` from SSE response streams (SOU-394), and
/// routes `notifications/progress` back to the client that minted the token
/// (SOU-444).
pub fn connect_remote_with_handler(
    server: &ServerEntry,
    server_handler: Option<ServerRequestHandler>,
    resource_updated: Option<ResourceUpdatedSink>,
    progress: Option<ProgressSink>,
    change_dirty: Option<Arc<AtomicU8>>,
) -> Result<DownstreamServer, String> {
    guard_connect_target(server)?;
    let url = server.url.as_deref().unwrap_or("");
    let server_id = &server.id;
    // Untrusted-provenance servers also get private/loopback refused at the resolver,
    // matching `guard_connect_target`'s pre-check but closing the DNS-rebind TOCTOU.
    let block_private = is_untrusted_source(server.source.as_deref());
    // First connect for a headless server: mint a token now. Only this path has the
    // registry config (client id, method, scopes); every later reacquisition runs
    // from the state vaulted here, which is why it can go through the shared seam
    // with just a server id.
    if uses_client_credentials(server) && secrets::get_secret(server_id, CC_STATE_KEY).is_none() {
        let config = server
            .client_credentials
            .as_ref()
            .expect("uses_client_credentials checked it");
        acquire_client_credentials(server_id, url, config)?;
    }
    let stored_auth = secrets::get_secret(server_id, secrets::HTTP_AUTH_KEY)
        .or_else(|| first_vaulted_secret(server));
    let auth = match refresh_token_if_needed(server_id)? {
        Some(fresh) => Some(fresh),
        None => stored_auth,
    };
    // Remember exactly what we hand the transport. The transport force-refreshes
    // internally on a 401/403 and vaults the result, so if the vaulted token
    // differs from this afterwards, an exchange already happened during this
    // connect (SOU-474).
    let sent_auth = auth.clone();
    let mut transport = authed_transport(url, auth, server_id, block_private)?;
    if let Some(ref handler) = server_handler {
        transport.set_server_request_handler(handler.clone());
    }
    transport.set_resource_updated_sink(resource_updated.clone());
    transport.set_progress_sink(progress.clone());
    transport.set_change_sink(change_dirty.clone());
    match DownstreamServer::connect(server_id.to_string(), Box::new(transport)) {
        Ok(ds) => Ok(ds),
        // The transport already gets one forced refresh per token on a 401/403.
        // If it spent one during this connect, the vault now holds a token that
        // has ALREADY been rejected, so minting yet another cannot help - and
        // against a provider that rotates the refresh token on use, each needless
        // exchange consumes a further link of the chain. Retry only when the
        // transport had no refresh of its own to spend (SOU-474).
        Err(e)
            if is_auth_error(&e)
                && secrets::get_secret(server_id, secrets::HTTP_AUTH_KEY)
                    .is_some_and(|vaulted| Some(&vaulted) != sent_auth.as_ref()) =>
        {
            Err(e)
        }
        Err(e) if is_auth_error(&e) => match refresh_token(server_id) {
            Ok(fresh) => {
                let mut transport = authed_transport(url, Some(fresh), server_id, block_private)?;
                if let Some(handler) = server_handler.clone() {
                    transport.set_server_request_handler(handler);
                }
                transport.set_resource_updated_sink(resource_updated);
                transport.set_progress_sink(progress);
                transport.set_change_sink(change_dirty);
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
    fn a_status_code_buried_in_a_longer_number_is_not_an_auth_error() {
        // Misreading these as auth failures shows the user a "Needs sign-in"
        // prompt for a network fault and burns an OAuth refresh exchange on it.
        assert!(!is_auth_error("connection refused (os error 10401)"));
        assert!(!is_auth_error("dial tcp 127.0.0.1:4013: refused"));
        assert!(!is_auth_error("read timed out after 4030ms"));
        assert!(!is_auth_error("HTTP 500: upstream returned 14012 bytes"));
        // Still caught at a boundary, wherever it sits in the message.
        assert!(is_auth_error("HTTP 401"));
        assert!(is_auth_error("server said 403."));
        assert!(is_auth_error("(403)"));
    }

    fn oauth_state(expires_at: Option<u64>, refresh_token: Option<&str>) -> OAuthState {
        OAuthState {
            issuer: Some("https://auth.example.com".into()),
            token_endpoint: "https://auth.example.com/token".into(),
            client_id: "client".into(),
            refresh_token: refresh_token.map(str::to_string),
            resource: Some("https://mcp.example.com".into()),
            scope: Some("files:read".into()),
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
        assert_eq!(state.issuer, None);
        assert_eq!(state.scope, None);
        assert_eq!(refresh_decision(&state, 1_000), RefreshDecision::NotNeeded);
    }

    #[test]
    fn refresh_credentials_stay_bound_to_their_issuer() {
        let endpoints = |issuer: &str, token_endpoint: &str| oauth::Endpoints {
            issuer: issuer.into(),
            authorization_endpoint: "https://auth.example.com/authorize".into(),
            token_endpoint: token_endpoint.into(),
            registration_endpoint: None,
            scope: None,
            authorization_response_iss_parameter_supported: false,
            client_id_metadata_document_supported: false,
            token_endpoint_auth_methods_supported: None,
        };

        let rotated = endpoints("https://auth.example.com", "https://auth.example.com/token-v2");
        assert_eq!(
            issuer_bound_token_endpoint("https://auth.example.com", &rotated).unwrap(),
            "https://auth.example.com/token-v2"
        );

        let changed = endpoints("https://other.example.com", "https://other.example.com/token");
        assert!(issuer_bound_token_endpoint("https://auth.example.com", &changed).is_err());
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
            client_credentials: None,
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

    // ----- SBS-524: client-credentials wiring ---------------------------------

    fn cc(client_id: &str) -> crate::registry::ClientCredentials {
        crate::registry::ClientCredentials {
            client_id: client_id.into(),
            ..Default::default()
        }
    }

    fn http_server(id: &str, cc: Option<crate::registry::ClientCredentials>) -> ServerEntry {
        let mut s = remote_server("https://mcp.example.com/mcp", None);
        s.id = id.into();
        s.client_credentials = cc;
        s
    }

    /// The registry file, its backups and its exports must never carry the client
    /// secret. Only the vault does. This asserts the shape rather than trusting
    /// that no one adds a `clientSecret` field later.
    #[test]
    fn client_credentials_config_serializes_without_any_secret() {
        let mut config = cc("client-abc");
        config.token_endpoint_auth_method = Some("client_secret_basic".into());
        config.scope = Some("mcp:read mcp:write".into());

        let json = serde_json::to_string(&config).unwrap();
        assert!(json.contains("\"clientId\":\"client-abc\""), "{json}");
        assert!(
            json.contains("\"tokenEndpointAuthMethod\":\"client_secret_basic\""),
            "{json}"
        );
        assert!(
            !json.to_ascii_lowercase().contains("secret\":"),
            "the registry must not carry a client secret: {json}"
        );

        let back: crate::registry::ClientCredentials = serde_json::from_str(&json).unwrap();
        assert_eq!(back, config);
    }

    /// A newer build's fields survive a round-trip through this one, same contract
    /// as the rest of the registry.
    #[test]
    fn client_credentials_config_preserves_unknown_fields() {
        let json = r#"{"clientId":"c","somethingNewer":{"a":1}}"#;
        let parsed: crate::registry::ClientCredentials = serde_json::from_str(json).unwrap();
        let out = serde_json::to_string(&parsed).unwrap();
        assert!(out.contains("somethingNewer"), "{out}");
    }

    /// The flow is selected by configuration, and a blank client id does not
    /// select it: an empty block would otherwise send every connect down the
    /// headless path and fail with "no client secret vaulted".
    #[test]
    fn client_credentials_flow_requires_a_non_empty_client_id() {
        assert!(uses_client_credentials(&http_server("a", Some(cc("client-abc")))));
        assert!(!uses_client_credentials(&http_server("b", Some(cc("   ")))));
        assert!(!uses_client_credentials(&http_server("c", Some(cc("")))));
        assert!(!uses_client_credentials(&http_server("d", None)));
    }

    #[test]
    fn client_credentials_state_round_trips_and_tolerates_older_vaulted_shapes() {
        let state = ClientCredentialsState {
            issuer: "https://auth.example.com".into(),
            token_endpoint: "https://auth.example.com/token".into(),
            client_id: "client-abc".into(),
            method: "client_secret_basic".into(),
            scope: Some("mcp:read".into()),
            resource: "https://mcp.example.com/mcp".into(),
            expires_at: Some(1_700_000_000),
        };
        let json = serde_json::to_string(&state).unwrap();
        // Assert the exact key set rather than grepping for "secret": the auth
        // METHOD is legitimately named `client_secret_basic`, so a substring check
        // both false-positives here and would miss a field named anything else.
        let keys: std::collections::BTreeSet<String> =
            serde_json::from_str::<serde_json::Map<String, serde_json::Value>>(&json)
                .unwrap()
                .keys()
                .cloned()
                .collect();
        assert_eq!(
            keys,
            [
                "issuer",
                "token_endpoint",
                "client_id",
                "method",
                "scope",
                "resource",
                "expires_at"
            ]
            .iter()
            .map(|k| k.to_string())
            .collect::<std::collections::BTreeSet<_>>(),
            "vaulted state grew a field; make sure it is not a credential: {json}"
        );
        let back: ClientCredentialsState = serde_json::from_str(&json).unwrap();
        assert_eq!(back.issuer, state.issuer);
        assert_eq!(back.method, state.method);
        assert_eq!(back.expires_at, state.expires_at);

        // A provider that reports no lifetime keeps the reactive 401/403 path.
        let minimal: ClientCredentialsState = serde_json::from_str(
            r#"{"issuer":"https://a","tokenEndpoint":"https://a/t","clientId":"c",
                "method":"client_secret_post","resource":"https://r"}"#
                .replace("tokenEndpoint", "token_endpoint")
                .replace("clientId", "client_id")
                .as_str(),
        )
        .unwrap();
        assert_eq!(minimal.expires_at, None);
        assert_eq!(minimal.scope, None);
    }
}
