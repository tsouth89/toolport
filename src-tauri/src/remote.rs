//! Remote (http) server connection with automatic OAuth token refresh.
//!
//! When a connection fails with an auth error and we have a stored refresh
//! token, we transparently refresh the access token and retry once. The OAuth
//! state (token endpoint, client id, refresh token) is vaulted alongside the
//! access token.

use serde::{Deserialize, Serialize};

use crate::downstream::{DownstreamServer, HttpTransport};
use crate::{oauth, secrets};

const STATE_KEY: &str = "__oauth_state__";

#[derive(Serialize, Deserialize)]
struct OAuthState {
    token_endpoint: String,
    client_id: String,
    refresh_token: Option<String>,
}

/// Persist what's needed to refresh this server's token later.
pub fn store_oauth_state(
    server_id: &str,
    token_endpoint: &str,
    client_id: &str,
    refresh_token: Option<String>,
) -> Result<(), String> {
    let state = OAuthState {
        token_endpoint: token_endpoint.to_string(),
        client_id: client_id.to_string(),
        refresh_token,
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
    let tokens = oauth::refresh(&state.token_endpoint, &state.client_id, rt)?;
    secrets::set_secret(server_id, secrets::HTTP_AUTH_KEY, &tokens.access_token)?;
    // Persist a rotated refresh token if the server issued one.
    let new_state = OAuthState {
        token_endpoint: state.token_endpoint,
        client_id: state.client_id,
        refresh_token: tokens.refresh_token.or(state.refresh_token),
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

/// Connect to a remote server, injecting any vaulted token. On an auth error,
/// refresh the token once and retry.
pub fn connect_remote(server_id: &str, url: &str) -> Result<DownstreamServer, String> {
    let auth = secrets::get_secret(server_id, secrets::HTTP_AUTH_KEY);
    let transport = HttpTransport::with_auth(url, auth);
    match DownstreamServer::connect(server_id.to_string(), Box::new(transport)) {
        Ok(ds) => Ok(ds),
        Err(e) if is_auth_error(&e) => match refresh_token(server_id) {
            Ok(fresh) => {
                let transport = HttpTransport::with_auth(url, Some(fresh));
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
}
