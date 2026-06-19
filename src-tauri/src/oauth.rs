//! OAuth 2.1 for remote MCP servers: RFC 8414 metadata discovery, RFC 7591
//! dynamic client registration, RFC 7636 PKCE, and an authorization-code flow
//! with a loopback redirect. The result is a bearer access token that rides the
//! same keychain injection path as a manually-pasted token.
//!
//! The browser leg is interactive and can't be unit-tested; the deterministic
//! pieces (PKCE, URL building, origin parsing) are.

use std::io::{Read, Write};
use std::net::TcpListener;
use std::time::{Duration, Instant};

use base64::Engine;
use serde::Deserialize;
use sha2::{Digest, Sha256};

const REDIRECT_PORT: u16 = 41789;

pub struct Tokens {
    pub access_token: String,
    pub refresh_token: Option<String>,
}

/// Everything needed to use and later refresh a remote server's access.
pub struct AuthResult {
    pub access_token: String,
    pub refresh_token: Option<String>,
    pub token_endpoint: String,
    pub client_id: String,
}

#[derive(Debug, Clone)]
pub struct Endpoints {
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    pub registration_endpoint: Option<String>,
    pub scope: Option<String>,
}

fn base64url(data: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(data)
}

/// Append a line to the OAuth debug log (`<config>/Conduit/oauth-debug.log`).
fn debug_log(msg: &str) {
    if let Some(dir) = dirs::config_dir() {
        let path = dir.join("Conduit").join("oauth-debug.log");
        if let Some(parent) = path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        if let Ok(mut f) = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
        {
            let _ = writeln!(f, "{msg}");
        }
    }
}

fn random_token(bytes: usize) -> String {
    let mut buf = vec![0u8; bytes];
    let _ = getrandom::getrandom(&mut buf);
    base64url(&buf)
}

/// (verifier, challenge) per RFC 7636 using S256.
pub fn pkce() -> (String, String) {
    let verifier = random_token(32);
    let mut hasher = Sha256::new();
    hasher.update(verifier.as_bytes());
    let challenge = base64url(&hasher.finalize());
    (verifier, challenge)
}

fn origin_of(url: &str) -> String {
    if let Some(scheme_end) = url.find("://") {
        let after = &url[scheme_end + 3..];
        let host_end = after.find('/').unwrap_or(after.len());
        format!("{}{}", &url[..scheme_end + 3], &after[..host_end])
    } else {
        url.to_string()
    }
}

#[derive(Deserialize)]
struct ProtectedResource {
    authorization_servers: Option<Vec<String>>,
}

#[derive(Deserialize)]
struct AsMeta {
    authorization_endpoint: String,
    token_endpoint: String,
    registration_endpoint: Option<String>,
    scopes_supported: Option<Vec<String>>,
}

fn get_json<T: serde::de::DeserializeOwned>(url: &str) -> Result<T, String> {
    ureq::get(url)
        .call()
        .map_err(|e| e.to_string())?
        .into_json::<T>()
        .map_err(|e| e.to_string())
}

fn split_origin_path(url: &str) -> (String, String) {
    if let Some(scheme_end) = url.find("://") {
        let after = &url[scheme_end + 3..];
        match after.find('/') {
            Some(i) => (
                format!("{}{}", &url[..scheme_end + 3], &after[..i]),
                after[i..].trim_end_matches('/').to_string(),
            ),
            None => (url.trim_end_matches('/').to_string(), String::new()),
        }
    } else {
        (url.trim_end_matches('/').to_string(), String::new())
    }
}

/// Candidate metadata URLs for an issuer. RFC 8414 inserts `.well-known` between
/// host and path (`host/.well-known/oauth-authorization-server/path`); OIDC and
/// some servers append it instead. Try the standards-compliant forms first.
fn metadata_candidates(issuer: &str) -> Vec<String> {
    let (origin, path) = split_origin_path(issuer);
    if path.is_empty() {
        vec![
            format!("{origin}/.well-known/oauth-authorization-server"),
            format!("{origin}/.well-known/openid-configuration"),
        ]
    } else {
        vec![
            format!("{origin}/.well-known/oauth-authorization-server{path}"),
            format!("{origin}/.well-known/openid-configuration{path}"),
            format!("{origin}{path}/.well-known/oauth-authorization-server"),
            format!("{origin}{path}/.well-known/openid-configuration"),
        ]
    }
}

/// Discover the authorization + token endpoints for an MCP server URL.
pub fn discover(mcp_url: &str) -> Result<Endpoints, String> {
    let origin = origin_of(mcp_url);
    let issuer = match get_json::<ProtectedResource>(&format!(
        "{origin}/.well-known/oauth-protected-resource"
    )) {
        Ok(pr) => pr
            .authorization_servers
            .and_then(|v| v.into_iter().next())
            .unwrap_or_else(|| origin.clone()),
        Err(_) => origin.clone(),
    };

    for url in metadata_candidates(&issuer) {
        if let Ok(meta) = get_json::<AsMeta>(&url) {
            return Ok(Endpoints {
                authorization_endpoint: meta.authorization_endpoint,
                token_endpoint: meta.token_endpoint,
                registration_endpoint: meta.registration_endpoint,
                scope: meta.scopes_supported.map(|s| s.join(" ")),
            });
        }
    }
    Err(
        "this server doesn't advertise OAuth. It may not need auth (just enable it), \
         or it may require a token you paste manually."
            .to_string(),
    )
}

#[derive(Deserialize)]
struct DcrResponse {
    client_id: String,
}

fn register_client(registration_endpoint: &str, redirect_uri: &str) -> Result<String, String> {
    let body = serde_json::json!({
        "client_name": "Conduit",
        "redirect_uris": [redirect_uri],
        "grant_types": ["authorization_code", "refresh_token"],
        "response_types": ["code"],
        "token_endpoint_auth_method": "none"
    });
    let resp: DcrResponse = ureq::post(registration_endpoint)
        .send_json(body)
        .map_err(|e| e.to_string())?
        .into_json()
        .map_err(|e| e.to_string())?;
    Ok(resp.client_id)
}

pub fn build_authorize_url(
    authorization_endpoint: &str,
    client_id: &str,
    redirect_uri: &str,
    challenge: &str,
    state: &str,
    resource: &str,
    scope: Option<&str>,
) -> String {
    let enc = |s: &str| urlencoding::encode(s).into_owned();
    let mut url = format!(
        "{authorization_endpoint}?response_type=code&client_id={}&redirect_uri={}&code_challenge={}&code_challenge_method=S256&state={}&resource={}",
        enc(client_id),
        enc(redirect_uri),
        enc(challenge),
        enc(state),
        enc(resource),
    );
    if let Some(s) = scope {
        if !s.is_empty() {
            url.push_str(&format!("&scope={}", enc(s)));
        }
    }
    url
}

#[derive(Deserialize)]
struct TokenResponse {
    access_token: String,
    refresh_token: Option<String>,
}

fn exchange_code(
    token_endpoint: &str,
    client_id: &str,
    redirect_uri: &str,
    code: &str,
    verifier: &str,
    resource: &str,
) -> Result<Tokens, String> {
    let resp: TokenResponse = ureq::post(token_endpoint)
        .send_form(&[
            ("grant_type", "authorization_code"),
            ("code", code),
            ("redirect_uri", redirect_uri),
            ("client_id", client_id),
            ("code_verifier", verifier),
            ("resource", resource),
        ])
        .map_err(|e| e.to_string())?
        .into_json()
        .map_err(|e| e.to_string())?;
    Ok(Tokens {
        access_token: resp.access_token,
        refresh_token: resp.refresh_token,
    })
}

/// Exchange a refresh token for a fresh access token (non-interactive).
pub fn refresh(token_endpoint: &str, client_id: &str, refresh_token: &str) -> Result<Tokens, String> {
    let resp: TokenResponse = ureq::post(token_endpoint)
        .send_form(&[
            ("grant_type", "refresh_token"),
            ("refresh_token", refresh_token),
            ("client_id", client_id),
        ])
        .map_err(|e| e.to_string())?
        .into_json()
        .map_err(|e| e.to_string())?;
    Ok(Tokens {
        access_token: resp.access_token,
        refresh_token: resp.refresh_token,
    })
}

fn open_browser(url: &str) {
    // NOT `cmd /C start` on Windows: cmd treats `&` in the URL as a command
    // separator and truncates it. rundll32 passes the URL through verbatim.
    #[cfg(windows)]
    let _ = std::process::Command::new("rundll32")
        .args(["url.dll,FileProtocolHandler", url])
        .spawn();
    #[cfg(target_os = "macos")]
    let _ = std::process::Command::new("open").arg(url).spawn();
    #[cfg(all(unix, not(target_os = "macos")))]
    let _ = std::process::Command::new("xdg-open").arg(url).spawn();
}

fn wait_for_code(listener: &TcpListener, expected_state: &str) -> Result<String, String> {
    let deadline = Instant::now() + Duration::from_secs(180);

    loop {
        if Instant::now() > deadline {
            return Err("timed out waiting for browser authorization".to_string());
        }
        match listener.accept() {
            Ok((mut stream, _)) => {
                let mut buf = [0u8; 4096];
                let n = stream.read(&mut buf).unwrap_or(0);
                let req = String::from_utf8_lossy(&buf[..n]);
                let path = req
                    .lines()
                    .next()
                    .and_then(|l| l.split_whitespace().nth(1))
                    .unwrap_or("");
                let query = path.split('?').nth(1).unwrap_or("");
                let (mut code, mut state) = (None, None);
                for kv in query.split('&') {
                    let mut it = kv.splitn(2, '=');
                    let k = it.next().unwrap_or("");
                    let raw = it.next().unwrap_or("");
                    let v = urlencoding::decode(raw)
                        .map(|c| c.into_owned())
                        .unwrap_or_default();
                    match k {
                        "code" => code = Some(v),
                        "state" => state = Some(v),
                        _ => {}
                    }
                }
                let html = "<html><body style='font-family:sans-serif;padding:2rem'>Authorization complete. You can close this window and return to Conduit.</body></html>";
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    html.len(),
                    html
                );
                let _ = stream.write_all(resp.as_bytes());

                if state.as_deref() != Some(expected_state) {
                    return Err("state mismatch (possible CSRF)".to_string());
                }
                return code.ok_or_else(|| "no authorization code in callback".to_string());
            }
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(150));
            }
            Err(e) => return Err(e.to_string()),
        }
    }
}

/// Run the full interactive flow and return tokens plus what's needed to refresh.
pub fn authenticate(mcp_url: &str) -> Result<AuthResult, String> {
    debug_log(&format!("=== oauth start: {mcp_url} ==="));
    let endpoints = discover(mcp_url)?;
    debug_log(&format!(
        "endpoints: authz={} token={} reg={:?} scope={:?}",
        endpoints.authorization_endpoint,
        endpoints.token_endpoint,
        endpoints.registration_endpoint,
        endpoints.scope
    ));
    let redirect_uri = format!("http://127.0.0.1:{REDIRECT_PORT}/callback");
    let client_id = match &endpoints.registration_endpoint {
        Some(reg) => register_client(reg, &redirect_uri)?,
        None => {
            return Err(
                "this server has no dynamic-registration endpoint; OAuth needs a pre-registered client"
                    .to_string(),
            )
        }
    };
    debug_log(&format!("client_id='{client_id}' (len {})", client_id.len()));
    if client_id.trim().is_empty() {
        return Err("dynamic registration returned an empty client_id".to_string());
    }
    let (verifier, challenge) = pkce();
    let state = random_token(16);

    // Bind the callback listener BEFORE opening the browser, so a fast redirect
    // can't arrive before we're listening.
    let listener = TcpListener::bind(("127.0.0.1", REDIRECT_PORT))
        .map_err(|e| format!("could not bind callback port {REDIRECT_PORT}: {e}"))?;
    listener.set_nonblocking(true).map_err(|e| e.to_string())?;

    let auth_url = build_authorize_url(
        &endpoints.authorization_endpoint,
        &client_id,
        &redirect_uri,
        &challenge,
        &state,
        mcp_url,
        endpoints.scope.as_deref(),
    );
    debug_log(&format!("authorize_url={auth_url}"));
    open_browser(&auth_url);
    let code = wait_for_code(&listener, &state)?;
    debug_log(&format!("got code (len {})", code.len()));
    let tokens = match exchange_code(
        &endpoints.token_endpoint,
        &client_id,
        &redirect_uri,
        &code,
        &verifier,
        mcp_url,
    ) {
        Ok(t) => {
            debug_log("token exchange: OK");
            t
        }
        Err(e) => {
            debug_log(&format!("token exchange FAILED: {e}"));
            return Err(e);
        }
    };
    Ok(AuthResult {
        access_token: tokens.access_token,
        refresh_token: tokens.refresh_token,
        token_endpoint: endpoints.token_endpoint,
        client_id,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pkce_challenge_matches_rfc_vector() {
        // RFC 7636 Appendix B test vector.
        let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        let mut hasher = Sha256::new();
        hasher.update(verifier.as_bytes());
        assert_eq!(
            base64url(&hasher.finalize()),
            "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
        );
    }

    #[test]
    fn origin_strips_path() {
        assert_eq!(origin_of("https://mcp.example.com/mcp"), "https://mcp.example.com");
        assert_eq!(origin_of("https://a.b:8080/x/y"), "https://a.b:8080");
    }

    #[test]
    fn authorize_url_has_required_params() {
        let url = build_authorize_url(
            "https://as/auth",
            "cid",
            "http://127.0.0.1:41789/callback",
            "chal",
            "st",
            "https://mcp/x",
            Some("mcp"),
        );
        assert!(url.contains("response_type=code"));
        assert!(url.contains("client_id=cid"));
        assert!(url.contains("code_challenge=chal"));
        assert!(url.contains("code_challenge_method=S256"));
        assert!(url.contains("redirect_uri=http%3A%2F%2F127.0.0.1%3A41789%2Fcallback"));
        assert!(url.contains("scope=mcp"));
    }

    #[test]
    fn metadata_candidates_are_rfc8414_path_aware() {
        let c = metadata_candidates("https://access.stripe.com/mcp");
        assert_eq!(
            c[0],
            "https://access.stripe.com/.well-known/oauth-authorization-server/mcp"
        );
        let c2 = metadata_candidates("https://as.example.com");
        assert_eq!(
            c2[0],
            "https://as.example.com/.well-known/oauth-authorization-server"
        );
    }
}
