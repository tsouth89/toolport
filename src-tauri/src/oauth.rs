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

/// Append a line to the OAuth debug log (`<conduit dir>/oauth-debug.log`).
/// Off unless `CONDUIT_DEBUG` is set, so auth-flow metadata isn't written to disk
/// for every user. Never log token values here.
fn debug_log(msg: &str) {
    if std::env::var_os("CONDUIT_DEBUG").is_none() {
        return;
    }
    if let Some(path) = crate::registry::conduit_dir().map(|d| d.join("oauth-debug.log")) {
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

/// Require an endpoint to use https, allowing only loopback http for local dev.
fn require_https(url: &str, what: &str) -> Result<(), String> {
    let lower = url.trim().to_ascii_lowercase();
    let ok = lower.starts_with("https://")
        || lower.starts_with("http://127.0.0.1")
        || lower.starts_with("http://localhost")
        || lower.starts_with("http://[::1]");
    if ok {
        Ok(())
    } else {
        Err(format!("{what} must use https (got {url})"))
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
            // OAuth 2.1 requires TLS for these endpoints. Without this check a
            // hostile/MITM'd metadata document could point the token endpoint at
            // an attacker (or an internal address), and we'd POST the auth code +
            // PKCE verifier there in cleartext.
            require_https(&meta.authorization_endpoint, "authorization endpoint")?;
            require_https(&meta.token_endpoint, "token endpoint")?;
            if let Some(reg) = &meta.registration_endpoint {
                require_https(reg, "registration endpoint")?;
            }
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
    /// Access-token lifetime in seconds, when the server reports it. Logged for
    /// diagnostics so we can see how often a server expects re-auth.
    #[serde(default)]
    expires_in: Option<u64>,
}

/// Choose the `scope` to request. The input is the server's advertised
/// `scopes_supported`. We want a refresh token (the `offline_access` scope), but
/// we must not ask for it unless the server actually offers it: requesting an
/// unsupported scope gets the entire authorization rejected with `invalid_scope`
/// (Stripe does exactly this). The advertised list already contains
/// `offline_access` when the server supports refresh tokens, so we pass it
/// through unchanged and never inject a scope the server didn't offer.
fn requested_scope(advertised: Option<String>) -> Option<String> {
    advertised
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
    debug_log(&format!(
        "token response: refresh_token={} expires_in={:?}",
        resp.refresh_token.is_some(),
        resp.expires_in
    ));
    Ok(Tokens {
        access_token: resp.access_token,
        refresh_token: resp.refresh_token,
    })
}

/// Exchange a refresh token for a fresh access token (non-interactive). When a
/// `resource` is given it's sent as the RFC 8707 resource indicator, so the
/// refreshed token stays bound to the same MCP server it was first issued for.
pub fn refresh(
    token_endpoint: &str,
    client_id: &str,
    refresh_token: &str,
    resource: Option<&str>,
) -> Result<Tokens, String> {
    let mut form: Vec<(&str, &str)> = vec![
        ("grant_type", "refresh_token"),
        ("refresh_token", refresh_token),
        ("client_id", client_id),
    ];
    if let Some(r) = resource {
        form.push(("resource", r));
    }
    let resp: TokenResponse = ureq::post(token_endpoint)
        .send_form(&form)
        .map_err(|e| e.to_string())?
        .into_json()
        .map_err(|e| e.to_string())?;
    debug_log(&format!(
        "refresh response: refresh_token={} expires_in={:?}",
        resp.refresh_token.is_some(),
        resp.expires_in
    ));
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
                let query = read_callback_query(&mut stream);
                let mut params: std::collections::HashMap<String, String> = std::collections::HashMap::new();
                for kv in query.split('&') {
                    let mut it = kv.splitn(2, '=');
                    let k = it.next().unwrap_or("");
                    let raw = it.next().unwrap_or("");
                    let v = urlencoding::decode(raw)
                        .map(|c| c.into_owned())
                        .unwrap_or_default();
                    if !k.is_empty() {
                        params.insert(k.to_string(), v);
                    }
                }

                let code = params.get("code");
                let error = params.get("error");

                // Ignore connections that carry neither an authorization result nor
                // an error - browsers hit the loopback with /favicon.ico and other
                // stray requests, and bailing on the first of those would mask the
                // real redirect arriving right behind it. Answer politely and keep
                // waiting until the deadline.
                if code.is_none() && error.is_none() {
                    write_callback_page(&mut stream, "Waiting for authorization...");
                    continue;
                }

                if let Some(error) = error {
                    let desc = params
                        .get("error_description")
                        .map(|d| format!(": {d}"))
                        .unwrap_or_default();
                    write_callback_page(&mut stream, "Authorization failed. You can close this window and return to Conduit.");
                    return Err(format!("authorization server returned an error ({error}){desc}"));
                }

                // We have a code. Validate state before accepting it.
                if params.get("state").map(String::as_str) != Some(expected_state) {
                    write_callback_page(&mut stream, "Authorization could not be verified. You can close this window.");
                    return Err("state mismatch (possible CSRF); try connecting again".to_string());
                }
                write_callback_page(&mut stream, "Authorization complete. You can close this window and return to Conduit.");
                return Ok(code.cloned().unwrap_or_default());
            }
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(150));
            }
            Err(e) => return Err(e.to_string()),
        }
    }
}

/// Read an HTTP request from the callback socket and return its raw query string
/// (the part after `?` in the request target). Reads until the end of the request
/// line/headers so a long `code` isn't truncated by a single short read.
fn read_callback_query(stream: &mut std::net::TcpStream) -> String {
    let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
    let mut data = Vec::new();
    let mut buf = [0u8; 1024];
    loop {
        match stream.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                data.extend_from_slice(&buf[..n]);
                if data.windows(4).any(|w| w == b"\r\n\r\n") || data.len() > 16384 {
                    break;
                }
            }
            Err(_) => break,
        }
    }
    let req = String::from_utf8_lossy(&data);
    let target = req
        .lines()
        .next()
        .and_then(|l| l.split_whitespace().nth(1))
        .unwrap_or("");
    target.split('?').nth(1).unwrap_or("").to_string()
}

fn write_callback_page(stream: &mut std::net::TcpStream, message: &str) {
    let html = format!(
        "<html><body style='font-family:sans-serif;padding:2rem'>{message}</body></html>"
    );
    let resp = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        html.len(),
        html
    );
    let _ = stream.write_all(resp.as_bytes());
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
    // Bind the callback listener BEFORE registering/opening the browser, so a
    // fast redirect can't arrive before we're listening AND we know the real
    // port. Prefer the stable port, but fall back to an OS-assigned one when it's
    // busy - a prior auth attempt's listener can still be in its 180s wait window,
    // which otherwise fails the new bind with "os error 10048". DCR registers the
    // exact redirect_uri for this flow, so a variable loopback port is fine.
    let listener = TcpListener::bind(("127.0.0.1", REDIRECT_PORT))
        .or_else(|_| TcpListener::bind(("127.0.0.1", 0)))
        .map_err(|e| format!("could not bind a loopback callback port: {e}"))?;
    let port = listener.local_addr().map_err(|e| e.to_string())?.port();
    listener.set_nonblocking(true).map_err(|e| e.to_string())?;
    let redirect_uri = format!("http://127.0.0.1:{port}/callback");
    debug_log(&format!("callback listening on {redirect_uri}"));

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

    // Request exactly the scopes the server advertises. That already includes
    // offline_access (the refresh-token scope) when the server supports it;
    // forcing offline_access otherwise gets the authorization rejected with
    // invalid_scope (e.g. Stripe).
    let scope = requested_scope(endpoints.scope.clone());
    let auth_url = build_authorize_url(
        &endpoints.authorization_endpoint,
        &client_id,
        &redirect_uri,
        &challenge,
        &state,
        mcp_url,
        scope.as_deref(),
    );
    debug_log(&format!(
        "opening authorize endpoint: {}",
        endpoints.authorization_endpoint
    ));
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
    fn requested_scope_never_forces_unsupported_offline_access() {
        // offline_access advertised -> kept (server supports refresh tokens).
        assert_eq!(
            requested_scope(Some("openid offline_access profile".into())).as_deref(),
            Some("openid offline_access profile")
        );
        // offline_access NOT advertised -> never injected (would be invalid_scope).
        assert_eq!(
            requested_scope(Some("mcp:access".into())).as_deref(),
            Some("mcp:access")
        );
        // No advertised scope -> request none.
        assert_eq!(requested_scope(None), None);
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
