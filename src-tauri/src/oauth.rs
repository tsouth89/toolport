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

fn random_token(bytes: usize) -> Result<String, String> {
    let mut buf = vec![0u8; bytes];
    // A CSPRNG failure must fail loudly. Silently ignoring the error would leave
    // the buffer all-zeros, making the PKCE verifier and the CSRF state constant
    // and predictable, which defeats both protections.
    getrandom::getrandom(&mut buf).map_err(|e| format!("secure RNG unavailable: {e}"))?;
    Ok(base64url(&buf))
}

/// (verifier, challenge) per RFC 7636 using S256.
pub fn pkce() -> Result<(String, String), String> {
    let verifier = random_token(32)?;
    let mut hasher = Sha256::new();
    hasher.update(verifier.as_bytes());
    let challenge = base64url(&hasher.finalize());
    Ok((verifier, challenge))
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

/// A ureq agent with a connect + read timeout for all OAuth HTTP. These endpoints
/// come from a fetched (and attacker-influenceable) metadata document, so a slow or
/// black-holed host must not hang the worker indefinitely behind a spinner that
/// never resolves. Bare `ureq::get/post` have no timeout; this does.
/// Refuse link-local / cloud-metadata addresses (169.254.169.254, the AWS ULA
/// `fd00:ec2::254`, IPv4-mapped forms). Fail-closed if ANY resolved address is one, so a
/// DNS answer mixing a public and a metadata IP can't sneak the metadata one through.
/// Private/loopback are allowed - a self-hosted MCP auth server on the LAN is legitimate.
fn screen_addrs(addrs: &[std::net::SocketAddr]) -> std::io::Result<()> {
    for sa in addrs {
        if ip_is_link_local(&sa.ip()) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                format!("OAuth SSRF guard: refusing link-local / cloud-metadata address {}", sa.ip()),
            ));
        }
    }
    Ok(())
}

/// A DNS resolver that screens every resolved address (see [`screen_addrs`]). Installed on
/// the OAuth agents so the check runs INSIDE ureq's resolver - covering the initial connect
/// AND any redirect target, and closing the resolve-then-connect (DNS-rebind) window that a
/// separate pre-check has. The OAuth endpoints come from an attacker-influenceable metadata
/// document, so this is the load-bearing SSRF guard.
fn screened_resolve(netloc: &str) -> std::io::Result<Vec<std::net::SocketAddr>> {
    use std::net::ToSocketAddrs;
    let addrs: Vec<std::net::SocketAddr> = netloc.to_socket_addrs()?.collect();
    screen_addrs(&addrs)?;
    Ok(addrs)
}

fn agent() -> ureq::Agent {
    ureq::AgentBuilder::new()
        .timeout(std::time::Duration::from_secs(30))
        .resolver(screened_resolve)
        .build()
}

/// Like [`agent`] but refuses to follow redirects. Used for the credential-bearing
/// POSTs (DCR, token exchange, refresh): a hostile authorization-server metadata
/// document could otherwise 302 the token POST to a host it controls and capture the
/// auth code or refresh token. Metadata discovery (a read-only GET) keeps following
/// redirects so providers that redirect their `.well-known` still resolve; both agents
/// screen resolved addresses so a redirect or rebind to cloud metadata is refused.
fn agent_no_redirect() -> ureq::Agent {
    ureq::AgentBuilder::new()
        .timeout(std::time::Duration::from_secs(30))
        .redirects(0)
        .resolver(screened_resolve)
        .build()
}

fn get_json<T: serde::de::DeserializeOwned>(url: &str) -> Result<T, String> {
    agent()
        .get(url)
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

/// The host (no scheme, userinfo, port, or brackets) of a URL.
pub fn host_of_url(url: &str) -> Option<String> {
    let after = url.split("://").nth(1)?;
    let authority = after.split(['/', '?', '#']).next()?;
    let authority = authority.rsplit('@').next()?; // strip any userinfo
    if let Some(rest) = authority.strip_prefix('[') {
        // IPv6 literal: [::1]:443 -> ::1
        return rest.split(']').next().map(|s| s.to_string());
    }
    authority.split(':').next().map(|s| s.to_string())
}

/// True if `ip` is a link-local or well-known cloud-metadata address: IPv4
/// 169.254.0.0/16, IPv6 fe80::/10, the IPv4-mapped forms of those, and the AWS
/// IPv6 metadata address fd00:ec2::254 (which lives in unique-local space, so a
/// pure link-local test would miss it). These are never a valid remote MCP
/// target and are the classic SSRF route to a cloud metadata service, so they
/// are refused for every server regardless of provenance.
pub fn ip_is_link_local(ip: &std::net::IpAddr) -> bool {
    use std::net::{IpAddr, Ipv6Addr};
    const AWS_V6_METADATA: Ipv6Addr = Ipv6Addr::new(0xfd00, 0x0ec2, 0, 0, 0, 0, 0, 0x254);
    match ip {
        IpAddr::V4(v4) => v4.is_link_local(),
        IpAddr::V6(v6) => {
            *v6 == AWS_V6_METADATA
                || (v6.segments()[0] & 0xffc0) == 0xfe80 // fe80::/10
                || v6
                    .to_ipv4_mapped()
                    .map(|m| m.is_link_local())
                    .unwrap_or(false)
        }
    }
}

pub(crate) fn ip_is_private(ip: &std::net::IpAddr) -> bool {
    use std::net::IpAddr;
    match ip {
        IpAddr::V4(v4) => {
            v4.is_loopback()
                || v4.is_private()
                || v4.is_link_local()
                || v4.is_unspecified()
                || v4.is_broadcast()
                // carrier-grade NAT 100.64.0.0/10
                || (v4.octets()[0] == 100 && (v4.octets()[1] & 0xc0) == 64)
        }
        IpAddr::V6(v6) => {
            v6.is_loopback()
                || v6.is_unspecified()
                || (v6.segments()[0] & 0xffc0) == 0xfe80 // link-local fe80::/10
                || (v6.segments()[0] & 0xfe00) == 0xfc00 // unique-local fc00::/7
                || v6
                    .to_ipv4_mapped()
                    .map(|m| ip_is_private(&IpAddr::V4(m)))
                    .unwrap_or(false)
        }
    }
}

/// True if `host` is loopback, private, or link-local. Resolves DNS (literal IPs
/// resolve to themselves); fails closed (treats an unresolvable host as private).
pub fn host_is_private(host: &str) -> bool {
    use std::net::ToSocketAddrs;
    let h = host.trim().to_ascii_lowercase();
    if h.is_empty() || h == "localhost" || h.ends_with(".localhost") {
        return true;
    }
    match (h.as_str(), 0u16).to_socket_addrs() {
        Ok(addrs) => {
            let ips: Vec<_> = addrs.map(|sa| sa.ip()).collect();
            ips.is_empty() || ips.iter().any(ip_is_private)
        }
        Err(_) => true,
    }
}

/// True only if `host` resolves to a link-local / cloud-metadata address (169.254.0.0/16,
/// fe80::/10, the AWS metadata form). Unlike `host_is_private`, loopback and RFC1918 are
/// NOT link-local. Fails OPEN (false on an empty/unresolvable host) so the stricter
/// `host_is_private` check downstream still catches those.
pub fn host_is_link_local(host: &str) -> bool {
    use std::net::ToSocketAddrs;
    let h = host.trim().to_ascii_lowercase();
    if h.is_empty() || h == "localhost" || h.ends_with(".localhost") {
        return false;
    }
    match (h.as_str(), 0u16).to_socket_addrs() {
        Ok(addrs) => addrs.map(|sa| sa.ip()).any(|ip| ip_is_link_local(&ip)),
        Err(_) => false,
    }
}

/// SSRF guard for an OAuth endpoint taken from a fetched metadata document. A
/// server that is itself local may legitimately use local endpoints, but a public
/// server must not be able to point our token POST / browser redirect at the
/// user's loopback or internal network. `server_local` = the originally configured
/// MCP server is itself on a private/loopback host.
fn guard_endpoint(url: &str, server_local: bool, what: &str) -> Result<(), String> {
    if server_local {
        return Ok(());
    }
    if let Some(host) = host_of_url(url) {
        if host_is_private(&host) {
            return Err(format!(
                "{what} points at a private or loopback address ({host}); refusing \
                 (a hostile metadata document could use this to reach your internal network)."
            ));
        }
    }
    Ok(())
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

    // Is the configured MCP server itself local? If so, local OAuth endpoints are
    // expected and allowed; if it's public, its metadata must not redirect us at a
    // private/loopback host (SSRF).
    let server_local = host_of_url(mcp_url).map(|h| host_is_private(&h)).unwrap_or(false);
    // The issuer can come from the protected-resource document, so guard the
    // metadata fetch too, not just the final endpoints.
    guard_endpoint(&issuer, server_local, "authorization server")?;

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
            // SSRF: a public server must not point these at a private/loopback host.
            guard_endpoint(&meta.authorization_endpoint, server_local, "authorization endpoint")?;
            guard_endpoint(&meta.token_endpoint, server_local, "token endpoint")?;
            if let Some(reg) = &meta.registration_endpoint {
                guard_endpoint(reg, server_local, "registration endpoint")?;
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
        "client_name": "Toolport",
        "redirect_uris": [redirect_uri],
        "grant_types": ["authorization_code", "refresh_token"],
        "response_types": ["code"],
        "token_endpoint_auth_method": "none"
    });
    let resp: DcrResponse = agent_no_redirect()
        .post(registration_endpoint)
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
    let resp: TokenResponse = agent_no_redirect()
        .post(token_endpoint)
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
    let resp: TokenResponse = agent_no_redirect()
        .post(token_endpoint)
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
                // The listener is non-blocking; on macOS/BSD the accepted socket can
                // inherit that, which would make our timed read return nothing. Force
                // it back to blocking so read_callback_query's read timeout applies.
                let _ = stream.set_nonblocking(false);
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
                debug_log(&format!(
                    "callback request: {} bytes of query, has_code={} has_error={} has_state={}",
                    query.len(),
                    code.is_some(),
                    error.is_some(),
                    params.contains_key("state")
                ));

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
                    write_callback_page(&mut stream, "Authorization failed. You can close this window and return to Toolport.");
                    return Err(format!("authorization server returned an error ({error}){desc}"));
                }

                // We have a code. Validate state before accepting it.
                if params.get("state").map(String::as_str) != Some(expected_state) {
                    write_callback_page(&mut stream, "Authorization could not be verified. You can close this window.");
                    return Err("state mismatch (possible CSRF); try connecting again".to_string());
                }
                write_callback_page(&mut stream, "Authorization complete. You can close this window and return to Toolport.");
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
    // The accepted socket can be non-blocking: on macOS/BSD it inherits the
    // listener's mode (unlike Windows), which would make a single read return
    // nothing and we'd serve a blank page while the browser sits on the callback.
    // Force blocking AND tolerate WouldBlock by retrying within a deadline, so the
    // request is read regardless of socket mode.
    let _ = stream.set_nonblocking(false);
    let _ = stream.set_read_timeout(Some(Duration::from_millis(500)));
    let deadline = Instant::now() + Duration::from_secs(5);
    let mut data = Vec::new();
    let mut buf = [0u8; 1024];
    while Instant::now() < deadline {
        match stream.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                data.extend_from_slice(&buf[..n]);
                if data.windows(4).any(|w| w == b"\r\n\r\n") || data.len() > 16384 {
                    break;
                }
            }
            Err(ref e)
                if e.kind() == std::io::ErrorKind::WouldBlock
                    || e.kind() == std::io::ErrorKind::TimedOut =>
            {
                std::thread::sleep(Duration::from_millis(20));
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
    // fast redirect can't arrive before we're listening AND we know the real port.
    // Always bind a fresh OS-assigned port: DCR registers the exact redirect_uri
    // for THIS attempt, so the port can vary, and a per-attempt port means two
    // overlapping attempts never share one. Previously a fixed port let a prior
    // attempt's still-waiting listener intercept a newer attempt's callback, which
    // failed the state check ("state mismatch").
    let listener = TcpListener::bind(("127.0.0.1", 0))
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
    let (verifier, challenge) = pkce()?;
    let state = random_token(16)?;

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
    fn screen_addrs_refuses_link_local_and_metadata() {
        use std::net::SocketAddr;
        let p = |s: &str| s.parse::<SocketAddr>().unwrap();
        // AWS/GCP/Azure IPv4 metadata, AWS IPv6 ULA metadata, and the IPv4-mapped form.
        for bad in ["169.254.169.254:80", "[fd00:ec2::254]:80", "[::ffff:169.254.169.254]:80"] {
            assert!(screen_addrs(&[p(bad)]).is_err(), "must refuse {bad}");
        }
        // A public address is allowed; a private/loopback one is allowed (self-hosted AS).
        assert!(screen_addrs(&[p("140.82.112.3:443")]).is_ok());
        assert!(screen_addrs(&[p("127.0.0.1:8080")]).is_ok());
        // Fail-closed: a mixed public+metadata answer is refused whole.
        assert!(screen_addrs(&[p("8.8.8.8:443"), p("169.254.169.254:80")]).is_err());
    }

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
    fn pkce_generates_a_fresh_verifier_each_call() {
        let (verifier, challenge) = pkce().expect("RNG should be available");
        // 32 random bytes base64url'd -> 43 chars, within RFC 7636's 43..=128.
        assert_eq!(verifier.len(), 43);
        // The challenge is S256(verifier).
        let mut hasher = Sha256::new();
        hasher.update(verifier.as_bytes());
        assert_eq!(challenge, base64url(&hasher.finalize()));
        // Guards the all-zeros bug: two calls must not produce the same verifier.
        assert_ne!(pkce().unwrap().0, verifier);
    }

    #[test]
    fn origin_strips_path() {
        assert_eq!(origin_of("https://mcp.example.com/mcp"), "https://mcp.example.com");
        assert_eq!(origin_of("https://a.b:8080/x/y"), "https://a.b:8080");
    }

    #[test]
    fn host_of_url_extracts_host() {
        assert_eq!(host_of_url("https://example.com/x").as_deref(), Some("example.com"));
        assert_eq!(host_of_url("https://example.com:8443/x").as_deref(), Some("example.com"));
        assert_eq!(host_of_url("http://[::1]:7000/cb").as_deref(), Some("::1"));
        assert_eq!(host_of_url("https://user:pw@host.tld/p").as_deref(), Some("host.tld"));
        assert_eq!(host_of_url("https://127.0.0.1/x").as_deref(), Some("127.0.0.1"));
    }

    #[test]
    fn ip_is_private_classifies() {
        use std::net::IpAddr;
        let p = |s: &str| ip_is_private(&s.parse::<IpAddr>().unwrap());
        assert!(p("127.0.0.1"));
        assert!(p("10.0.0.5"));
        assert!(p("192.168.1.1"));
        assert!(p("172.16.0.1"));
        assert!(p("169.254.10.10"));
        assert!(p("100.64.1.1")); // CGNAT
        assert!(p("::1"));
        assert!(p("fe80::1"));
        assert!(p("fc00::1"));
        assert!(p("::ffff:127.0.0.1")); // IPv4-mapped loopback
        assert!(!p("8.8.8.8"));
        assert!(!p("140.82.112.3")); // a public GitHub IP range
        assert!(!p("2606:4700:4700::1111")); // public IPv6
    }

    #[test]
    fn host_is_private_handles_localhost_and_literals() {
        assert!(host_is_private("localhost"));
        assert!(host_is_private("foo.localhost"));
        assert!(host_is_private("127.0.0.1"));
        assert!(host_is_private("10.1.2.3"));
        assert!(host_is_private("")); // fail closed
        assert!(!host_is_private("8.8.8.8"));
    }

    #[test]
    fn guard_endpoint_blocks_private_for_public_server() {
        // Public server: a metadata doc pointing at loopback/internal is rejected.
        assert!(guard_endpoint("http://127.0.0.1:9000/token", false, "token").is_err());
        assert!(guard_endpoint("https://10.0.0.5/token", false, "token").is_err());
        // A public endpoint is allowed (literal IP, so the test needs no DNS).
        assert!(guard_endpoint("https://8.8.8.8/token", false, "token").is_ok());
        // Local server: local endpoints are expected and allowed.
        assert!(guard_endpoint("http://127.0.0.1:9000/token", true, "token").is_ok());
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
