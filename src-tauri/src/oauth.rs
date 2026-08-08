//! OAuth 2.1 for remote MCP servers: RFC 8414 metadata discovery, RFC 7591
//! dynamic client registration, RFC 7636 PKCE, RFC 9207 issuer validation, and
//! an authorization-code flow with a loopback redirect. The result is a bearer
//! access token that rides the same keychain injection path as a manually-pasted
//! token.
//!
//! The browser leg is interactive and can't be unit-tested; the deterministic
//! pieces (PKCE, URL building, origin parsing) are.

use std::io::{Read, Write};
use std::net::TcpListener;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use base64::Engine;
use serde::Deserialize;
use sha2::{Digest, Sha256};

/// Stable HTTPS client identifier whose metadata is published by toolport.app.
/// Authorization servers that advertise CIMD support fetch this document rather
/// than accepting an unauthenticated dynamic-registration write.
const CLIENT_ID_METADATA_URL: &str = "https://toolport.app/.well-known/oauth-client/toolport.json";

pub struct Tokens {
    pub access_token: String,
    pub refresh_token: Option<String>,
    /// Unix timestamp when Toolport received this token response.
    pub issued_at: u64,
    /// Unix timestamp when the access token expires, when the server reports a
    /// lifetime. `None` preserves the reactive-refresh behavior for providers
    /// that omit `expires_in`.
    pub expires_at: Option<u64>,
}

/// Everything needed to use and later refresh a remote server's access.
pub struct AuthResult {
    pub access_token: String,
    pub refresh_token: Option<String>,
    pub issued_at: u64,
    pub expires_at: Option<u64>,
    pub token_endpoint: String,
    pub client_id: String,
    /// Validated authorization-server issuer that minted the client credentials.
    pub issuer: String,
    /// Scope set requested for this authorization. Persisted so a later runtime
    /// challenge can add to it without dropping previously granted access.
    pub scope: Option<String>,
}

#[derive(Debug, Clone)]
pub struct Endpoints {
    pub issuer: String,
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    pub registration_endpoint: Option<String>,
    pub scope: Option<String>,
    pub authorization_response_iss_parameter_supported: bool,
    pub client_id_metadata_document_supported: bool,
    /// RFC 8414 `token_endpoint_auth_methods_supported`. `None` when the server
    /// omits it, which per RFC 8414 means `client_secret_basic` only.
    pub token_endpoint_auth_methods_supported: Option<Vec<String>>,
}

/// How the client authenticates itself to the token endpoint.
///
/// Only relevant to the headless client-credentials flow (SBS-524). The
/// interactive authorization-code flow uses a public client with PKCE and sends
/// no client secret at all.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClientAuthMethod {
    /// Credentials in the form body (RFC 6749 §2.3.1, the `client_secret_post`
    /// alternative).
    ClientSecretPost,
    /// Credentials in an HTTP Basic header (RFC 6749 §2.3.1, the default that
    /// RFC 8414 assumes when a server advertises nothing).
    ClientSecretBasic,
    /// RFC 7523 private-key JWT assertion. Recognized and configurable, but not
    /// implemented: it needs an asymmetric signing dependency the crate does not
    /// have. Tracked in SBS-599. Selecting it fails closed rather than silently
    /// downgrading to a shared secret, which would be a security regression.
    PrivateKeyJwt,
}

impl ClientAuthMethod {
    /// The RFC 8414 `token_endpoint_auth_method` identifier.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ClientSecretPost => "client_secret_post",
            Self::ClientSecretBasic => "client_secret_basic",
            Self::PrivateKeyJwt => "private_key_jwt",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s.trim() {
            "client_secret_post" => Some(Self::ClientSecretPost),
            "client_secret_basic" => Some(Self::ClientSecretBasic),
            "private_key_jwt" => Some(Self::PrivateKeyJwt),
            _ => None,
        }
    }

    /// Does this method authenticate with a shared secret Toolport can send today?
    fn is_implemented(self) -> bool {
        matches!(self, Self::ClientSecretPost | Self::ClientSecretBasic)
    }
}

/// Choose the token-endpoint auth method for a client-credentials connection.
///
/// `configured` is the user's explicit choice, if any. `advertised` is the
/// server's `token_endpoint_auth_methods_supported`.
///
/// Fails closed in every ambiguous case rather than guessing. Sending a client
/// secret by a method the server did not advertise leaks it to an endpoint that
/// may log or reject it, and silently substituting a different method than the
/// user configured is exactly the kind of downgrade this flow exists to avoid.
pub fn select_client_auth_method(
    configured: Option<ClientAuthMethod>,
    advertised: Option<&[String]>,
) -> Result<ClientAuthMethod, String> {
    // RFC 8414: when the server omits the field, `client_secret_basic` is the
    // assumed default. Treat an empty list the same way rather than concluding
    // that nothing is supported.
    let supported: Option<Vec<ClientAuthMethod>> = advertised
        .filter(|list| !list.is_empty())
        .map(|list| list.iter().filter_map(|m| ClientAuthMethod::parse(m)).collect());

    if let Some(method) = configured {
        if !method.is_implemented() {
            return Err(format!(
                "{} is not supported yet (it needs asymmetric signing; tracked in \
                 SBS-599). Configure client_secret_post or client_secret_basic.",
                method.as_str()
            ));
        }
        if let Some(ref supported) = supported {
            if !supported.contains(&method) {
                return Err(format!(
                    "the authorization server does not accept {}; it advertises: {}",
                    method.as_str(),
                    advertised.map(|l| l.join(", ")).unwrap_or_default()
                ));
            }
        }
        return Ok(method);
    }

    let Some(supported) = supported else {
        // Nothing advertised: RFC 8414's default.
        return Ok(ClientAuthMethod::ClientSecretBasic);
    };
    // Prefer basic, then post, among what we can actually do. `private_key_jwt`
    // is deliberately not auto-selected: it is unimplemented, and picking it
    // here would fail every connection on servers that advertise it alongside a
    // secret-based method we can use.
    supported
        .iter()
        .copied()
        .find(|m| *m == ClientAuthMethod::ClientSecretBasic)
        .or_else(|| {
            supported
                .iter()
                .copied()
                .find(|m| *m == ClientAuthMethod::ClientSecretPost)
        })
        .ok_or_else(|| {
            format!(
                "the authorization server advertises no token-endpoint auth method \
                 Toolport can use ({}). private_key_jwt is tracked in SBS-599.",
                advertised.map(|l| l.join(", ")).unwrap_or_default()
            )
        })
}

fn base64url(data: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(data)
}

/// Append a line to the OAuth debug log (`<conduit dir>/oauth-debug.log`).
/// Off unless `CONDUIT_DEBUG` is set, so auth-flow metadata isn't written to disk
/// for every user. Never log token values here.
fn debug_log(msg: &str) {
    if crate::brand::env_var_os("TOOLPORT_DEBUG", "CONDUIT_DEBUG").is_none() {
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
    resource: Option<String>,
    authorization_servers: Option<Vec<String>>,
    scopes_supported: Option<Vec<String>>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct BearerChallenge {
    pub(crate) resource_metadata: Option<String>,
    pub(crate) scope: Option<String>,
    pub(crate) error: Option<String>,
}

/// Split an HTTP authentication header on commas that are outside quoted
/// strings. Authentication parameters commonly contain URLs and descriptions,
/// so a plain `split(',')` corrupts valid quoted values.
fn auth_header_parts(value: &str) -> Vec<&str> {
    let mut parts = Vec::new();
    let mut start = 0;
    let mut quoted = false;
    let mut escaped = false;
    for (index, ch) in value.char_indices() {
        if escaped {
            escaped = false;
            continue;
        }
        match ch {
            '\\' if quoted => escaped = true,
            '"' => quoted = !quoted,
            ',' if !quoted => {
                parts.push(value[start..index].trim());
                start = index + 1;
            }
            _ => {}
        }
    }
    parts.push(value[start..].trim());
    parts
}

fn auth_param(value: &str) -> Option<(&str, String)> {
    let (name, value) = value.split_once('=')?;
    let name = name.trim();
    let value = value.trim();
    if name.is_empty() || value.is_empty() {
        return None;
    }
    let decoded = if value.starts_with('"') && value.ends_with('"') && value.len() >= 2 {
        let mut out = String::new();
        let mut escaped = false;
        for ch in value[1..value.len() - 1].chars() {
            if escaped {
                out.push(ch);
                escaped = false;
            } else if ch == '\\' {
                escaped = true;
            } else {
                out.push(ch);
            }
        }
        if escaped {
            return None;
        }
        out
    } else {
        value.to_string()
    };
    Some((name, decoded))
}

/// Select the first Bearer challenge from one or more `WWW-Authenticate`
/// fields. A response may advertise another scheme first or place Bearer
/// parameters in later comma-separated segments.
pub(crate) fn bearer_challenge<'a>(
    headers: impl IntoIterator<Item = &'a str>,
) -> Option<BearerChallenge> {
    for header in headers {
        let mut bearer = false;
        let mut challenge = BearerChallenge::default();
        let mut found = false;
        for part in auth_header_parts(header) {
            let (candidate, param) = match part.split_once(char::is_whitespace) {
                Some((scheme, rest))
                    if !scheme.contains('=') && !rest.trim_start().starts_with('=') =>
                {
                    (Some(scheme), rest.trim())
                }
                None if !part.contains('=') => (Some(part), ""),
                _ => (None, part),
            };
            if let Some(scheme) = candidate {
                // Any new auth scheme starts a new challenge, including a
                // second Bearer challenge. Do not merge its parameters into
                // the first Bearer challenge selected above.
                if found {
                    break;
                }
                bearer = scheme.eq_ignore_ascii_case("bearer");
                found = bearer;
            }
            if !bearer || param.is_empty() {
                continue;
            }
            let Some((name, value)) = auth_param(param) else {
                continue;
            };
            let value = value.trim().to_string();
            if value.is_empty() {
                continue;
            }
            if name.eq_ignore_ascii_case("resource_metadata") {
                challenge.resource_metadata.get_or_insert(value);
            } else if name.eq_ignore_ascii_case("scope") {
                challenge.scope.get_or_insert(value);
            } else if name.eq_ignore_ascii_case("error") {
                challenge.error.get_or_insert(value);
            }
        }
        if found {
            return Some(challenge);
        }
    }
    None
}

#[derive(Deserialize)]
struct AsMeta {
    issuer: String,
    authorization_endpoint: String,
    token_endpoint: String,
    registration_endpoint: Option<String>,
    scopes_supported: Option<Vec<String>>,
    #[serde(default)]
    authorization_response_iss_parameter_supported: bool,
    #[serde(default)]
    client_id_metadata_document_supported: bool,
    /// RFC 8414. Absent means `client_secret_basic` per the spec, so this stays
    /// `Option` rather than defaulting to an empty list, which would instead read
    /// as "the server supports nothing".
    token_endpoint_auth_methods_supported: Option<Vec<String>>,
}

enum ClientRegistration<'a> {
    MetadataDocument,
    Dynamic(&'a str),
}

fn select_client_registration(endpoints: &Endpoints) -> Result<ClientRegistration<'_>, String> {
    if endpoints.client_id_metadata_document_supported {
        Ok(ClientRegistration::MetadataDocument)
    } else if let Some(endpoint) = endpoints.registration_endpoint.as_deref() {
        Ok(ClientRegistration::Dynamic(endpoint))
    } else {
        Err(
            "this server supports neither Client ID Metadata Documents nor dynamic registration; OAuth needs a pre-registered client"
                .to_string(),
        )
    }
}

/// A ureq agent with a connect + read timeout for all OAuth HTTP. These endpoints
/// come from a fetched (and attacker-influenceable) metadata document, so a slow or
/// black-holed host must not hang the worker indefinitely behind a spinner that
/// never resolves. Bare `ureq::get/post` have no timeout; this does.
/// Refuse link-local / cloud-metadata addresses (169.254.169.254, the AWS ULA
/// `fd00:ec2::254`, IPv4-mapped forms) for EVERY flow. When `block_private`, also refuse
/// loopback / RFC1918 / ULA - set for a public-provenance server, whose metadata must not
/// point our token POST at the user's internal network. Fail-closed if ANY resolved address
/// is refused, so a DNS answer mixing a public and an internal IP can't sneak the bad one
/// through. `block_private` is left false for a server the user configured at a local/LAN
/// address, so a self-hosted MCP auth server keeps working.
fn screen_addrs(addrs: &[std::net::SocketAddr], block_private: bool) -> std::io::Result<()> {
    for sa in addrs {
        if ip_is_link_local(&sa.ip()) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                format!("OAuth SSRF guard: refusing link-local / cloud-metadata address {}", sa.ip()),
            ));
        }
        if block_private && ip_is_private(&sa.ip()) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                format!("OAuth SSRF guard: refusing private/loopback address {} for a public server", sa.ip()),
            ));
        }
    }
    Ok(())
}

/// A DNS resolver that screens every resolved address (see [`screen_addrs`]). Installed on
/// the OAuth agents so the check runs INSIDE ureq's resolver - covering the initial connect
/// AND any redirect target, and closing the resolve-then-connect (DNS-rebind) window that a
/// separate pre-check has. `block_private` is a STABLE, provenance-derived flag (whether the
/// user's configured server is public), not a per-connect re-resolution, so a hostile host
/// that rebinds public->private between the pre-check and the connect is still refused here.
/// The OAuth endpoints come from an attacker-influenceable metadata document, so this is the
/// load-bearing SSRF guard.
fn screened_resolve(netloc: &str, block_private: bool) -> std::io::Result<Vec<std::net::SocketAddr>> {
    use std::net::ToSocketAddrs;
    let addrs: Vec<std::net::SocketAddr> = netloc.to_socket_addrs()?.collect();
    screen_addrs(&addrs, block_private)?;
    Ok(addrs)
}

fn agent(block_private: bool) -> ureq::Agent {
    ureq::AgentBuilder::new()
        .timeout(std::time::Duration::from_secs(30))
        .resolver(move |netloc: &str| screened_resolve(netloc, block_private))
        .build()
}

/// Like [`agent`] but refuses to follow redirects. Used for the credential-bearing
/// POSTs (DCR, token exchange, refresh): a hostile authorization-server metadata
/// document could otherwise 302 the token POST to a host it controls and capture the
/// auth code or refresh token. Metadata discovery (a read-only GET) keeps following
/// redirects so providers that redirect their `.well-known` still resolve; both agents
/// screen resolved addresses so a redirect or rebind to cloud metadata is refused.
fn agent_no_redirect(block_private: bool) -> ureq::Agent {
    ureq::AgentBuilder::new()
        .timeout(std::time::Duration::from_secs(30))
        .redirects(0)
        .resolver(move |netloc: &str| screened_resolve(netloc, block_private))
        .build()
}

/// Short-lived, no-redirect agent for the optional Bearer challenge probe.
/// Discovery must not inherit the 30-second credential-exchange timeout when
/// an older or unhealthy MCP endpoint does not answer the preflight request.
fn challenge_probe_agent(block_private: bool) -> ureq::Agent {
    ureq::AgentBuilder::new()
        .timeout(std::time::Duration::from_secs(5))
        .redirects(0)
        .resolver(move |netloc: &str| screened_resolve(netloc, block_private))
        .build()
}

fn get_json<T: serde::de::DeserializeOwned>(url: &str, block_private: bool) -> Result<T, String> {
    agent(block_private)
        .get(url)
        .call()
        .map_err(|e| e.to_string())?
        .into_json::<T>()
        .map_err(|e| e.to_string())
}

/// Fetch optional discovery metadata while distinguishing an absent/unreachable
/// endpoint from a reachable endpoint that returned malformed JSON. Older MCP
/// servers may not implement the protected-resource well-known URI, but a 2xx
/// response must not bypass validation merely by being unparseable.
fn get_optional_discovery_json<T: serde::de::DeserializeOwned>(
    url: &str,
    block_private: bool,
) -> Result<Option<T>, String> {
    let response = match agent(block_private).get(url).call() {
        Ok(response) => response,
        Err(_) => return Ok(None),
    };
    response
        .into_json::<T>()
        .map(Some)
        .map_err(|e| format!("metadata response was not valid JSON: {e}"))
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
            format!("{origin}{path}/.well-known/openid-configuration"),
            // Compatibility fallback used by some pre-spec servers. The three
            // required MCP candidates above retain their normative priority.
            format!("{origin}{path}/.well-known/oauth-authorization-server"),
        ]
    }
}

/// RFC 9728 inserts the protected-resource well-known suffix between the origin
/// and the resource path. MCP additionally requires clients to fall back to the
/// origin-level document after trying the path-specific form.
fn protected_resource_metadata_candidates(resource: &str) -> Vec<String> {
    let Ok(parsed) = url::Url::parse(resource) else {
        return vec![format!(
            "{}/.well-known/oauth-protected-resource",
            origin_of(resource).trim_end_matches('/')
        )];
    };
    let mut origin_url = parsed.clone();
    origin_url.set_path("");
    origin_url.set_query(None);
    origin_url.set_fragment(None);
    let origin = origin_url.as_str().trim_end_matches('/');
    let root = format!("{origin}/.well-known/oauth-protected-resource");
    let path = parsed.path().trim_start_matches('/');
    let mut specific = root.clone();
    if !path.is_empty() {
        specific.push('/');
        specific.push_str(path);
    }
    if let Some(query) = parsed.query() {
        specific.push('?');
        specific.push_str(query);
    }
    if specific == root {
        vec![root]
    } else {
        vec![specific, root]
    }
}

fn validated_protected_resource(
    expected_resource: &str,
    metadata: ProtectedResource,
) -> Result<(String, Option<String>), String> {
    let resource = metadata.resource.ok_or_else(|| {
        "protected-resource metadata has no resource identifier; refusing OAuth discovery"
            .to_string()
    })?;
    if resource != expected_resource {
        return Err(
            "protected-resource metadata describes a different resource; refusing OAuth discovery"
                .to_string(),
        );
    }
    let issuer = metadata
        .authorization_servers
        .and_then(|servers| {
            servers
                .into_iter()
                .map(|issuer| issuer.trim().to_string())
                .find(|issuer| !issuer.is_empty())
        })
        .ok_or_else(|| {
            "protected-resource metadata has no authorization server; refusing OAuth discovery"
                .to_string()
        })?;
    let scope = metadata.scopes_supported.and_then(normalized_scope);
    Ok((issuer, scope))
}

fn normalized_scope(scopes: Vec<String>) -> Option<String> {
    let scope = scopes
        .into_iter()
        .map(|scope| scope.trim().to_string())
        .filter(|scope| !scope.is_empty())
        .collect::<Vec<_>>()
        .join(" ");
    (!scope.is_empty()).then_some(scope)
}

fn initial_scope(
    protected_resource_found: bool,
    protected_resource_scope: Option<String>,
    authorization_server_scopes: Option<Vec<String>>,
) -> Option<String> {
    if protected_resource_found {
        // Absence is meaningful: current MCP says to omit `scope` when the
        // resource did not advertise one, not to request every AS-wide scope.
        protected_resource_scope
    } else {
        // Compatibility for older MCP servers that predate RFC 9728 metadata.
        authorization_server_scopes.and_then(normalized_scope)
    }
}

/// Preserve the order supplied by the authorization server while removing
/// duplicates. In a step-up flow `existing` is the scope set Toolport requested
/// previously and `additional` is the current operation's authoritative
/// challenge, as required by the MCP scope-union rule.
pub(crate) fn scope_union(existing: Option<&str>, additional: Option<&str>) -> Option<String> {
    let mut scopes: Vec<&str> = Vec::new();
    for scope in existing
        .into_iter()
        .chain(additional)
        .flat_map(str::split_whitespace)
    {
        if !scopes.contains(&scope) {
            scopes.push(scope);
        }
    }
    (!scopes.is_empty()).then(|| scopes.join(" "))
}

/// RFC 8414 and OIDC Discovery bind a metadata document to the issuer used to
/// locate it. Keep this as an exact string comparison: normalizing case, ports,
/// slashes, or percent encoding would weaken the value later recorded for RFC
/// 9207 authorization-response validation.
fn validate_metadata_issuer(expected: &str, actual: &str) -> Result<(), String> {
    if actual == expected {
        Ok(())
    } else {
        Err("authorization-server metadata issuer mismatch; refusing OAuth discovery".to_string())
    }
}

/// Require an endpoint to use https, allowing only loopback http for local dev.
/// The loopback exception is decided on the PARSED host, not a string prefix: a
/// prefix check (`starts_with("http://127.0.0.1")`) also accepts a cleartext
/// endpoint at an attacker-controlled host like `http://127.0.0.1.evil.com/token`
/// or `http://localhost@evil.com/`, defeating the TLS-required invariant. Only a
/// host that IS loopback (127.0.0.0/8, ::1, or `localhost`) may skip https.
fn require_https(url: &str, what: &str) -> Result<(), String> {
    let lower = url.trim().to_ascii_lowercase();
    if lower.starts_with("https://") {
        return Ok(());
    }
    if lower.starts_with("http://") {
        if let Some(host) = host_of_url(&lower) {
            let is_loopback = host == "localhost"
                || host.ends_with(".localhost")
                || host
                    .parse::<std::net::IpAddr>()
                    .map(|ip| ip.is_loopback())
                    .unwrap_or(false);
            if is_loopback {
                return Ok(());
            }
        }
    }
    Err(format!("{what} must use https (got {url})"))
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

/// True only when `host` can be POSITIVELY confirmed local: `localhost`, a literal
/// private IP, or a name that RESOLVES and whose every address is private. Unlike
/// [`host_is_private`] (which fails closed, returning true for an unresolvable host so it
/// is safe for REFUSING), this fails to `false` on an empty/unparseable/unresolvable host,
/// and on any host with even one public address. It is the safe input for GRANTING local
/// trust: an attacker who serves NXDOMAIN for their own domain cannot get it classified as
/// local and thereby switch off the SSRF endpoint guard. See issue #422.
pub fn host_is_definitely_private(host: &str) -> bool {
    use std::net::ToSocketAddrs;
    let h = host.trim().to_ascii_lowercase();
    if h.is_empty() {
        return false;
    }
    if h == "localhost" || h.ends_with(".localhost") {
        return true;
    }
    match (h.as_str(), 0u16).to_socket_addrs() {
        // Confirmed local ONLY if it resolved to at least one address and every one is
        // private. A mix of private + public is not confirmed-local (fail safe: guard on).
        Ok(addrs) => {
            let ips: Vec<_> = addrs.map(|sa| sa.ip()).collect();
            !ips.is_empty() && ips.iter().all(ip_is_private)
        }
        Err(_) => false,
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

/// Ask the configured endpoint for its Bearer challenge before starting OAuth.
/// Current MCP servers use this response to point clients at the exact RFC 9728
/// metadata document and, when authorization is incremental, the scope needed
/// for the attempted request. Failure to obtain a challenge is not fatal because
/// pre-RFC 9728 servers still rely on well-known discovery.
fn probe_bearer_challenge(mcp_url: &str, block_private: bool) -> Option<BearerChallenge> {
    let body = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "server/discover",
        "params": {
            "_meta": {
                "io.modelcontextprotocol/protocolVersion": crate::downstream::MODERN_PROTOCOL_VERSION,
                "io.modelcontextprotocol/clientInfo": {
                    "name": "toolport",
                    "version": env!("CARGO_PKG_VERSION")
                },
                "io.modelcontextprotocol/clientCapabilities": {}
            }
        }
    });
    let response = challenge_probe_agent(block_private)
        .post(mcp_url)
        .set("Content-Type", "application/json")
        .set("Accept", "application/json, text/event-stream")
        .set(
            "MCP-Protocol-Version",
            crate::downstream::MODERN_PROTOCOL_VERSION,
        )
        .set("Mcp-Method", "server/discover")
        .send_json(body);
    match response {
        Err(ureq::Error::Status(code, response)) if code == 401 || code == 403 => {
            let values = response.all("www-authenticate");
            let challenge = bearer_challenge(values.iter().copied());
            drain_probe_response(response);
            challenge
        }
        Ok(response) => {
            drain_probe_response(response);
            None
        }
        Err(ureq::Error::Status(code, response)) => {
            drain_probe_response(response);
            debug_log(&format!("OAuth challenge probe returned HTTP {code}"));
            None
        }
        Err(error @ ureq::Error::Transport(_)) => {
            debug_log(&format!("OAuth challenge probe failed: {error}"));
            None
        }
    }
}

/// Drain a bounded amount from probe responses so ordinary error pages do not
/// prevent connection reuse, without allowing a hostile body to consume
/// unbounded memory or time.
fn drain_probe_response(response: ureq::Response) {
    let mut reader = response.into_reader().take(8 * 1024);
    let _ = std::io::copy(&mut reader, &mut std::io::sink());
}

/// Discover the authorization + token endpoints for an MCP server URL.
pub fn discover(mcp_url: &str) -> Result<Endpoints, String> {
    let origin = origin_of(mcp_url);
    // Is the configured MCP server itself local? If so, local OAuth endpoints are
    // expected and allowed; if it's public, its metadata must not redirect us at a
    // private/loopback host (SSRF). This is a stable property of the URL the user
    // configured, so it also drives the resolver's rebind-safe `block_private`.
    // Positive determination only (#422): an unresolvable host must NOT be treated as
    // local, or a server that serves NXDOMAIN for its own domain gets the SSRF guard
    // switched off and can redirect the token POST at the internal network.
    let server_local = host_of_url(mcp_url)
        .map(|h| host_is_definitely_private(&h))
        .unwrap_or(false);
    let block_private = !server_local;
    let challenge = probe_bearer_challenge(mcp_url, block_private);
    let challenge_scope = challenge
        .as_ref()
        .and_then(|challenge| challenge.scope.clone());
    let mut protected_resource_found = false;
    let mut resource_scope = None;
    let mut discovered_issuer = None;
    let challenge_metadata = challenge.and_then(|challenge| challenge.resource_metadata);
    if let Some(url) = challenge_metadata.as_ref() {
        require_https(url, "protected-resource metadata")?;
        guard_endpoint(url, server_local, "protected-resource metadata")?;
        match get_optional_discovery_json::<ProtectedResource>(url, block_private) {
            Ok(Some(metadata)) => {
                let (issuer, scope) =
                    validated_protected_resource(mcp_url, metadata).map_err(|e| {
                        format!("protected-resource metadata rejected at {url}: {e}")
                    })?;
                protected_resource_found = true;
                discovered_issuer = Some(issuer);
                resource_scope = scope;
            }
            Ok(None) => debug_log(&format!(
                "protected-resource metadata advertised at {url} was unavailable; trying well-known discovery"
            )),
            Err(e) => {
                return Err(format!(
                    "protected-resource metadata rejected at {url}: {e}"
                ))
            }
        }
    }
    if discovered_issuer.is_none() {
        for url in protected_resource_metadata_candidates(mcp_url) {
            match get_optional_discovery_json::<ProtectedResource>(&url, block_private) {
                Ok(Some(metadata)) => match validated_protected_resource(mcp_url, metadata) {
                    Ok((issuer, scope)) => {
                        protected_resource_found = true;
                        discovered_issuer = Some(issuer);
                        resource_scope = scope;
                        break;
                    }
                    // A document was found and parsed, so rejecting its security
                    // binding must fail closed. Falling back to origin-level AS
                    // discovery here would silently bypass RFC 9728 validation.
                    Err(e) => {
                        return Err(format!(
                            "protected-resource metadata rejected at {url}: {e}"
                        ))
                    }
                },
                Ok(None) => {}
                Err(e) => {
                    return Err(format!(
                        "protected-resource metadata rejected at {url}: {e}"
                    ))
                }
            }
        }
    }
    // Preserve compatibility with pre-RFC 9728 servers that publish only
    // authorization-server metadata at the MCP origin. Current MCP servers are
    // expected to take the validated protected-resource path above.
    let issuer = discovered_issuer.unwrap_or_else(|| origin.clone());

    // The issuer can come from the protected-resource document, so guard the
    // metadata fetch too, not just the final endpoints. Requiring TLS here
    // prevents an attacker from substituting the metadata before its endpoint
    // URLs receive their own HTTPS and SSRF checks.
    require_https(&issuer, "authorization server")?;
    guard_endpoint(&issuer, server_local, "authorization server")?;

    for url in metadata_candidates(&issuer) {
        if let Ok(meta) = get_json::<AsMeta>(&url, block_private) {
            if let Err(e) = validate_metadata_issuer(&issuer, &meta.issuer) {
                debug_log(&format!("metadata rejected at {url}: {e}"));
                continue;
            }
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
                issuer: meta.issuer,
                authorization_endpoint: meta.authorization_endpoint,
                token_endpoint: meta.token_endpoint,
                registration_endpoint: meta.registration_endpoint,
                // The protected resource defines the scopes needed to access it.
                // Keep AS metadata as a compatibility fallback for older servers
                // that did not publish RFC 9728 protected-resource metadata.
                scope: challenge_scope.or_else(|| {
                    initial_scope(
                        protected_resource_found,
                        resource_scope,
                        meta.scopes_supported,
                    )
                }),
                authorization_response_iss_parameter_supported: meta
                    .authorization_response_iss_parameter_supported,
                client_id_metadata_document_supported: meta
                    .client_id_metadata_document_supported,
                token_endpoint_auth_methods_supported: meta
                    .token_endpoint_auth_methods_supported,
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

fn register_client(
    registration_endpoint: &str,
    redirect_uri: &str,
    block_private: bool,
) -> Result<String, String> {
    let body = dcr_request_body(redirect_uri);
    let resp: DcrResponse = agent_no_redirect(block_private)
        .post(registration_endpoint)
        .send_json(body)
        .map_err(|e| e.to_string())?
        .into_json()
        .map_err(|e| e.to_string())?;
    Ok(resp.client_id)
}

fn dcr_request_body(redirect_uri: &str) -> serde_json::Value {
    serde_json::json!({
        "client_name": "Toolport",
        "redirect_uris": [redirect_uri],
        "grant_types": ["authorization_code", "refresh_token"],
        "response_types": ["code"],
        "token_endpoint_auth_method": "none",
        // Toolport uses an RFC 8252 loopback redirect with an OS-assigned port,
        // so it is a native public client rather than an OIDC web client.
        "application_type": "native"
    })
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
    /// Access-token lifetime in seconds, when the server reports it. Converted
    /// to an absolute expiry so later processes can refresh before the deadline.
    #[serde(default)]
    expires_in: Option<u64>,
}

impl TokenResponse {
    fn into_tokens(self, issued_at: u64) -> Tokens {
        Tokens {
            access_token: self.access_token,
            refresh_token: self.refresh_token,
            issued_at,
            expires_at: self
                .expires_in
                .map(|lifetime| issued_at.saturating_add(lifetime)),
        }
    }
}

fn now_epoch_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
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
    block_private: bool,
) -> Result<Tokens, String> {
    let resp: TokenResponse = agent_no_redirect(block_private)
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
    Ok(resp.into_tokens(now_epoch_seconds()))
}

/// Exchange a refresh token for a fresh access token (non-interactive). When a
/// `resource` is given it's sent as the RFC 8707 resource indicator, so the
/// refreshed token stays bound to the same MCP server it was first issued for.
pub fn refresh(
    token_endpoint: &str,
    client_id: &str,
    refresh_token: &str,
    resource: Option<&str>,
    block_private: bool,
) -> Result<Tokens, String> {
    let mut form: Vec<(&str, &str)> = vec![
        ("grant_type", "refresh_token"),
        ("refresh_token", refresh_token),
        ("client_id", client_id),
    ];
    if let Some(r) = resource {
        form.push(("resource", r));
    }
    let resp: TokenResponse = agent_no_redirect(block_private)
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
    Ok(resp.into_tokens(now_epoch_seconds()))
}

/// Mint an access token with the RFC 6749 client-credentials grant (SBS-524).
///
/// This is the headless path: no browser, no user consent, no refresh token. The
/// authorization server issues a token to the *client* rather than on behalf of a
/// user, so when it expires the correct move is to ask for another one, not to
/// redeem a refresh token. Servers are told not to issue one for this grant.
///
/// Deliberately fails closed rather than falling back to the interactive flow. A
/// headless connection that silently opened a browser would be a surprising and
/// unusable behaviour on a server, which is the environment this exists for.
///
/// `resource` rides as the RFC 8707 resource indicator so the token stays bound to
/// the MCP server it was minted for, matching [`exchange_code`] and [`refresh`].
pub fn client_credentials_token(
    token_endpoint: &str,
    client_id: &str,
    client_secret: &str,
    method: ClientAuthMethod,
    scope: Option<&str>,
    resource: Option<&str>,
    block_private: bool,
) -> Result<Tokens, String> {
    if !method.is_implemented() {
        return Err(format!(
            "{} is not supported yet (tracked in SBS-599)",
            method.as_str()
        ));
    }
    // The secret rides in this request, so the transport must be encrypted. Same
    // rule as every other credential-bearing call here; loopback is exempt for
    // local development only.
    require_https(token_endpoint, "token endpoint")?;

    let mut form: Vec<(&str, &str)> = vec![("grant_type", "client_credentials")];
    if let Some(s) = scope {
        form.push(("scope", s));
    }
    if let Some(r) = resource {
        form.push(("resource", r));
    }

    // `agent_no_redirect`: a 302 on a credential-bearing POST could hand the
    // client secret to a host named by an attacker-influenceable metadata
    // document. Same reasoning as the code exchange and refresh.
    let request = agent_no_redirect(block_private).post(token_endpoint);
    let response = match method {
        ClientAuthMethod::ClientSecretBasic => {
            // RFC 6749 §2.3.1: client_id and secret are form-urlencoded before
            // base64, not sent raw. Skipping that corrupts any secret containing
            // a `+`, `:` or `/`, which is common in generated credentials.
            let credentials = format!(
                "{}:{}",
                urlencoding::encode(client_id),
                urlencoding::encode(client_secret)
            );
            let header = format!(
                "Basic {}",
                base64::engine::general_purpose::STANDARD.encode(credentials.as_bytes())
            );
            request.set("Authorization", &header).send_form(&form)
        }
        ClientAuthMethod::ClientSecretPost => {
            let mut form = form.clone();
            form.push(("client_id", client_id));
            form.push(("client_secret", client_secret));
            request.send_form(&form)
        }
        ClientAuthMethod::PrivateKeyJwt => unreachable!("rejected above"),
    };

    let resp: TokenResponse = response
        .map_err(|e| redact_secret(&e.to_string(), client_secret))?
        .into_json()
        .map_err(|e| redact_secret(&e.to_string(), client_secret))?;
    debug_log(&format!(
        "client_credentials response: method={} expires_in={:?} refresh_token={}",
        method.as_str(),
        resp.expires_in,
        resp.refresh_token.is_some()
    ));
    let mut tokens = resp.into_tokens(now_epoch_seconds());
    // RFC 6749 §4.4.3: a refresh token SHOULD NOT be issued for this grant. If a
    // server sends one anyway, drop it rather than vault it: keeping it would let
    // the reacquire path silently become a refresh path, and the whole point of
    // this flow is that re-authentication is cheap and non-interactive.
    tokens.refresh_token = None;
    Ok(tokens)
}

/// Strip a credential out of text that is about to be surfaced or logged.
///
/// Transport errors can quote the request, and this flow puts the secret in the
/// body for `client_secret_post`. Redacting at the boundary is cheaper to keep
/// right than auditing every downstream sink.
fn redact_secret(text: &str, secret: &str) -> String {
    if secret.is_empty() {
        return text.to_string();
    }
    text.replace(secret, "***")
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

fn validate_authorization_response_issuer(
    response_issuer: Option<&str>,
    expected_issuer: &str,
    issuer_parameter_required: bool,
) -> Result<(), String> {
    match response_issuer {
        Some(actual) if actual == expected_issuer => Ok(()),
        Some(_) => Err(
            "authorization response issuer mismatch (possible mix-up attack); try connecting again"
                .to_string(),
        ),
        None if issuer_parameter_required => Err(
            "authorization server omitted the issuer it advertised; try connecting again"
                .to_string(),
        ),
        None => Ok(()),
    }
}

fn wait_for_code(
    listener: &TcpListener,
    expected_state: &str,
    expected_issuer: &str,
    issuer_parameter_required: bool,
) -> Result<String, String> {
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
                    "callback request: {} bytes of query, has_code={} has_error={} has_state={} has_iss={}",
                    query.len(),
                    code.is_some(),
                    error.is_some(),
                    params.contains_key("state"),
                    params.contains_key("iss")
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

                // Validate state and issuer before accepting a code OR acting on an
                // error. RFC 9207 explicitly forbids displaying attacker-supplied
                // error details when the response issuer does not match.
                if params.get("state").map(String::as_str) != Some(expected_state) {
                    write_callback_page(&mut stream, "Authorization could not be verified. You can close this window.");
                    return Err("state mismatch (possible CSRF); try connecting again".to_string());
                }
                if let Err(e) = validate_authorization_response_issuer(
                    params.get("iss").map(String::as_str),
                    expected_issuer,
                    issuer_parameter_required,
                ) {
                    write_callback_page(&mut stream, "Authorization could not be verified. You can close this window.");
                    return Err(e);
                }

                if let Some(error) = error {
                    let desc = params
                        .get("error_description")
                        .map(|d| format!(": {d}"))
                        .unwrap_or_default();
                    write_callback_page(&mut stream, "Authorization failed. You can close this window and return to Toolport.");
                    return Err(format!("authorization server returned an error ({error}){desc}"));
                }

                let Some(code) = code.filter(|code| !code.trim().is_empty()) else {
                    write_callback_page(&mut stream, "Authorization failed. You can close this window and return to Toolport.");
                    return Err(
                        "authorization server returned an empty authorization code".to_string(),
                    );
                };

                write_callback_page(&mut stream, "Authorization complete. You can close this window and return to Toolport.");
                return Ok(code.clone());
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
    authenticate_with_scope(mcp_url, None)
}

/// Run interactive authorization while retaining a previously requested scope
/// set and adding a runtime challenge. Discovery's initial scope is included too,
/// but never replaces either side of the step-up union.
pub fn authenticate_with_scope(
    mcp_url: &str,
    requested_scope_set: Option<&str>,
) -> Result<AuthResult, String> {
    debug_log(&format!("=== oauth start: {mcp_url} ==="));
    // Same provenance rule as discover(): a public configured server must not have
    // its DCR / token POST reach a private/loopback host, even via a DNS rebind. Use the
    // positive-determination predicate so an unresolvable host stays screened (#422).
    let block_private = !host_of_url(mcp_url)
        .map(|h| host_is_definitely_private(&h))
        .unwrap_or(false);
    let endpoints = discover(mcp_url)?;
    let scope = scope_union(requested_scope_set, endpoints.scope.as_deref());
    debug_log(&format!(
        "endpoints: authz={} token={} reg={:?} cimd={} scope={:?}",
        endpoints.authorization_endpoint,
        endpoints.token_endpoint,
        endpoints.registration_endpoint,
        endpoints.client_id_metadata_document_supported,
        scope
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

    let client_id = match select_client_registration(&endpoints)? {
        ClientRegistration::MetadataDocument => CLIENT_ID_METADATA_URL.to_string(),
        ClientRegistration::Dynamic(registration_endpoint) => {
            register_client(registration_endpoint, &redirect_uri, block_private)?
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
    let scope = requested_scope(scope);
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
    let code = wait_for_code(
        &listener,
        &state,
        &endpoints.issuer,
        endpoints.authorization_response_iss_parameter_supported,
    )?;
    debug_log(&format!("got code (len {})", code.len()));
    let tokens = match exchange_code(
        &endpoints.token_endpoint,
        &client_id,
        &redirect_uri,
        &code,
        &verifier,
        mcp_url,
        block_private,
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
        issued_at: tokens.issued_at,
        expires_at: tokens.expires_at,
        token_endpoint: endpoints.token_endpoint,
        client_id,
        issuer: endpoints.issuer,
        scope,
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
        // Link-local / metadata is refused regardless of block_private.
        for bad in ["169.254.169.254:80", "[fd00:ec2::254]:80", "[::ffff:169.254.169.254]:80"] {
            assert!(screen_addrs(&[p(bad)], false).is_err(), "must refuse {bad}");
        }
        // A public address is always allowed.
        assert!(screen_addrs(&[p("140.82.112.3:443")], true).is_ok());
        // A private/loopback one is allowed only for a local-provenance server.
        assert!(screen_addrs(&[p("127.0.0.1:8080")], false).is_ok());
        assert!(screen_addrs(&[p("10.0.0.5:443")], false).is_ok());
        // Fail-closed: a mixed public+metadata answer is refused whole.
        assert!(screen_addrs(&[p("8.8.8.8:443"), p("169.254.169.254:80")], false).is_err());
    }

    #[test]
    fn screen_addrs_blocks_private_for_public_server() {
        use std::net::SocketAddr;
        let p = |s: &str| s.parse::<SocketAddr>().unwrap();
        // With block_private set (public-provenance server), a rebind to loopback /
        // RFC1918 / CGNAT / IPv6-ULA is refused - closing the DNS-rebind SSRF window.
        for bad in ["127.0.0.1:8080", "10.0.0.5:443", "192.168.1.1:80", "100.64.0.1:80", "[fc00::1]:80"] {
            assert!(screen_addrs(&[p(bad)], true).is_err(), "must refuse {bad} for a public server");
        }
        // A public IP still resolves for the public server.
        assert!(screen_addrs(&[p("8.8.8.8:443")], true).is_ok());
        // Fail-closed: public + private mix is refused whole for a public server.
        assert!(screen_addrs(&[p("8.8.8.8:443"), p("10.0.0.5:80")], true).is_err());
    }

    #[test]
    fn require_https_rejects_prefix_lookalike_hosts() {
        // https is always fine.
        assert!(require_https("https://auth.example.com/token", "token").is_ok());
        // Genuine loopback http is allowed for local dev.
        assert!(require_https("http://127.0.0.1:9000/token", "token").is_ok());
        assert!(require_https("http://localhost:9000/token", "token").is_ok());
        assert!(require_https("http://[::1]:9000/token", "token").is_ok());
        // Prefix look-alikes at an attacker host must NOT satisfy the loopback exception.
        assert!(require_https("http://127.0.0.1.evil.com/token", "token").is_err());
        assert!(require_https("http://localhost.evil.com/token", "token").is_err());
        assert!(require_https("http://localhost@evil.com/token", "token").is_err());
        // A plain public cleartext endpoint is refused.
        assert!(require_https("http://auth.example.com/token", "token").is_err());
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
    fn host_is_definitely_private_requires_positive_confirmation() {
        // Positively local: localhost and literal private IPs (no DNS needed).
        assert!(host_is_definitely_private("localhost"));
        assert!(host_is_definitely_private("foo.localhost"));
        assert!(host_is_definitely_private("127.0.0.1"));
        assert!(host_is_definitely_private("10.1.2.3"));
        assert!(host_is_definitely_private("192.168.1.10"));

        // NOT confirmable, so NOT local: empty, public, and (the #422 fix) unresolvable.
        // `.invalid` is guaranteed non-resolvable (RFC 2606), so this needs no network.
        assert!(!host_is_definitely_private(""));
        assert!(!host_is_definitely_private("8.8.8.8"));
        assert!(!host_is_definitely_private("no-such-host-422.invalid"));

        // The contrast that is the whole bug: host_is_private treats an unresolvable
        // host as private (fail closed, for refusing), but that must NOT grant local trust.
        assert!(host_is_private("no-such-host-422.invalid"));
        assert!(!host_is_definitely_private("no-such-host-422.invalid"));
    }

    #[test]
    fn unresolvable_server_host_does_not_disable_the_ssrf_guard() {
        // The end-to-end shape of #422: server_local is derived from the configured MCP
        // host. When that host is unresolvable, the OLD code (host_is_private) returned
        // true and made guard_endpoint a no-op, so a metadata doc pointing at 127.0.0.1
        // was accepted. With host_is_definitely_private it's false, so the guard still
        // refuses the internal endpoint.
        let server_local = host_is_definitely_private("no-such-host-422.invalid");
        assert!(!server_local, "an unresolvable server host is not local");
        assert!(
            guard_endpoint("http://127.0.0.1:9999/token", server_local, "token").is_err(),
            "the token endpoint must still be refused for an unresolvable (public-provenance) server"
        );

        // A genuinely local server (literal private IP) still gets its local endpoints.
        let local = host_is_definitely_private("192.168.1.10");
        assert!(local);
        assert!(guard_endpoint("http://127.0.0.1:9999/token", local, "token").is_ok());
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
    fn dcr_identifies_the_loopback_client_as_native() {
        let body = dcr_request_body("http://127.0.0.1:41789/callback");
        assert_eq!(body["application_type"], "native");
        assert_eq!(body["token_endpoint_auth_method"], "none");
        assert_eq!(
            body["redirect_uris"],
            serde_json::json!(["http://127.0.0.1:41789/callback"])
        );
    }

    #[test]
    fn authorization_response_issuer_follows_rfc9207_table() {
        let expected = "https://auth.example.com";
        assert!(validate_authorization_response_issuer(Some(expected), expected, true).is_ok());
        assert!(validate_authorization_response_issuer(Some(expected), expected, false).is_ok());
        assert!(validate_authorization_response_issuer(None, expected, false).is_ok());
        assert!(validate_authorization_response_issuer(None, expected, true).is_err());
        assert!(validate_authorization_response_issuer(
            Some("https://evil.example.com"),
            expected,
            false
        )
        .is_err());
    }

    #[test]
    fn authorization_response_issuer_comparison_is_not_normalized() {
        let expected = "https://auth.example.com";
        for different in [
            "https://AUTH.example.com",
            "https://auth.example.com/",
            "https://auth.example.com:443",
        ] {
            assert!(
                validate_authorization_response_issuer(Some(different), expected, false).is_err(),
                "must compare the issuer exactly: {different}"
            );
        }
    }

    #[test]
    fn callback_rejects_an_empty_authorization_code() {
        use std::io::Write;

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let address = listener.local_addr().unwrap();
        let client = std::thread::spawn(move || {
            let mut stream = std::net::TcpStream::connect(address).unwrap();
            stream
                .write_all(
                    b"GET /callback?code=&state=expected HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n",
                )
                .unwrap();
        });

        let error = wait_for_code(&listener, "expected", "https://auth.example.com", false)
            .expect_err("an empty authorization code must not reach token exchange");
        client.join().unwrap();
        assert!(error.contains("empty authorization code"));
    }

    #[test]
    fn metadata_issuer_must_match_the_selected_authorization_server() {
        assert!(validate_metadata_issuer(
            "https://auth.example.com",
            "https://auth.example.com"
        )
        .is_ok());
        assert!(validate_metadata_issuer(
            "https://auth.example.com",
            "https://other.example.com"
        )
        .is_err());
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
    fn token_response_keeps_issue_and_expiry_timestamps() {
        let tokens = TokenResponse {
            access_token: "access".into(),
            refresh_token: Some("refresh".into()),
            expires_in: Some(3_600),
        }
        .into_tokens(1_000);

        assert_eq!(tokens.issued_at, 1_000);
        assert_eq!(tokens.expires_at, Some(4_600));
        assert_eq!(tokens.refresh_token.as_deref(), Some("refresh"));
    }

    #[test]
    fn token_response_without_lifetime_keeps_unknown_expiry() {
        let tokens = TokenResponse {
            access_token: "access".into(),
            refresh_token: None,
            expires_in: None,
        }
        .into_tokens(1_000);

        assert_eq!(tokens.issued_at, 1_000);
        assert_eq!(tokens.expires_at, None);
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
        assert_eq!(
            c[2],
            "https://access.stripe.com/mcp/.well-known/openid-configuration"
        );
    }

    #[test]
    fn protected_resource_candidates_try_the_endpoint_path_then_origin() {
        assert_eq!(
            protected_resource_metadata_candidates("https://mcp.example.com/public/mcp"),
            vec![
                "https://mcp.example.com/.well-known/oauth-protected-resource/public/mcp",
                "https://mcp.example.com/.well-known/oauth-protected-resource",
            ]
        );
        assert_eq!(
            protected_resource_metadata_candidates("https://mcp.example.com"),
            vec!["https://mcp.example.com/.well-known/oauth-protected-resource"]
        );
        assert_eq!(
            protected_resource_metadata_candidates("https://mcp.example.com/mcp?tenant=acme"),
            vec![
                "https://mcp.example.com/.well-known/oauth-protected-resource/mcp?tenant=acme",
                "https://mcp.example.com/.well-known/oauth-protected-resource",
            ]
        );
    }

    #[test]
    fn protected_resource_metadata_is_bound_and_supplies_scopes() {
        let metadata = ProtectedResource {
            resource: Some("https://mcp.example.com/mcp".into()),
            authorization_servers: Some(vec!["https://auth.example.com".into()]),
            scopes_supported: Some(vec!["files:read".into(), "files:write".into()]),
        };
        let (issuer, scope) =
            validated_protected_resource("https://mcp.example.com/mcp", metadata).unwrap();
        assert_eq!(issuer, "https://auth.example.com");
        assert_eq!(scope.as_deref(), Some("files:read files:write"));
    }

    #[test]
    fn protected_resource_metadata_normalizes_advertised_scopes() {
        let metadata = ProtectedResource {
            resource: Some("https://mcp.example.com/mcp".into()),
            authorization_servers: Some(vec!["  https://auth.example.com  ".into()]),
            scopes_supported: Some(vec![
                " files:read ".into(),
                "".into(),
                "  ".into(),
                "files:write".into(),
            ]),
        };
        let (issuer, scope) =
            validated_protected_resource("https://mcp.example.com/mcp", metadata).unwrap();
        assert_eq!(issuer, "https://auth.example.com");
        assert_eq!(scope.as_deref(), Some("files:read files:write"));
    }

    #[test]
    fn protected_resource_scope_absence_does_not_expand_to_all_as_scopes() {
        assert_eq!(
            initial_scope(
                true,
                None,
                Some(vec!["openid".into(), "admin".into()])
            ),
            None
        );
        assert_eq!(
            initial_scope(
                false,
                None,
                Some(vec![" ".into(), " legacy:mcp ".into(), "".into()])
            ),
            Some("legacy:mcp".into())
        );
    }

    #[test]
    fn protected_resource_metadata_rejects_impersonation_and_empty_issuers() {
        let missing_resource = ProtectedResource {
            resource: None,
            authorization_servers: Some(vec!["https://auth.example.com".into()]),
            scopes_supported: None,
        };
        let error = validated_protected_resource(
            "https://mcp.example.com/mcp",
            missing_resource,
        )
        .unwrap_err();
        assert!(error.contains("no resource identifier"));

        let wrong_resource = ProtectedResource {
            resource: Some("https://other.example.com/mcp".into()),
            authorization_servers: Some(vec!["https://auth.example.com".into()]),
            scopes_supported: None,
        };
        assert!(validated_protected_resource(
            "https://mcp.example.com/mcp",
            wrong_resource
        )
        .is_err());

        let no_issuer = ProtectedResource {
            resource: Some("https://mcp.example.com/mcp".into()),
            authorization_servers: Some(vec!["".into()]),
            scopes_supported: None,
        };
        assert!(validated_protected_resource("https://mcp.example.com/mcp", no_issuer).is_err());
    }

    #[test]
    fn bearer_challenge_extracts_resource_metadata_and_scope() {
        let parsed = bearer_challenge([
            "Basic realm=\"legacy\", Bearer resource_metadata=\"https://mcp.example.com/auth/meta?label=a,b\", scope=\"files:read files:write\", error=\"insufficient_scope\"",
        ])
        .expect("Bearer challenge should be selected after another scheme");
        assert_eq!(
            parsed.resource_metadata.as_deref(),
            Some("https://mcp.example.com/auth/meta?label=a,b")
        );
        assert_eq!(parsed.scope.as_deref(), Some("files:read files:write"));
        assert_eq!(parsed.error.as_deref(), Some("insufficient_scope"));
    }

    #[test]
    fn bearer_challenge_supports_repeated_headers_and_quoted_escapes() {
        let parsed = bearer_challenge([
            "Basic realm=\"legacy\"",
            "Bearer error=\"invalid_token\", resource_metadata=\"https://mcp.example.com/meta?note=a\\\"b\"",
        ])
        .expect("Bearer challenge should be found in a later field");
        assert_eq!(
            parsed.resource_metadata.as_deref(),
            Some("https://mcp.example.com/meta?note=a\"b")
        );
        assert_eq!(parsed.scope, None);
    }

    #[test]
    fn bearer_challenge_ignores_empty_scope_and_stops_at_the_next_scheme() {
        let parsed = bearer_challenge([
            "Bearer scope=\"\", Basic realm=\"other\", resource_metadata=\"https://wrong.example/meta\"",
        ])
        .expect("Bearer scheme should still be recognized");
        assert_eq!(parsed, BearerChallenge::default());
    }

    #[test]
    fn bearer_challenge_does_not_merge_multiple_bearer_challenges() {
        let parsed = bearer_challenge([
            "Bearer scope=\"files:read\", Bearer resource_metadata=\"https://wrong.example/meta\"",
        ])
        .expect("the first Bearer challenge should be selected");
        assert_eq!(parsed.scope.as_deref(), Some("files:read"));
        assert_eq!(parsed.resource_metadata, None);
    }

    #[test]
    fn bearer_challenge_recognizes_a_bare_scheme() {
        assert_eq!(
            bearer_challenge(["Bearer, Basic realm=\"legacy\""]),
            Some(BearerChallenge::default())
        );
    }

    #[test]
    fn bearer_challenge_accepts_whitespace_around_parameter_equals() {
        let parsed = bearer_challenge([
            "Bearer resource_metadata = \"https://mcp.example.com/meta\", scope = \"files:read\"",
        ])
        .expect("Bearer challenge with optional whitespace should parse");
        assert_eq!(
            parsed.resource_metadata.as_deref(),
            Some("https://mcp.example.com/meta")
        );
        assert_eq!(parsed.scope.as_deref(), Some("files:read"));
    }

    #[test]
    fn bearer_challenge_probe_handles_other_http_errors() {
        let server = tiny_http::Server::http("127.0.0.1:0").unwrap();
        let address = server.server_addr().to_ip().unwrap();
        let url = format!("http://{address}/mcp");
        let handle = std::thread::spawn(move || {
            let request = server
                .recv_timeout(std::time::Duration::from_secs(2))
                .unwrap()
                .expect("challenge probe");
            request
                .respond(
                    tiny_http::Response::from_string("method not allowed")
                        .with_status_code(405),
                )
                .unwrap();
        });

        assert_eq!(probe_bearer_challenge(&url, false), None);
        handle.join().unwrap();
    }

    #[test]
    fn discovery_uses_the_metadata_url_and_scope_from_the_bearer_challenge() {
        let server = tiny_http::Server::http("127.0.0.1:0").unwrap();
        let port = server.server_addr().to_ip().unwrap().port();
        let origin = format!("http://127.0.0.1:{port}");
        let mcp_url = format!("{origin}/mcp");
        let resource_metadata = format!("{origin}/oauth-resource");
        let expected_resource = mcp_url.clone();
        let expected_origin = origin.clone();
        let handle = std::thread::spawn(move || {
            for _ in 0..3 {
                let request = server
                    .recv_timeout(std::time::Duration::from_secs(2))
                    .unwrap()
                    .expect("OAuth discovery request");
                let response = match request.url() {
                    "/mcp" => {
                        let challenge = format!(
                            "Bearer resource_metadata=\"{resource_metadata}\", scope=\"files:read\""
                        );
                        tiny_http::Response::from_string("authorization required")
                            .with_status_code(401)
                            .with_header(
                                tiny_http::Header::from_bytes(
                                    b"WWW-Authenticate",
                                    challenge.as_bytes(),
                                )
                                .unwrap(),
                            )
                    }
                    "/oauth-resource" => tiny_http::Response::from_string(
                        serde_json::json!({
                            "resource": expected_resource,
                            "authorization_servers": [expected_origin]
                        })
                        .to_string(),
                    )
                    .with_header(
                        tiny_http::Header::from_bytes(b"Content-Type", b"application/json")
                            .unwrap(),
                    ),
                    "/.well-known/oauth-authorization-server" => {
                        tiny_http::Response::from_string(
                            serde_json::json!({
                                "issuer": expected_origin,
                                "authorization_endpoint": format!("{expected_origin}/authorize"),
                                "token_endpoint": format!("{expected_origin}/token"),
                                "registration_endpoint": format!("{expected_origin}/register"),
                                "scopes_supported": ["admin"]
                            })
                            .to_string(),
                        )
                        .with_header(
                            tiny_http::Header::from_bytes(b"Content-Type", b"application/json")
                                .unwrap(),
                        )
                    }
                    path => panic!("unexpected OAuth discovery path: {path}"),
                };
                request.respond(response).unwrap();
            }
        });

        let endpoints = discover(&mcp_url).expect("challenge-guided discovery should succeed");
        handle.join().unwrap();
        assert_eq!(endpoints.issuer, origin);
        assert_eq!(endpoints.scope.as_deref(), Some("files:read"));
    }

    #[test]
    fn discovery_falls_back_when_challenge_metadata_is_unavailable() {
        let server = tiny_http::Server::http("127.0.0.1:0").unwrap();
        let port = server.server_addr().to_ip().unwrap().port();
        let origin = format!("http://127.0.0.1:{port}");
        let mcp_url = format!("{origin}/mcp");
        let resource_metadata = format!("{origin}/unavailable-resource");
        let expected_resource = mcp_url.clone();
        let expected_origin = origin.clone();
        let handle = std::thread::spawn(move || {
            for _ in 0..4 {
                let request = server
                    .recv_timeout(std::time::Duration::from_secs(2))
                    .unwrap()
                    .expect("OAuth discovery request");
                let response = match request.url() {
                    "/mcp" => {
                        let challenge = format!(
                            "Bearer resource_metadata=\"{resource_metadata}\", scope=\"files:read\""
                        );
                        tiny_http::Response::from_string("authorization required")
                            .with_status_code(401)
                            .with_header(
                                tiny_http::Header::from_bytes(
                                    b"WWW-Authenticate",
                                    challenge.as_bytes(),
                                )
                                .unwrap(),
                            )
                    }
                    "/unavailable-resource" => {
                        tiny_http::Response::from_string("temporarily unavailable")
                            .with_status_code(503)
                    }
                    "/.well-known/oauth-protected-resource/mcp" => {
                        tiny_http::Response::from_string(
                            serde_json::json!({
                                "resource": expected_resource,
                                "authorization_servers": [expected_origin]
                            })
                            .to_string(),
                        )
                        .with_header(
                            tiny_http::Header::from_bytes(b"Content-Type", b"application/json")
                                .unwrap(),
                        )
                    }
                    "/.well-known/oauth-authorization-server" => {
                        tiny_http::Response::from_string(
                            serde_json::json!({
                                "issuer": expected_origin,
                                "authorization_endpoint": format!("{expected_origin}/authorize"),
                                "token_endpoint": format!("{expected_origin}/token")
                            })
                            .to_string(),
                        )
                        .with_header(
                            tiny_http::Header::from_bytes(b"Content-Type", b"application/json")
                                .unwrap(),
                        )
                    }
                    path => panic!("unexpected OAuth discovery path: {path}"),
                };
                request.respond(response).unwrap();
            }
        });

        let endpoints = discover(&mcp_url).expect("well-known fallback should succeed");
        handle.join().unwrap();
        assert_eq!(endpoints.issuer, origin);
        assert_eq!(endpoints.scope.as_deref(), Some("files:read"));
    }

    #[test]
    fn discovery_rejects_malformed_challenge_metadata_without_fallback() {
        let server = tiny_http::Server::http("127.0.0.1:0").unwrap();
        let port = server.server_addr().to_ip().unwrap().port();
        let origin = format!("http://127.0.0.1:{port}");
        let mcp_url = format!("{origin}/mcp");
        let resource_metadata = format!("{origin}/malformed-resource");
        let handle = std::thread::spawn(move || {
            for _ in 0..2 {
                let request = server
                    .recv_timeout(std::time::Duration::from_secs(2))
                    .unwrap()
                    .expect("OAuth discovery request");
                let response = match request.url() {
                    "/mcp" => {
                        let challenge =
                            format!("Bearer resource_metadata=\"{resource_metadata}\"");
                        tiny_http::Response::from_string("authorization required")
                            .with_status_code(401)
                            .with_header(
                                tiny_http::Header::from_bytes(
                                    b"WWW-Authenticate",
                                    challenge.as_bytes(),
                                )
                                .unwrap(),
                            )
                    }
                    "/malformed-resource" => tiny_http::Response::from_string("not json")
                        .with_header(
                            tiny_http::Header::from_bytes(b"Content-Type", b"application/json")
                                .unwrap(),
                        ),
                    path => panic!("unexpected OAuth discovery path: {path}"),
                };
                request.respond(response).unwrap();
            }
        });

        let error = discover(&mcp_url).unwrap_err();
        handle.join().unwrap();
        assert!(error.contains("metadata response was not valid JSON"));
        assert!(error.contains("/malformed-resource"));
    }

    #[test]
    fn discover_fails_closed_on_invalid_protected_resource_metadata() {
        use std::sync::{Arc, Mutex};
        use std::time::Duration;

        let server = tiny_http::Server::http("127.0.0.1:0").unwrap();
        let address = server.server_addr().to_ip().unwrap();
        let resource = format!("http://{address}");
        let requested_paths = Arc::new(Mutex::new(Vec::new()));
        let seen = Arc::clone(&requested_paths);
        let handle = std::thread::spawn(move || {
            while let Ok(Some(request)) = server.recv_timeout(Duration::from_millis(250)) {
                seen.lock().unwrap().push(request.url().to_string());
                let response = tiny_http::Response::from_string(
                    serde_json::json!({
                        "authorization_servers": ["https://auth.example.com"]
                    })
                    .to_string(),
                )
                .with_header(
                    tiny_http::Header::from_bytes(b"Content-Type", b"application/json").unwrap(),
                );
                request.respond(response).unwrap();
            }
        });

        let error = discover(&resource).unwrap_err();
        handle.join().unwrap();

        assert!(error.contains("no resource identifier"));
        assert_eq!(
            requested_paths.lock().unwrap().as_slice(),
            ["/", "/.well-known/oauth-protected-resource"]
        );
    }

    #[test]
    fn discover_fails_closed_on_malformed_protected_resource_metadata() {
        use std::time::Duration;

        let server = tiny_http::Server::http("127.0.0.1:0").unwrap();
        let address = server.server_addr().to_ip().unwrap();
        let resource = format!("http://{address}");
        let handle = std::thread::spawn(move || {
            for body in ["", "not json"] {
                let request = server
                    .recv_timeout(Duration::from_secs(2))
                    .unwrap()
                    .expect("OAuth discovery request");
                let response = if body.is_empty() {
                    tiny_http::Response::from_string(body)
                } else {
                    tiny_http::Response::from_string(body).with_header(
                        tiny_http::Header::from_bytes(b"Content-Type", b"application/json")
                            .unwrap(),
                    )
                };
                request.respond(response).unwrap();
            }
        });

        let error = discover(&resource).unwrap_err();
        handle.join().unwrap();

        assert!(error.contains("metadata response was not valid JSON"));
    }

    #[test]
    fn discover_refuses_cleartext_authorization_server_metadata() {
        use std::time::Duration;

        let server = tiny_http::Server::http("127.0.0.1:0").unwrap();
        let address = server.server_addr().to_ip().unwrap();
        let resource = format!("http://{address}");
        let document_resource = resource.clone();
        let handle = std::thread::spawn(move || {
            for body in [
                String::new(),
                serde_json::json!({
                    "resource": document_resource,
                    "authorization_servers": ["http://8.8.8.8"]
                })
                .to_string(),
            ] {
                let request = server
                    .recv_timeout(Duration::from_secs(2))
                    .unwrap()
                    .expect("OAuth discovery request");
                let response = if body.is_empty() {
                    tiny_http::Response::from_string(body)
                } else {
                    tiny_http::Response::from_string(body).with_header(
                        tiny_http::Header::from_bytes(b"Content-Type", b"application/json")
                            .unwrap(),
                    )
                };
                request.respond(response).unwrap();
            }
        });

        let error = discover(&resource).unwrap_err();
        handle.join().unwrap();

        assert!(error.contains("authorization server must use https"));
    }

    #[test]
    fn step_up_scope_union_preserves_prior_access_and_deduplicates() {
        assert_eq!(
            scope_union(
                Some("files:read profile"),
                Some("files:write files:read")
            )
            .as_deref(),
            Some("files:read profile files:write")
        );
        assert_eq!(scope_union(None, Some("  files:read  ")).as_deref(), Some("files:read"));
        assert_eq!(scope_union(Some(""), None), None);
    }

    #[test]
    fn cimd_is_preferred_over_dynamic_registration_when_advertised() {
        let endpoints = |cimd, registration_endpoint| Endpoints {
            issuer: "https://auth.example.com".into(),
            authorization_endpoint: "https://auth.example.com/authorize".into(),
            token_endpoint: "https://auth.example.com/token".into(),
            registration_endpoint,
            scope: None,
            authorization_response_iss_parameter_supported: false,
            client_id_metadata_document_supported: cimd,
            token_endpoint_auth_methods_supported: None,
        };

        assert!(matches!(
            select_client_registration(&endpoints(
                true,
                Some("https://auth.example.com/register".into())
            )),
            Ok(ClientRegistration::MetadataDocument)
        ));
        assert!(matches!(
            select_client_registration(&endpoints(
                false,
                Some("https://auth.example.com/register".into())
            )),
            Ok(ClientRegistration::Dynamic("https://auth.example.com/register"))
        ));
        assert!(select_client_registration(&endpoints(false, None)).is_err());
    }

    #[test]
    fn cimd_client_id_is_a_stable_https_url_with_a_path() {
        let client_id = url::Url::parse(CLIENT_ID_METADATA_URL).unwrap();
        assert_eq!(client_id.scheme(), "https");
        assert_ne!(client_id.path(), "/");
        assert_eq!(client_id.as_str(), CLIENT_ID_METADATA_URL);
    }

    #[test]
    fn authorization_server_metadata_reads_cimd_capability() {
        let metadata: AsMeta = serde_json::from_value(serde_json::json!({
            "issuer": "https://auth.example.com",
            "authorization_endpoint": "https://auth.example.com/authorize",
            "token_endpoint": "https://auth.example.com/token",
            "client_id_metadata_document_supported": true
        }))
        .unwrap();
        assert!(metadata.client_id_metadata_document_supported);
    }

    // ----- SBS-524: client-credentials auth-method selection ------------------

    fn methods(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| s.to_string()).collect()
    }

    /// RFC 8414: a server that omits `token_endpoint_auth_methods_supported` is
    /// declaring `client_secret_basic`, not declaring nothing.
    #[test]
    fn absent_or_empty_advertisement_means_client_secret_basic() {
        assert_eq!(
            select_client_auth_method(None, None).unwrap(),
            ClientAuthMethod::ClientSecretBasic
        );
        // An empty list is treated the same rather than as "supports nothing",
        // which would make such a server unusable for no good reason.
        assert_eq!(
            select_client_auth_method(None, Some(&[])).unwrap(),
            ClientAuthMethod::ClientSecretBasic
        );
    }

    #[test]
    fn auto_selection_picks_a_method_we_can_actually_perform() {
        assert_eq!(
            select_client_auth_method(None, Some(&methods(&["client_secret_post"]))).unwrap(),
            ClientAuthMethod::ClientSecretPost
        );
        assert_eq!(
            select_client_auth_method(
                None,
                Some(&methods(&["client_secret_post", "client_secret_basic"]))
            )
            .unwrap(),
            ClientAuthMethod::ClientSecretBasic
        );
    }

    /// `private_key_jwt` must never be auto-selected while it is unimplemented:
    /// picking it would fail every connection to a server that also offers a
    /// secret-based method we can use.
    #[test]
    fn auto_selection_skips_private_key_jwt_but_uses_a_usable_sibling() {
        assert_eq!(
            select_client_auth_method(
                None,
                Some(&methods(&["private_key_jwt", "client_secret_post"]))
            )
            .unwrap(),
            ClientAuthMethod::ClientSecretPost
        );
    }

    #[test]
    fn auto_selection_fails_closed_when_nothing_is_usable() {
        let err = select_client_auth_method(
            None,
            Some(&methods(&["private_key_jwt", "tls_client_auth"])),
        )
        .unwrap_err();
        assert!(err.contains("SBS-599"), "error should point at the follow-up: {err}");
    }

    /// Configuring an unimplemented method fails rather than quietly downgrading
    /// to a shared secret, which would be a security regression.
    #[test]
    fn configured_private_key_jwt_fails_closed_rather_than_downgrading() {
        let err = select_client_auth_method(
            Some(ClientAuthMethod::PrivateKeyJwt),
            Some(&methods(&["private_key_jwt", "client_secret_basic"])),
        )
        .unwrap_err();
        assert!(err.contains("not supported yet"), "{err}");
        assert!(err.contains("SBS-599"), "{err}");
    }

    /// Never send a secret by a method the server did not advertise.
    #[test]
    fn configured_method_must_be_advertised() {
        let err = select_client_auth_method(
            Some(ClientAuthMethod::ClientSecretPost),
            Some(&methods(&["client_secret_basic"])),
        )
        .unwrap_err();
        assert!(err.contains("does not accept client_secret_post"), "{err}");

        // But an explicit choice is honoured when the server says nothing, since
        // there is no advertisement to contradict it.
        assert_eq!(
            select_client_auth_method(Some(ClientAuthMethod::ClientSecretPost), None).unwrap(),
            ClientAuthMethod::ClientSecretPost
        );
    }

    #[test]
    fn auth_method_identifiers_round_trip() {
        for m in [
            ClientAuthMethod::ClientSecretPost,
            ClientAuthMethod::ClientSecretBasic,
            ClientAuthMethod::PrivateKeyJwt,
        ] {
            assert_eq!(ClientAuthMethod::parse(m.as_str()), Some(m));
        }
        assert_eq!(ClientAuthMethod::parse("none"), None);
        assert_eq!(ClientAuthMethod::parse("tls_client_auth"), None);
    }

    /// The token endpoint receives the secret, so cleartext is refused outright
    /// before any request is made.
    #[test]
    fn client_credentials_refuses_a_cleartext_token_endpoint() {
        // `unwrap_err` would require `Tokens: Debug`, and `Tokens` deliberately
        // does not derive it: a Debug impl on a struct holding an access token is
        // one stray `{:?}` away from logging the credential.
        let err = match client_credentials_token(
            "http://auth.example.com/token",
            "client",
            "s3cret",
            ClientAuthMethod::ClientSecretBasic,
            None,
            None,
            true,
        ) {
            Err(e) => e,
            Ok(_) => panic!("a cleartext token endpoint must be refused"),
        };
        assert!(err.contains("must use https"), "{err}");
    }

    #[test]
    fn client_credentials_rejects_private_key_jwt_before_any_request() {
        let err = match client_credentials_token(
            "https://auth.example.com/token",
            "client",
            "",
            ClientAuthMethod::PrivateKeyJwt,
            None,
            None,
            true,
        ) {
            Err(e) => e,
            Ok(_) => panic!("private_key_jwt must be refused before any request"),
        };
        assert!(err.contains("SBS-599"), "{err}");
    }

    /// A secret can appear in a transport error that quotes the request body.
    #[test]
    fn secrets_are_redacted_from_surfaced_text() {
        assert_eq!(
            redact_secret("POST failed: client_secret=hunter2&x=1", "hunter2"),
            "POST failed: client_secret=***&x=1"
        );
        // An empty secret must not turn every character into a redaction.
        assert_eq!(redact_secret("nothing to hide", ""), "nothing to hide");
    }
}
