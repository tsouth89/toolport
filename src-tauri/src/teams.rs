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

pub fn save_token(token: &str) -> Result<(), String> {
    crate::secrets::set_secret(TEAM_TOKEN_SERVER, TEAM_TOKEN_KEY, token)
}
pub fn load_token() -> Option<String> {
    crate::secrets::get_secret(TEAM_TOKEN_SERVER, TEAM_TOKEN_KEY)
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
        || host.parse::<std::net::IpAddr>().ok().map_or(false, |ip| match ip {
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
        Err("team server URL must use https:// unless it is loopback HTTP for local development".to_string())
    }
}

/// A ureq agent with a connect + read timeout. The team commands run on the Tauri
/// command thread, so a slow or black-holed team server must not hang the UI: bare
/// `ureq::get/post/put` have no timeout, this does.
fn agent() -> ureq::Agent {
    agent_with_timeout(30)
}

/// A ureq agent with an explicit total timeout. A long-poll config pull needs a client
/// timeout comfortably above the server's `wait` window, so the server (not the client)
/// decides when to return.
fn agent_with_timeout(secs: u64) -> ureq::Agent {
    ureq::AgentBuilder::new()
        .timeout(std::time::Duration::from_secs(secs))
        .build()
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
pub fn join(server_url: &str, invite_code: &str, member_name: Option<&str>) -> Result<JoinResult, String> {
    require_secure_team_url(server_url)?;
    let url = format!("{}/join", base(server_url));
    let body = serde_json::json!({ "invite_code": invite_code, "member_name": member_name });
    let resp = agent().post(&url).send_json(body).map_err(stringify)?;
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
    let resp = agent().post(&url).send_json(body).map_err(stringify)?;
    let v: Value = resp.into_json().map_err(|e| e.to_string())?;
    match v["status"].as_str().unwrap_or("") {
        "approved" => complete_join(server_url, member_name, joined_from(&v)?).map(JoinPoll::Connected),
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
        agent_with_timeout(wait_secs + 10)
    } else {
        agent()
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
    match agent()
        .get(&url)
        .set("authorization", &format!("Bearer {token}"))
        .call()
    {
        Ok(resp) => {
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

/// Admin push of the team config. Returns the new version.
pub fn push_config(server_url: &str, team_id: &str, token: &str, config: &Value) -> Result<i64, String> {
    require_secure_team_url(server_url)?;
    let url = format!("{}/teams/{}/config", base(server_url), team_id);
    let body = serde_json::json!({ "config": config });
    let resp = agent()
        .put(&url)
        .set("authorization", &format!("Bearer {token}"))
        .send_json(body)
        .map_err(stringify)?;
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
) -> Result<bool, String> {
    require_secure_team_url(server_url)?;
    let url = format!("{}/teams/{}/usage", base(server_url), team_id);
    match agent()
        .post(&url)
        .set("authorization", &format!("Bearer {token}"))
        .send_json(json!({ "day": day, "rows": rows }))
    {
        Ok(_) => Ok(true),
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
pub fn connect(server_url: &str, invite_code: &str, member_name: Option<&str>) -> Result<ConnectOutcome, String> {
    match join(server_url, invite_code, member_name)? {
        JoinResult::Joined(joined) => {
            complete_join(server_url, member_name, joined).map(ConnectOutcome::Connected)
        }
        JoinResult::Pending { request_token } => Ok(ConnectOutcome::Pending { request_token }),
    }
}

/// Finalize an approved join: vault the token, record the connection, and do the first
/// pull + merge. Shared by the direct-connect and approval-poll paths.
fn complete_join(server_url: &str, member_name: Option<&str>, joined: Joined) -> Result<MergeOutcome, String> {
    save_token(&joined.member_token)?;
    // The token is now in the keychain. Any failure past this point must clear it,
    // or we'd orphan a live bearer token with no local record of the connection.
    finish_connect(server_url, member_name, joined)
        .map(|(_conn, outcome)| outcome)
        .inspect_err(|_| {
            let _ = clear_token();
        })
}

fn finish_connect(server_url: &str, member_name: Option<&str>, joined: Joined) -> Result<(TeamConnection, MergeOutcome), String> {
    let conn = TeamConnection {
        server_url: base(server_url),
        team_id: joined.team_id.clone(),
        role: joined.role.clone(),
        member_name: member_name.map(String::from),
        last_version: 0,
        last_etag: None,
        usage_reported: HashMap::new(),
    };
    // Pull BEFORE loading the registry, then load a FRESH copy AFTER the (possibly
    // multi-second) network round trip and apply onto that — mirroring `sync_inner`.
    // Loading first and saving here would clobber any change another command made to the
    // registry while we were waiting on the join window's pull.
    let pulled = pull_config(&base(server_url), &joined.team_id, &joined.member_token, 0, None, 0)?;
    let mut reg = crate::registry::load()?;
    reg.team = Some(conn);
    let mut outcome = MergeOutcome::default();
    if let Some((version, cfg, etag)) = pulled {
        outcome = apply_team_config(&mut reg, &joined.team_id, &cfg);
        if let Some(t) = reg.team.as_mut() {
            t.last_version = version;
            t.last_etag = etag;
        }
    }
    crate::registry::save(&reg)?;
    let conn = reg.team.clone().ok_or_else(|| "team connection lost after save".to_string())?;
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
    let token = load_token().ok_or("team token is missing from the keychain")?;

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

    // Re-load a FRESH registry now, AFTER the (possibly multi-second) network round
    // trips, and apply the deltas to it. Loading at the top and saving here would clobber
    // any change another command made to the registry while we were on the network.
    let mut reg = crate::registry::load()?;
    match reg.team.as_ref() {
        // The user disconnected or switched teams mid-sync: don't apply stale results.
        None => return Ok(SyncResult::Ok { role, role_changed, applied: None }),
        Some(t) if t.team_id != conn.team_id => {
            return Ok(SyncResult::Ok { role, role_changed, applied: None })
        }
        _ => {}
    }

    let applied = match pulled {
        None => None,
        Some((version, cfg, etag)) => {
            let outcome = apply_team_config(&mut reg, &conn.team_id, &cfg);
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
    crate::registry::save(&reg)?;
    // Best-effort showback after the config work: report today's/yesterday's per-server
    // usage rollup to the team server. Any failure here must never affect the sync
    // result — the member's config is already applied and saved.
    report_usage(&conn, &token);
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
        let Ok(reg) = crate::registry::load() else { return };
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
    let audit_lines = crate::audit::read_recent(usize::MAX);
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
        match post_usage_day(&conn.server_url, &conn.team_id, token, &day, rows) {
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
    let Ok(mut reg) = crate::registry::load() else { return };
    if let Some(t) = reg.team.as_mut() {
        if t.team_id == conn.team_id {
            t.usage_reported = new_state;
            let _ = crate::registry::save(&reg);
        }
    }
}

/// Leave the team: remove its merged servers, clear the connection and the token.
pub fn disconnect() -> Result<(), String> {
    let mut reg = crate::registry::load()?;
    if let Some(conn) = reg.team.clone() {
        remove_team(&mut reg, &conn.team_id);
    }
    reg.team = None;
    crate::registry::save(&reg)?;
    let _ = clear_token();
    Ok(())
}

/// Admin: push the current local server set as the team config. The user's own servers
/// only (team-sourced ones are excluded), secret values never sent. Returns the version.
pub fn push_current() -> Result<i64, String> {
    let reg = crate::registry::load()?;
    let conn = reg.team.clone().ok_or("not connected to a team")?;
    if conn.role != "admin" {
        return Err("only a team admin can push the shared config".into());
    }
    let token = load_token().ok_or("team token is missing from the keychain")?;
    let cfg = team_export(&reg);
    push_config(&conn.server_url, &conn.team_id, &token, &cfg)
}

/// Build the config an admin pushes: the user's own servers (not team-sourced), with
/// env keys but no secret values, plus the destructive-tool policy flag and the
/// org screening policy.
fn team_export(reg: &Registry) -> Value {
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
                .map(|a| {
                    if crate::arg_looks_secret(a) {
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
            })
        })
        .collect();
    serde_json::json!({
        "servers": servers,
        "denyDestructive": reg.deny_destructive,
        // Org screening policy. Emitted on every push so a desktop push never silently
        // wipes a dashboard-set policy. Each flag is tighten-only on the member side:
        // `true` forces the corresponding local safety toggle on, `false`/absent is a
        // no-op that can never turn a member's toggle off. Shape is intentionally
        // extensible (e.g. a future `sensitivity` field) without a breaking change.
        "screeningPolicy": {
            "forceContentDefense": reg.content_defense,
            "forceQuarantineOnDrift": reg.quarantine_on_drift,
            "forceHumanApproval": reg.human_approval,
        },
    })
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
    let prev_enabled_by_profile: std::collections::HashMap<String, std::collections::HashSet<String>> =
        reg.profiles
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
    let mut used_ids: Vec<String> = reg.servers.iter().map(|s| s.id.clone()).collect();
    let mut outcome = MergeOutcome::default();
    if let Some(arr) = team_cfg.get("servers").and_then(Value::as_array) {
        for s in arr {
            match classify_team_server(s, &tag) {
                TeamClass::Ready(mut entry) => {
                    entry.id = crate::registry::unique_id(&entry.id, &used_ids);
                    used_ids.push(entry.id.clone());
                    auto_enable.push(entry.id.clone());
                    reg.servers.push(entry);
                    outcome.applied += 1;
                }
                TeamClass::Review(mut entry) => {
                    entry.id = crate::registry::unique_id(&entry.id, &used_ids);
                    used_ids.push(entry.id.clone());
                    review_ids.push(entry.id.clone());
                    reg.servers.push(entry);
                    outcome.review += 1;
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
    let active_id = reg.active_profile_id.clone();
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
            if was_enabled(id) && !p.enabled_server_ids.contains(id) {
                p.enabled_server_ids.push(id.clone());
            }
        }
    }

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

    outcome
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
            .map(|a| a.iter().filter_map(|x| x.as_str().map(String::from)).collect())
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
    // Loopback / LAN (RFC1918) is a legit internal server, but require opt-in like stdio.
    if crate::oauth::host_is_private(&host) {
        return TeamClass::Review(entry);
    }
    TeamClass::Ready(entry)
}

fn slugify_id(s: &str) -> String {
    s.chars()
        .map(|c| if c.is_ascii_alphanumeric() { c.to_ascii_lowercase() } else { '-' })
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
    }
    // Release ALL of this team's forced safety locks: the member is no longer in the team, so
    // an org-forced policy (HITL, destructive-block, content defense, drift-quarantine) must not
    // keep applying. Their OWN settings are left untouched.
    reg.team_forced_human_approval = false;
    reg.team_forced_deny_destructive = false;
    reg.team_forced_content_defense = false;
    reg.team_forced_quarantine_on_drift = false;
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn merge_reported_takes_the_max_per_counter() {
        // A log rotation can shrink the local rollup mid-day; the already-reported
        // watermark must win so the re-send never erases counts the server has.
        let mut local = BTreeMap::new();
        local.insert("github".to_string(), usage_report::Row { calls: 3, tokens_saved: 900 });
        local.insert("stripe".to_string(), usage_report::Row { calls: 7, tokens_saved: 0 });
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
        r.profiles.iter().find(|p| p.id == active).unwrap().enabled_server_ids.clone()
    }

    #[test]
    fn merge_adds_team_servers_without_touching_local() {
        let mut r = base_registry();
        let cfg = json!({ "servers": [
            { "id": "github", "name": "GitHub", "transport": "http", "url": "https://1.2.3.4/mcp",
              "env": [{ "key": "TOKEN", "secret": true }] },
            { "id": "stripe", "name": "Stripe", "transport": "http", "url": "https://1.2.3.5/mcp" }
        ]});
        assert_eq!(apply_team_config(&mut r, "t1", &cfg).applied, 2);

        assert!(r.servers.iter().any(|s| s.id == "mine"), "local server preserved");
        let gh = r.servers.iter().find(|s| s.id == "team_github").unwrap();
        assert_eq!(gh.source.as_deref(), Some("team:t1"));
        assert_eq!(gh.env[0].key, "TOKEN");
        assert!(gh.env[0].value.is_none(), "no secret value carried from the team");

        let enabled = active_enabled(&r);
        assert!(enabled.contains(&"team_github".to_string()));
        assert!(enabled.contains(&"team_stripe".to_string()));
        assert!(enabled.contains(&"mine".to_string()), "local enablement preserved");
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
        assert!(!team_ids.contains(&"team_b".to_string()), "removed team server is gone");
        assert!(!active_enabled(&r).contains(&"team_b".to_string()), "no stale profile entry");
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
        assert_eq!(team_ids.len(), 2, "two team server entries, not one overwriting the other");
        let unique: std::collections::HashSet<&String> = team_ids.iter().collect();
        assert_eq!(unique.len(), 2, "the colliding ids were deduped to distinct ids");
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
            r.servers.iter().find(|s| s.id == "team_github").unwrap().source.as_deref(),
            Some("manual"),
        );
        // The team server took a distinct, deduped id.
        let team: Vec<_> = r.servers.iter().filter(|s| s.source.as_deref() == Some("team:t1")).collect();
        assert_eq!(team.len(), 1);
        assert_ne!(team[0].id, "team_github", "team server deduped away from the local id");
    }

    #[test]
    fn team_forced_deny_destructive_is_releasable_and_leaves_the_member_untouched() {
        let mut r = base_registry();
        r.deny_destructive = false; // member's own choice: off
        apply_team_config(&mut r, "t1", &json!({ "servers": [], "denyDestructive": true }));
        assert!(r.team_forced_deny_destructive, "org force recorded separately");
        assert!(!r.deny_destructive, "member's own setting is untouched");
        assert!(r.deny_destructive_effective(), "enforced while the org forces it");
        // Org drops the flag -> released, gate follows the member's own (off).
        apply_team_config(&mut r, "t1", &json!({ "servers": [] }));
        assert!(!r.deny_destructive_effective(), "org released the lock");
        // And leaving the team releases it too.
        apply_team_config(&mut r, "t1", &json!({ "servers": [], "denyDestructive": true }));
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
        assert!(r.content_defense_effective(), "org forced content defense on");
        assert!(r.quarantine_on_drift_effective(), "org forced drift-quarantine on");
        assert!(!r.content_defense, "member's own content-defense is untouched");

        // Org dropping the policy releases both to the member's own (off), no permanent lock.
        apply_team_config(&mut r, "t1", &json!({ "servers": [] }));
        assert!(!r.content_defense_effective(), "content defense released");
        assert!(!r.quarantine_on_drift_effective(), "drift-quarantine released");
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
        apply_team_config(
            &mut r,
            "t1",
            &json!({ "servers": [], "denyDestructive": true, "screeningPolicy": {
                "forceHumanApproval": true,
                "forceContentDefense": true,
                "forceQuarantineOnDrift": true,
            }}),
        );
        assert!(
            r.human_approval_effective()
                && r.deny_destructive_effective()
                && r.content_defense_effective()
                && r.quarantine_on_drift_effective(),
            "all four enforced while in the team"
        );
        remove_team(&mut r, "t1");
        assert!(
            !r.team_forced_human_approval
                && !r.team_forced_deny_destructive
                && !r.team_forced_content_defense
                && !r.team_forced_quarantine_on_drift,
            "leaving clears every org lock"
        );
        assert!(
            !r.human_approval_effective()
                && !r.deny_destructive_effective()
                && !r.content_defense_effective()
                && !r.quarantine_on_drift_effective(),
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
        assert!(r.team_forced_human_approval, "org force recorded separately");
        assert!(!r.human_approval, "member's own setting is never overwritten by the org");
        assert!(r.human_approval_effective(), "gate is active while the org forces it");

        // The org disabling its policy RELEASES the lock (the old code left it stuck on), and
        // the gate reverts to the member's own choice.
        apply_team_config(
            &mut r,
            "t1",
            &json!({ "servers": [], "screeningPolicy": { "forceHumanApproval": false }}),
        );
        assert!(!r.team_forced_human_approval, "org released the force");
        assert!(!r.human_approval_effective(), "gate follows the member's own choice again");
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
        assert!(!r.team_forced_human_approval, "leaving the team clears the org lock");
        assert!(!r.human_approval_effective(), "no team, no force -> follows member's choice");
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
        assert!(r.human_approval_effective(), "the member's own on-setting is preserved");
        remove_team(&mut r, "t1");
        assert!(r.human_approval_effective(), "leaving doesn't disable the member's own choice");
    }

    #[test]
    fn team_export_round_trips_screening_policy() {
        // The pushed config must carry the policy so a desktop push never wipes it, and
        // it must reflect the admin's own toggles.
        let mut r = base_registry();
        r.content_defense = true;
        r.quarantine_on_drift = true;
        r.human_approval = true;
        let cfg = team_export(&r);
        let sp = cfg.get("screeningPolicy").expect("policy is emitted");
        assert_eq!(sp.get("forceContentDefense").and_then(Value::as_bool), Some(true));
        assert_eq!(sp.get("forceQuarantineOnDrift").and_then(Value::as_bool), Some(true));
        assert_eq!(sp.get("forceHumanApproval").and_then(Value::as_bool), Some(true));
    }

    #[test]
    fn team_export_excludes_gateway_and_team_servers() {
        let mut r = base_registry(); // has "mine" (manual)
        // Toolport's own gateway entry: infra, must never be pushed to the team.
        r.servers.push(ServerEntry {
            id: "toolport".into(),
            name: "Toolport".into(),
            transport: "stdio".into(),
            command: Some(r"C:\projects\personal\conduit\src-tauri\target\debug\conduit-gateway.exe".into()),
            args: vec![],
            env: vec![],
            url: None,
            source: Some("manual".into()),
            disabled_tools: vec![],
            cwd: None,
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
            unknown_fields: serde_json::Map::new(),
        });
        let cfg = team_export(&r);
        let ids: Vec<&str> = cfg["servers"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|s| s["id"].as_str())
            .collect();
        assert_eq!(ids, vec!["mine"], "only the member's own non-gateway server is pushed");
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
    fn remove_team_clears_team_servers_only() {
        let mut r = base_registry();
        apply_team_config(
            &mut r,
            "t1",
            &json!({ "servers": [{ "id": "a", "name": "A", "transport": "http", "url": "https://1.2.3.4/mcp" }] }),
        );
        remove_team(&mut r, "t1");
        assert!(r.servers.iter().all(|s| s.source.as_deref() != Some("team:t1")));
        assert!(r.servers.iter().any(|s| s.id == "mine"), "local server preserved");
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
        assert_eq!(outcome.applied, 1, "only the public remote server auto-enables");
        assert_eq!(outcome.review, 3, "two local commands + one loopback URL need review");
        assert_eq!(outcome.blocked, 1, "the link-local/metadata URL is blocked outright");

        let team: Vec<_> = r.servers.iter().filter(|s| s.source.as_deref() == Some("team:t1")).collect();
        assert_eq!(team.len(), 4, "ready + review servers sync; only the blocked one is dropped");
        assert!(!team.iter().any(|s| s.id == "team_meta"), "link-local server never synced");

        // The review stdio server carries its command so the member can run it AFTER opt-in...
        let rce = r.servers.iter().find(|s| s.id == "team_rce").expect("review server synced");
        assert_eq!(rce.command.as_deref(), Some("powershell"));

        // ...but only the public remote server is enabled; review servers stay OFF.
        let enabled = active_enabled(&r);
        assert!(enabled.contains(&"team_safe".to_string()), "ready server auto-enabled");
        assert!(!enabled.contains(&"team_rce".to_string()), "local-command server stays off");
        assert!(!enabled.contains(&"team_lan".to_string()), "loopback server stays off");
    }

    #[test]
    fn re_sync_preserves_member_consent_for_review_servers() {
        let mut r = base_registry();
        let cfg = json!({ "servers": [
            { "id": "tool", "name": "Tool", "transport": "stdio", "command": "npx" }
        ]});
        // First sync: the stdio server is added but OFF (needs review).
        apply_team_config(&mut r, "t1", &cfg);
        assert!(!active_enabled(&r).contains(&"team_tool".to_string()), "review server starts off");
        // Member consents by enabling it.
        let active = r.active_profile_id.clone().unwrap();
        r.profiles.iter_mut().find(|p| p.id == active).unwrap().enabled_server_ids.push("team_tool".into());
        // Re-sync (config unchanged): consent is preserved, the server stays enabled.
        apply_team_config(&mut r, "t1", &cfg);
        assert!(active_enabled(&r).contains(&"team_tool".to_string()), "prior consent survives re-sync");
    }
}
