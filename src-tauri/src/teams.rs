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

use serde_json::Value;

use crate::registry::{EnvVar, Registry, ServerEntry, TeamConnection};

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

/// A ureq agent with a connect + read timeout. The team commands run on the Tauri
/// command thread, so a slow or black-holed team server must not hang the UI: bare
/// `ureq::get/post/put` have no timeout, this does.
fn agent() -> ureq::Agent {
    ureq::AgentBuilder::new()
        .timeout(std::time::Duration::from_secs(30))
        .build()
}

// --- HTTP client (ureq) ---

#[derive(Debug)]
pub struct Joined {
    pub team_id: String,
    pub member_token: String,
    pub role: String,
}

/// Redeem an invite code, returning the member token, team id, and role.
pub fn join(server_url: &str, invite_code: &str, member_name: Option<&str>) -> Result<Joined, String> {
    let url = format!("{}/join", base(server_url));
    let body = serde_json::json!({ "invite_code": invite_code, "member_name": member_name });
    let resp = agent().post(&url).send_json(body).map_err(stringify)?;
    let v: Value = resp.into_json().map_err(|e| e.to_string())?;
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

/// Pull the team's current config. `Ok(None)` means unchanged since `last_version`
/// (HTTP 304); `Ok(Some((version, config)))` is the new config.
pub fn pull_config(
    server_url: &str,
    team_id: &str,
    token: &str,
    last_version: i64,
) -> Result<Option<(i64, Value)>, String> {
    let url = format!("{}/teams/{}/config", base(server_url), team_id);
    let etag = format!("\"v{last_version}\"");
    let req = agent()
        .get(&url)
        .set("authorization", &format!("Bearer {token}"))
        .set("if-none-match", &etag);
    match req.call() {
        Ok(resp) => {
            if resp.status() == 304 {
                return Ok(None);
            }
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
            Ok(Some((version, config)))
        }
        Err(ureq::Error::Status(304, _)) => Ok(None),
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

/// Join a team: redeem the invite, vault the token, record the connection, and do the
/// first pull + merge. Returns the stored connection.
pub fn connect(server_url: &str, invite_code: &str, member_name: Option<&str>) -> Result<MergeOutcome, String> {
    let joined = join(server_url, invite_code, member_name)?;
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
    let mut reg = crate::registry::load()?;
    let conn = TeamConnection {
        server_url: base(server_url),
        team_id: joined.team_id.clone(),
        role: joined.role.clone(),
        member_name: member_name.map(String::from),
        last_version: 0,
    };
    reg.team = Some(conn);
    let mut outcome = MergeOutcome::default();
    if let Some((version, cfg)) = pull_config(&base(server_url), &joined.team_id, &joined.member_token, 0)? {
        outcome = apply_team_config(&mut reg, &joined.team_id, &cfg);
        if let Some(t) = reg.team.as_mut() {
            t.last_version = version;
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

    let pulled = pull_config(&conn.server_url, &conn.team_id, &token, conn.last_version)?;

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
        Some((version, cfg)) => {
            let outcome = apply_team_config(&mut reg, &conn.team_id, &cfg);
            if let Some(t) = reg.team.as_mut() {
                t.last_version = version;
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
    Ok(SyncResult::Ok {
        role,
        role_changed,
        applied,
    })
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
        .filter(|s| s.source.as_deref().map(|x| !x.starts_with("team:")).unwrap_or(true))
        .map(|s| {
            serde_json::json!({
                "id": s.id,
                "name": s.name,
                "transport": s.transport,
                "command": s.command,
                "args": s.args,
                "url": s.url,
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
    //    member had ENABLED. That enablement is their standing consent for the
    //    review-required ones, so we re-apply it after the replace instead of forcing a
    //    re-approval on every sync.
    let old_ids: Vec<String> = reg
        .servers
        .iter()
        .filter(|s| is_team_server(s, &tag))
        .map(|s| s.id.clone())
        .collect();
    let prev_enabled: std::collections::HashSet<String> = reg
        .active_profile_id
        .as_ref()
        .and_then(|aid| reg.profiles.iter().find(|p| &p.id == aid))
        .map(|p| {
            p.enabled_server_ids
                .iter()
                .filter(|id| old_ids.contains(id))
                .cloned()
                .collect()
        })
        .unwrap_or_default();
    reg.servers.retain(|s| !is_team_server(s, &tag));
    for p in &mut reg.profiles {
        p.enabled_server_ids.retain(|id| !old_ids.contains(id));
    }

    // 2. Classify and add the new team servers. Ready (public remote) servers are safe to
    //    auto-enable; review servers (local command or LAN URL) are added but left off;
    //    blocked (link-local/metadata) are refused outright.
    let mut auto_enable: Vec<String> = Vec::new();
    let mut review_ids: Vec<String> = Vec::new();
    let mut outcome = MergeOutcome::default();
    if let Some(arr) = team_cfg.get("servers").and_then(Value::as_array) {
        for s in arr {
            match classify_team_server(s, &tag) {
                TeamClass::Ready(entry) => {
                    auto_enable.push(entry.id.clone());
                    reg.servers.push(entry);
                    outcome.applied += 1;
                }
                TeamClass::Review(entry) => {
                    review_ids.push(entry.id.clone());
                    reg.servers.push(entry);
                    outcome.review += 1;
                }
                TeamClass::Blocked => outcome.blocked += 1,
                TeamClass::Skip => {}
            }
        }
    }

    // 3. Enable: ready servers always; review servers ONLY if the member had already
    //    consented (enabled before this sync). New review servers stay off, so nothing
    //    local runs without an explicit opt-in.
    if let Some(active_id) = reg.active_profile_id.clone() {
        if let Some(p) = reg.profiles.iter_mut().find(|p| p.id == active_id) {
            let to_enable = auto_enable
                .iter()
                .chain(review_ids.iter().filter(|id| prev_enabled.contains(*id)));
            for id in to_enable {
                if !p.enabled_server_ids.contains(id) {
                    p.enabled_server_ids.push(id.clone());
                }
            }
        }
    }

    // 4. Policy can only tighten safety.
    if team_cfg.get("denyDestructive").and_then(Value::as_bool) == Some(true) {
        reg.deny_destructive = true;
    }

    // 5. Screening policy is tighten-only as well: the org can force content defense,
    //    drift-quarantine, and human approval ON, but a member can never be loosened by a
    //    team config. A missing policy or a `false` flag is a no-op (it does not turn a
    //    member's own toggle off), so this only ever raises the member's safety posture.
    if let Some(sp) = team_cfg.get("screeningPolicy") {
        if sp.get("forceContentDefense").and_then(Value::as_bool) == Some(true) {
            reg.content_defense = true;
        }
        if sp.get("forceQuarantineOnDrift").and_then(Value::as_bool) == Some(true) {
            reg.quarantine_on_drift = true;
        }
        // Org-mandated human-in-the-loop: force the member's gateway to hold gated tool
        // calls for human approval. Tighten-only, like the flags above.
        if sp.get("forceHumanApproval").and_then(Value::as_bool) == Some(true) {
            reg.human_approval = true;
        }
    }

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
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

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
    fn policy_can_tighten_but_never_loosen() {
        let mut r = base_registry();
        r.deny_destructive = false;
        apply_team_config(&mut r, "t1", &json!({ "servers": [], "denyDestructive": true }));
        assert!(r.deny_destructive, "team policy tightened safety");
        apply_team_config(&mut r, "t1", &json!({ "servers": [] }));
        assert!(r.deny_destructive, "absence of the flag never loosens an existing lock");
    }

    #[test]
    fn screening_policy_can_tighten_but_never_loosen() {
        let mut r = base_registry();
        // Member starts with content defense off, drift-quarantine off, human approval off.
        r.content_defense = false;
        r.quarantine_on_drift = false;
        r.human_approval = false;

        // Org policy forces all three on: the member's posture is raised.
        apply_team_config(
            &mut r,
            "t1",
            &json!({ "servers": [], "screeningPolicy": {
                "forceContentDefense": true,
                "forceQuarantineOnDrift": true,
                "forceHumanApproval": true,
            }}),
        );
        assert!(r.content_defense, "org policy forced content defense on");
        assert!(r.quarantine_on_drift, "org policy forced drift-quarantine on");
        assert!(r.human_approval, "org policy forced human approval on");

        // A policy with the flags false, or absent entirely, never turns them back off.
        apply_team_config(
            &mut r,
            "t1",
            &json!({ "servers": [], "screeningPolicy": {
                "forceContentDefense": false,
                "forceQuarantineOnDrift": false,
                "forceHumanApproval": false,
            }}),
        );
        assert!(r.content_defense, "false flag never loosens an existing lock");
        assert!(r.quarantine_on_drift, "false flag never loosens an existing lock");
        assert!(r.human_approval, "false flag never loosens an existing lock");

        apply_team_config(&mut r, "t1", &json!({ "servers": [] }));
        assert!(r.content_defense, "absent policy never loosens an existing lock");
        assert!(r.quarantine_on_drift, "absent policy never loosens an existing lock");
        assert!(r.human_approval, "absent policy never loosens an existing lock");
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
