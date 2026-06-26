//! Conduit Teams client: join a team, pull/push the shared MCP server set, and merge
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
    let resp = ureq::post(&url).send_json(body).map_err(stringify)?;
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
    let req = ureq::get(&url)
        .set("authorization", &format!("Bearer {token}"))
        .set("if-none-match", &etag);
    match req.call() {
        Ok(resp) => {
            if resp.status() == 304 {
                return Ok(None);
            }
            let v: Value = resp.into_json().map_err(|e| e.to_string())?;
            Ok(Some((v["version"].as_i64().unwrap_or(0), v["config"].clone())))
        }
        Err(ureq::Error::Status(304, _)) => Ok(None),
        Err(e) => Err(stringify(e)),
    }
}

/// Admin push of the team config. Returns the new version.
pub fn push_config(server_url: &str, team_id: &str, token: &str, config: &Value) -> Result<i64, String> {
    let url = format!("{}/teams/{}/config", base(server_url), team_id);
    let body = serde_json::json!({ "config": config });
    let resp = ureq::put(&url)
        .set("authorization", &format!("Bearer {token}"))
        .send_json(body)
        .map_err(stringify)?;
    let v: Value = resp.into_json().map_err(|e| e.to_string())?;
    Ok(v["version"].as_i64().unwrap_or(0))
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
pub fn connect(server_url: &str, invite_code: &str, member_name: Option<&str>) -> Result<TeamConnection, String> {
    let joined = join(server_url, invite_code, member_name)?;
    save_token(&joined.member_token)?;
    let mut reg = crate::registry::load()?;
    let conn = TeamConnection {
        server_url: base(server_url),
        team_id: joined.team_id.clone(),
        role: joined.role.clone(),
        member_name: member_name.map(String::from),
        last_version: 0,
    };
    reg.team = Some(conn);
    if let Some((version, cfg)) = pull_config(&base(server_url), &joined.team_id, &joined.member_token, 0)? {
        apply_team_config(&mut reg, &joined.team_id, &cfg);
        if let Some(t) = reg.team.as_mut() {
            t.last_version = version;
        }
    }
    crate::registry::save(&reg)?;
    reg.team.clone().ok_or_else(|| "team connection lost after save".into())
}

/// Pull the latest team config and merge it. `Ok(None)` if nothing changed.
pub fn sync_now() -> Result<Option<(i64, usize)>, String> {
    let mut reg = crate::registry::load()?;
    let conn = reg.team.clone().ok_or("not connected to a team")?;
    let token = load_token().ok_or("team token is missing from the keychain")?;
    match pull_config(&conn.server_url, &conn.team_id, &token, conn.last_version)? {
        None => Ok(None),
        Some((version, cfg)) => {
            let merged = apply_team_config(&mut reg, &conn.team_id, &cfg);
            if let Some(t) = reg.team.as_mut() {
                t.last_version = version;
            }
            crate::registry::save(&reg)?;
            Ok(Some((version, merged)))
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
/// env keys but no secret values, plus the destructive-tool policy flag.
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
    serde_json::json!({ "servers": servers, "denyDestructive": reg.deny_destructive })
}

// --- merge (pure, testable) ---

fn tag_for(team_id: &str) -> String {
    format!("team:{team_id}")
}

fn is_team_server(s: &ServerEntry, tag: &str) -> bool {
    s.source.as_deref() == Some(tag)
}

/// Merge a team config (registry-format JSON `{ servers, denyDestructive? }`) into the
/// local registry. Team servers are tagged `source = "team:<id>"`, their ids prefixed
/// `team_`, and enabled in the active profile so they're actually exposed. Re-running
/// REPLACES this team's servers (a removed team server disappears) while leaving the
/// member's own servers and profiles untouched. A team `denyDestructive: true` is
/// adopted: policy can only tighten safety, never loosen it. Returns servers merged.
pub fn apply_team_config(reg: &mut Registry, team_id: &str, team_cfg: &Value) -> usize {
    let tag = tag_for(team_id);

    // 1. Drop the previous generation of this team's servers (clean replace).
    let old_ids: Vec<String> = reg
        .servers
        .iter()
        .filter(|s| is_team_server(s, &tag))
        .map(|s| s.id.clone())
        .collect();
    reg.servers.retain(|s| !is_team_server(s, &tag));
    for p in &mut reg.profiles {
        p.enabled_server_ids.retain(|id| !old_ids.contains(id));
    }

    // 2. Build the new team servers.
    let mut new_ids = Vec::new();
    if let Some(arr) = team_cfg.get("servers").and_then(Value::as_array) {
        for s in arr {
            if let Some(entry) = team_server_entry(s, &tag) {
                new_ids.push(entry.id.clone());
                reg.servers.push(entry);
            }
        }
    }

    // 3. Enable them in the active profile so the gateway exposes them.
    if let Some(active_id) = reg.active_profile_id.clone() {
        if let Some(p) = reg.profiles.iter_mut().find(|p| p.id == active_id) {
            for id in &new_ids {
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

    new_ids.len()
}

/// Convert one team-config server JSON into a tagged `ServerEntry`. Env keeps only keys
/// (no values, since the team server never carried a secret); the member vaults each
/// one locally. Returns None if the entry has neither a name nor an id.
fn team_server_entry(s: &Value, tag: &str) -> Option<ServerEntry> {
    let str_field = |k: &str| s.get(k).and_then(Value::as_str).filter(|x| !x.is_empty());
    let orig_id = str_field("id");
    let name = str_field("name").or(orig_id)?;
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
    Some(ServerEntry {
        id,
        name: name.to_string(),
        transport: str_field("transport").unwrap_or("stdio").to_string(),
        command: str_field("command").map(String::from),
        args: str_array("args"),
        env,
        url: str_field("url").map(String::from),
        source: Some(tag.to_string()),
        disabled_tools: str_array("disabledTools"),
    })
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
            { "id": "github", "name": "GitHub", "transport": "http", "url": "https://api.example/mcp",
              "env": [{ "key": "TOKEN", "secret": true }] },
            { "id": "stripe", "name": "Stripe", "transport": "stdio", "command": "stripe-mcp" }
        ]});
        assert_eq!(apply_team_config(&mut r, "t1", &cfg), 2);

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
                { "id": "a", "name": "A", "transport": "stdio", "command": "a" },
                { "id": "b", "name": "B", "transport": "stdio", "command": "b" }
            ]}),
        );
        // Team drops "b", adds "c".
        apply_team_config(
            &mut r,
            "t1",
            &json!({ "servers": [
                { "id": "a", "name": "A", "transport": "stdio", "command": "a" },
                { "id": "c", "name": "C", "transport": "stdio", "command": "c" }
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
    fn remove_team_clears_team_servers_only() {
        let mut r = base_registry();
        apply_team_config(
            &mut r,
            "t1",
            &json!({ "servers": [{ "id": "a", "name": "A", "transport": "stdio", "command": "a" }] }),
        );
        remove_team(&mut r, "t1");
        assert!(r.servers.iter().all(|s| s.source.as_deref() != Some("team:t1")));
        assert!(r.servers.iter().any(|s| s.id == "mine"), "local server preserved");
        assert!(!active_enabled(&r).iter().any(|id| id.starts_with("team_")));
    }
}
