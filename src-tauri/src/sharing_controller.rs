//! Shell-neutral setup import and export operations.

use crate::registry::{self, Registry, ServerEntry};

const SHARE_ENDPOINT: &str = "https://toolport.app/api/share";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SetupImportItem {
    pub name: String,
    pub transport: String,
    pub command: Option<String>,
    pub args: Vec<String>,
    pub url: Option<String>,
    pub is_new: bool,
}

pub(crate) fn build_export(
    registry: &Registry,
    name: Option<&str>,
    description: Option<&str>,
    server_ids: Option<&[String]>,
) -> serde_json::Value {
    let include = server_ids.map(|ids| {
        ids.iter()
            .map(String::as_str)
            .collect::<std::collections::HashSet<_>>()
    });
    let servers = registry
        .servers
        .iter()
        .filter(|server| !crate::clients::is_gateway_server(server))
        .filter(|server| {
            include
                .as_ref()
                .is_none_or(|ids| ids.contains(server.id.as_str()))
        })
        .map(|server| {
            let mut server = server.clone();
            server.id.clear();
            for entry in &mut server.env {
                entry.value = None;
            }
            let mask = registry::secret_arg_mask(&server.args);
            for (argument, secret) in server.args.iter_mut().zip(mask) {
                if secret {
                    *argument = "<redacted>".to_string();
                }
            }
            if let Some(url) = server.url.as_deref() {
                server.url = Some(registry::redact_url_userinfo(url));
            }
            server
        })
        .collect::<Vec<ServerEntry>>();
    let mut document =
        serde_json::json!({ "kind": "conduit-setup", "version": 1, "servers": servers });
    if let Some(name) = name.map(str::trim).filter(|value| !value.is_empty()) {
        document["name"] = serde_json::json!(name);
    }
    if let Some(description) = description.map(str::trim).filter(|value| !value.is_empty()) {
        document["description"] = serde_json::json!(description);
    }
    document
}

pub(crate) fn apply_import(registry: &mut Registry, json: &str) -> Result<usize, String> {
    apply_import_selected(registry, json, None)
}

/// Like [`apply_import`], importing only the servers whose names are in
/// `selected` (case-insensitive). `None` keeps every new server.
pub(crate) fn apply_import_selected(
    registry: &mut Registry,
    json: &str,
    selected: Option<&[String]>,
) -> Result<usize, String> {
    #[derive(serde::Deserialize)]
    struct Document {
        servers: Vec<ServerEntry>,
    }
    let document: Document = serde_json::from_str(json)
        .map_err(|error| format!("That doesn't look like a Toolport setup: {error}"))?;
    let mut to_add = Vec::<ServerEntry>::new();
    for mut server in document.servers {
        if let Some(selected) = selected {
            if !selected
                .iter()
                .any(|name| name.eq_ignore_ascii_case(&server.name))
            {
                continue;
            }
        }
        if registry
            .servers
            .iter()
            .chain(to_add.iter())
            .any(|entry| entry.name.eq_ignore_ascii_case(&server.name))
        {
            continue;
        }
        if let Some(milliseconds) = server.request_timeout_ms {
            registry::validate_request_timeout_ms(milliseconds).map_err(|error| {
                format!("Invalid request timeout for '{}': {error}", server.name)
            })?;
        }
        server.id.clear();
        for entry in &mut server.env {
            entry.value = None;
        }
        server.source = Some("shared".to_string());
        to_add.push(server);
    }
    let added = to_add.len();
    for server in to_add {
        registry.add_server(server);
    }
    Ok(added)
}

/// Import only the named servers from a setup document.
pub fn import_json_selected(json: &str, selected: &[String]) -> Result<(Registry, usize), String> {
    registry::update(|registry| apply_import_selected(registry, json, Some(selected)))
}

/// The safety facts a human must see before importing one server: whether it
/// runs a local command, and whether it dials a private or internal address.
pub fn import_item_warnings(item: &SetupImportItem) -> Vec<&'static str> {
    let mut warnings = Vec::new();
    if item.command.as_deref().is_some_and(|c| !c.is_empty()) {
        warnings.push("Runs a shell command on your machine");
    }
    if let Some(url) = item.url.as_deref() {
        if url_is_private_or_internal(url) {
            warnings.push("Connects to a private or internal address");
        }
    }
    warnings
}

fn url_is_private_or_internal(url: &str) -> bool {
    let Ok(parsed) = url::Url::parse(url) else {
        return false;
    };
    let Some(host) = parsed.host_str() else {
        return false;
    };
    let host = host.trim_matches(['[', ']']);
    if host.eq_ignore_ascii_case("localhost")
        || host.to_lowercase().ends_with(".local")
        || host.to_lowercase().ends_with(".internal")
        || host.to_lowercase().ends_with(".lan")
    {
        return true;
    }
    host.parse::<std::net::IpAddr>()
        .map(|ip| crate::oauth::ip_is_private(&ip))
        .unwrap_or(false)
}

pub fn export_json(
    name: Option<&str>,
    description: Option<&str>,
    server_ids: Option<&[String]>,
) -> Result<String, String> {
    let registry = registry::load()?;
    serde_json::to_string_pretty(&build_export(&registry, name, description, server_ids))
        .map_err(|error| error.to_string())
}

pub fn preview_import(json: &str) -> Result<Vec<SetupImportItem>, String> {
    #[derive(serde::Deserialize)]
    struct Document {
        servers: Vec<ServerEntry>,
    }
    let document: Document = serde_json::from_str(json)
        .map_err(|error| format!("That doesn't look like a Toolport setup: {error}"))?;
    let registry = registry::load()?;
    Ok(document
        .servers
        .into_iter()
        .map(|server| SetupImportItem {
            is_new: !registry
                .servers
                .iter()
                .any(|entry| entry.name.eq_ignore_ascii_case(&server.name)),
            name: server.name,
            transport: server.transport,
            command: server.command,
            args: server.args,
            url: server.url,
        })
        .collect())
}

pub fn import_json(json: &str) -> Result<(Registry, usize), String> {
    registry::update(|registry| apply_import(registry, json))
}

pub fn read_setup_file(path: &std::path::Path) -> Result<String, String> {
    const MAX_SETUP_BYTES: u64 = 4 * 1024 * 1024;
    if std::fs::metadata(path).is_ok_and(|metadata| metadata.len() > MAX_SETUP_BYTES) {
        return Err("That file is too large to be a Toolport setup.".to_string());
    }
    std::fs::read_to_string(path).map_err(|error| format!("Couldn't read the file: {error}"))
}

pub fn write_setup_file(path: &std::path::Path, json: &str) -> Result<(), String> {
    std::fs::write(path, json).map_err(|error| format!("Couldn't write the file: {error}"))
}

pub fn parse_share_url(url: &str) -> Option<String> {
    let after = url
        .strip_prefix("toolport://")
        .or_else(|| url.strip_prefix("conduit://"))?;
    let after = after.strip_prefix("import")?;
    let query = after.trim_start_matches('/').strip_prefix('?')?;
    query.split('&').find_map(|pair| {
        let value = pair.strip_prefix("s=")?;
        let id = value.chars().take(64).collect::<String>();
        (!id.is_empty()
            && id
                .chars()
                .all(|character| character.is_ascii_alphanumeric()))
        .then_some(id)
    })
}

pub fn fetch_shared_setup(id: &str) -> Result<String, String> {
    if id.is_empty()
        || id.len() > 32
        || !id
            .chars()
            .all(|character| character.is_ascii_alphanumeric())
    {
        return Err("invalid share id".to_string());
    }
    let url = format!("{SHARE_ENDPOINT}?id={id}");
    use std::io::Read as _;
    let response = ureq::get(&url)
        .timeout(std::time::Duration::from_secs(20))
        .call()
        .map_err(|error| format!("couldn't reach the share service: {error}"))?;
    let mut body = Vec::new();
    response
        .into_reader()
        .take(128 * 1024)
        .read_to_end(&mut body)
        .map_err(|error| error.to_string())?;
    String::from_utf8(body).map_err(|error| error.to_string())
}

pub fn share_setup(setup_json: &str) -> Result<String, String> {
    use std::io::Read as _;
    let response = ureq::post(SHARE_ENDPOINT)
        .timeout(std::time::Duration::from_secs(20))
        .set("content-type", "application/json")
        .send_string(setup_json)
        .map_err(|error| format!("couldn't reach the share service: {error}"))?;
    let mut body = Vec::new();
    response
        .into_reader()
        .take(64 * 1024)
        .read_to_end(&mut body)
        .map_err(|error| error.to_string())?;
    let value: serde_json::Value =
        serde_json::from_slice(&body).map_err(|error| error.to_string())?;
    value
        .get("url")
        .and_then(serde_json::Value::as_str)
        .map(str::to_string)
        .ok_or_else(|| "the share service did not return a link".to_string())
}

#[cfg(test)]
mod controller_tests {
    use super::*;

    fn item(command: Option<&str>, url: Option<&str>) -> SetupImportItem {
        SetupImportItem {
            is_new: true,
            name: "server".to_string(),
            transport: "stdio".to_string(),
            command: command.map(str::to_string),
            args: Vec::new(),
            url: url.map(str::to_string),
        }
    }

    #[test]
    fn import_warnings_flag_shell_commands_and_private_addresses() {
        assert_eq!(
            import_item_warnings(&item(Some("npx"), None)),
            vec!["Runs a shell command on your machine"]
        );
        assert_eq!(
            import_item_warnings(&item(None, Some("http://192.168.1.4:9000/mcp"))),
            vec!["Connects to a private or internal address"]
        );
        assert_eq!(
            import_item_warnings(&item(None, Some("http://vault.internal/mcp"))),
            vec!["Connects to a private or internal address"]
        );
        assert!(import_item_warnings(&item(None, Some("https://mcp.example.com"))).is_empty());
        assert_eq!(
            import_item_warnings(&item(Some("bash"), Some("http://localhost:3000"))).len(),
            2
        );
    }

    #[test]
    fn selected_import_filters_by_name_case_insensitively() {
        let mut registry = Registry::default();
        let json = r#"{"servers":[
            {"name":"GitHub","transport":"http","url":"https://example.com/mcp"},
            {"name":"Jira","transport":"http","url":"https://example.com/jira"}
        ]}"#;
        let added =
            apply_import_selected(&mut registry, json, Some(&["github".to_string()])).unwrap();
        assert_eq!(added, 1);
        assert_eq!(registry.servers.len(), 1);
        assert_eq!(registry.servers[0].name, "GitHub");
        assert_eq!(registry.servers[0].source.as_deref(), Some("shared"));
    }

    #[test]
    fn shared_import_enforces_remote_request_timeout_bounds_atomically() {
        let mut registry = Registry::default();
        let invalid = serde_json::json!({ "servers": [
            {
                "name": "Valid",
                "transport": "http",
                "url": "https://example.com/mcp",
                "requestTimeoutMs": 90_000
            },
            {
                "name": "Invalid",
                "transport": "http",
                "url": "https://example.com/slow",
                "requestTimeoutMs": registry::MAX_REQUEST_TIMEOUT_MS + 1
            }
        ]});

        let error = apply_import(&mut registry, &invalid.to_string()).unwrap_err();
        assert!(error.contains("Invalid request timeout for 'Invalid'"));
        assert!(
            registry.servers.is_empty(),
            "a rejected document must not be partially imported"
        );

        let valid = serde_json::json!({ "servers": [{
            "name": "Maximum",
            "transport": "http",
            "url": "https://example.com/mcp",
            "requestTimeoutMs": registry::MAX_REQUEST_TIMEOUT_MS
        }]});
        assert_eq!(apply_import(&mut registry, &valid.to_string()).unwrap(), 1);
        assert_eq!(
            registry.servers[0].request_timeout_ms,
            Some(registry::MAX_REQUEST_TIMEOUT_MS)
        );
    }

    #[test]
    fn shared_import_and_export_round_trip_timeouts_for_local_commands() {
        let mut registry = Registry::default();
        let json = serde_json::json!({ "servers": [
            {
                "name": "Local",
                "transport": "stdio",
                "command": "local-server",
                "requestTimeoutMs": 90_000
            },
            {
                "name": "Local wrapper",
                "transport": "http",
                "command": "local-server",
                "requestTimeoutMs": 120_000
            }
        ]});

        assert_eq!(apply_import(&mut registry, &json.to_string()).unwrap(), 2);
        assert_eq!(
            registry.servers[0].request_timeout_ms,
            Some(90_000)
        );
        assert_eq!(
            registry.servers[1].request_timeout_ms,
            Some(120_000)
        );
        let exported = build_export(&registry, None, None, None);
        let servers = exported["servers"].as_array().unwrap();
        assert_eq!(servers[0]["requestTimeoutMs"], 90_000);
        assert_eq!(servers[1]["requestTimeoutMs"], 120_000);
    }
}
