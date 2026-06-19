//! MCP server catalog.
//!
//! Two layers, so users can add servers without hand-typing commands/URLs:
//!   1. A small hand-verified "popular" seed, bundled and offline.
//!   2. Live search against the official MCP Registry for the long tail.
//!
//! Both produce the same [`CatalogEntry`] shape, which the UI turns into a
//! registry server with one click - the existing auth flow then handles creds.

use serde::{Deserialize, Serialize};
use serde_json::Value;

const REGISTRY_URL: &str = "https://registry.modelcontextprotocol.io/v0/servers";

/// One addable server: enough to create a registry entry, plus display metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CatalogEntry {
    pub name: String,
    pub description: String,
    /// "stdio" | "http" | "sse"
    pub transport: String,
    pub command: Option<String>,
    pub args: Vec<String>,
    pub url: Option<String>,
    /// Env-var names the server needs (treated as secrets when added).
    pub env_keys: Vec<String>,
    /// "curated" | "registry"
    pub source: String,
    pub homepage: Option<String>,
}

/// The hand-verified popular set. Hosted (URL) servers are favored here because
/// their endpoints are far more stable than package names. The live registry
/// covers the long tail; this set is what most people reach for first.
pub fn curated() -> Vec<CatalogEntry> {
    // Remote servers, keyed by transport. Most hosted MCPs are streamable-http;
    // a few still use SSE endpoints.
    let http = |name: &str, desc: &str, url: &str, home: &str| CatalogEntry {
        name: name.to_string(),
        description: desc.to_string(),
        transport: "http".to_string(),
        command: None,
        args: vec![],
        url: Some(url.to_string()),
        env_keys: vec![],
        source: "curated".to_string(),
        homepage: Some(home.to_string()),
    };
    let sse = |name: &str, desc: &str, url: &str, home: &str| CatalogEntry {
        transport: "sse".to_string(),
        ..http(name, desc, url, home)
    };
    // Local (stdio) servers: `command` + args, with any required secret env keys.
    let cmd =
        |name: &str, desc: &str, command: &str, args: &[&str], env: &[&str], home: &str| {
            CatalogEntry {
                name: name.to_string(),
                description: desc.to_string(),
                transport: "stdio".to_string(),
                command: Some(command.to_string()),
                args: args.iter().map(|s| s.to_string()).collect(),
                url: None,
                env_keys: env.iter().map(|s| s.to_string()).collect(),
                source: "curated".to_string(),
                homepage: Some(home.to_string()),
            }
        };

    vec![
        // --- Payments & commerce ---
        http("Stripe", "Payments, customers, charges, and balances.", "https://mcp.stripe.com", "https://docs.stripe.com/mcp"),
        // --- Code, deploy & infra ---
        http("GitHub", "Repos, issues, PRs, and code search.", "https://api.githubcopilot.com/mcp/", "https://github.com/github/github-mcp-server"),
        http("Vercel", "Projects, deployments, and logs on Vercel.", "https://mcp.vercel.com", "https://vercel.com/docs/mcp/vercel-mcp"),
        http("Sentry", "Errors, issues, and releases from Sentry.", "https://mcp.sentry.dev/mcp", "https://docs.sentry.io"),
        http("Cloudflare Docs", "Search Cloudflare's documentation.", "https://docs.mcp.cloudflare.com/mcp", "https://developers.cloudflare.com/agents/model-context-protocol/"),
        cmd("AWS", "AWS APIs, docs, and best practices via AWS Labs MCP.", "uvx", &["awslabs.core-mcp-server@latest"], &["AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY"], "https://github.com/awslabs/mcp"),
        // --- Databases ---
        http("Supabase", "Query and manage your Supabase projects.", "https://mcp.supabase.com/mcp", "https://supabase.com/docs/guides/getting-started/mcp"),
        sse("Neon", "Serverless Postgres: branches, queries, projects.", "https://mcp.neon.tech/sse", "https://neon.tech/docs/ai/neon-mcp-server"),
        cmd("PostgreSQL", "Query a Postgres database (add your connection string to args).", "npx", &["-y", "@modelcontextprotocol/server-postgres"], &[], "https://github.com/modelcontextprotocol/servers"),
        // --- Project management & docs ---
        http("Notion", "Search and edit Notion pages and databases.", "https://mcp.notion.com/mcp", "https://developers.notion.com"),
        sse("Linear", "Issues, projects, and cycles in Linear.", "https://mcp.linear.app/sse", "https://linear.app/docs"),
        sse("Atlassian", "Jira issues and Confluence pages.", "https://mcp.atlassian.com/v1/sse", "https://support.atlassian.com/atlassian-rovo-mcp-server/"),
        sse("Asana", "Tasks, projects, and portfolios in Asana.", "https://mcp.asana.com/sse", "https://developers.asana.com/docs/mcp-server"),
        // --- Communication ---
        cmd("Slack", "Read and send Slack messages and manage channels.", "npx", &["-y", "@modelcontextprotocol/server-slack"], &["SLACK_BOT_TOKEN", "SLACK_TEAM_ID"], "https://github.com/modelcontextprotocol/servers"),
        // --- Knowledge & search ---
        http("Context7", "Up-to-date docs and code examples for libraries.", "https://mcp.context7.com/mcp", "https://github.com/upstash/context7"),
        http("DeepWiki", "Ask questions about any public GitHub repo. No auth.", "https://mcp.deepwiki.com/mcp", "https://deepwiki.com"),
        http("Hugging Face", "Models, datasets, and Spaces on Hugging Face.", "https://huggingface.co/mcp", "https://huggingface.co/settings/mcp"),
        cmd("Brave Search", "Web search via the Brave Search API.", "npx", &["-y", "@modelcontextprotocol/server-brave-search"], &["BRAVE_API_KEY"], "https://github.com/modelcontextprotocol/servers"),
        // --- Email & comms already above; Design ---
        cmd("Figma", "Turn Figma designs into code (Framelink).", "npx", &["-y", "figma-developer-mcp", "--stdio"], &["FIGMA_API_KEY"], "https://github.com/GLips/Figma-Context-MCP"),
        // --- Email ---
        cmd("Resend", "Send transactional email through Resend.", "npx", &["-y", "resend-mcp"], &["RESEND_API_KEY"], "https://resend.com/docs"),
        // --- Local utilities (no account needed) ---
        cmd("Filesystem", "Read and write files in directories you allow.", "npx", &["-y", "@modelcontextprotocol/server-filesystem"], &[], "https://github.com/modelcontextprotocol/servers"),
        cmd("Fetch", "Fetch a URL and return its content as markdown.", "uvx", &["mcp-server-fetch"], &[], "https://github.com/modelcontextprotocol/servers"),
        cmd("Git", "Read, search, and manipulate a local Git repo.", "uvx", &["mcp-server-git"], &[], "https://github.com/modelcontextprotocol/servers"),
        cmd("Playwright", "Drive a real browser for testing and scraping.", "npx", &["-y", "@playwright/mcp@latest"], &[], "https://github.com/microsoft/playwright-mcp"),
    ]
}

fn user_catalog_path() -> Option<std::path::PathBuf> {
    Some(dirs::config_dir()?.join("Conduit").join("user-catalog.json"))
}

/// Servers the user has promoted into their own catalog (their real-world picks).
/// Always tagged source "user" so the UI can badge and un-promote them.
pub fn promoted() -> Vec<CatalogEntry> {
    let mut list: Vec<CatalogEntry> = user_catalog_path()
        .and_then(|p| std::fs::read_to_string(p).ok())
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default();
    for e in &mut list {
        e.source = "user".to_string();
    }
    list
}

fn save_promoted(list: &[CatalogEntry]) -> Result<(), String> {
    let path = user_catalog_path().ok_or("no config dir")?;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    }
    let json = serde_json::to_string_pretty(list).map_err(|e| e.to_string())?;
    std::fs::write(path, json).map_err(|e| e.to_string())
}

/// Add an entry to the user's catalog (no-op if a same-named one exists).
pub fn promote(entry: CatalogEntry) -> Result<(), String> {
    let mut list = promoted();
    if !list.iter().any(|e| e.name.eq_ignore_ascii_case(&entry.name)) {
        list.push(entry);
        save_promoted(&list)?;
    }
    Ok(())
}

/// Remove an entry from the user's catalog by name.
pub fn unpromote(name: &str) -> Result<(), String> {
    let mut list = promoted();
    list.retain(|e| !e.name.eq_ignore_ascii_case(name));
    save_promoted(&list)
}

/// The popular set shown by default: the user's promoted picks first, then the
/// curated set, de-duplicated by name (user wins).
pub fn popular() -> Vec<CatalogEntry> {
    let mut out = promoted();
    let mut seen: std::collections::HashSet<String> =
        out.iter().map(|e| e.name.to_lowercase()).collect();
    for e in curated() {
        if seen.insert(e.name.to_lowercase()) {
            out.push(e);
        }
    }
    out
}

/// Filter a catalog list by a query (name or description). Substring match, plus
/// an all-terms fallback so multi-word queries still hit. Empty query = all.
fn filter_catalog(list: Vec<CatalogEntry>, query: &str) -> Vec<CatalogEntry> {
    let q = query.trim().to_lowercase();
    if q.is_empty() {
        return list;
    }
    let terms: Vec<&str> = q.split_whitespace().collect();
    list.into_iter()
        .filter(|e| {
            let hay = format!("{} {}", e.name.to_lowercase(), e.description.to_lowercase());
            hay.contains(&q) || terms.iter().all(|t| hay.contains(t))
        })
        .collect()
}

/// Popular entries (user + curated) matching a query.
fn popular_matching(query: &str) -> Vec<CatalogEntry> {
    filter_catalog(popular(), query)
}

/// Search the catalog: the user's picks + curated matches first (highest
/// quality), then live MCP Registry results for the long tail, de-duplicated by
/// name. This is why popular picks like Vercel always surface even when the
/// registry's own search doesn't return them.
pub fn search(query: &str) -> Vec<CatalogEntry> {
    let mut out = popular_matching(query);
    let mut seen: std::collections::HashSet<String> =
        out.iter().map(|e| e.name.to_lowercase()).collect();
    if !query.trim().is_empty() {
        if let Ok(registry) = search_registry(query) {
            for e in registry {
                if seen.insert(e.name.to_lowercase()) {
                    out.push(e);
                }
            }
        }
    }
    out
}

/// Turn one registry `server` object into a catalog entry. Prefers a hosted
/// remote (simplest to connect), else the first installable package.
fn map_server(server: &Value) -> Option<CatalogEntry> {
    let id = server.get("name").and_then(|v| v.as_str()).unwrap_or("");
    // Friendly title when present; fall back to the namespaced id.
    let name = server
        .get("title")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .unwrap_or(id)
        .to_string();
    if name.is_empty() {
        return None;
    }
    let description = server
        .get("description")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let homepage = server
        .get("repository")
        .and_then(|r| r.get("url"))
        .and_then(|v| v.as_str())
        .map(String::from);

    if let Some(remote) = server
        .get("remotes")
        .and_then(|v| v.as_array())
        .and_then(|a| a.first())
    {
        if let Some(url) = remote.get("url").and_then(|v| v.as_str()) {
            let ty = remote.get("type").and_then(|v| v.as_str()).unwrap_or("");
            let transport = if ty.contains("sse") { "sse" } else { "http" };
            return Some(CatalogEntry {
                name,
                description,
                transport: transport.to_string(),
                command: None,
                args: vec![],
                url: Some(url.to_string()),
                env_keys: vec![],
                source: "registry".to_string(),
                homepage,
            });
        }
    }

    if let Some(pkg) = server
        .get("packages")
        .and_then(|v| v.as_array())
        .and_then(|a| a.first())
    {
        let registry_type = pkg
            .get("registryType")
            .or_else(|| pkg.get("registry_type"))
            .and_then(|v| v.as_str())
            .unwrap_or("npm");
        let identifier = pkg.get("identifier").and_then(|v| v.as_str()).unwrap_or("");
        if identifier.is_empty() {
            return None;
        }
        let version = pkg.get("version").and_then(|v| v.as_str());
        let spec = match version {
            Some(v) if !v.is_empty() && v != "latest" => format!("{identifier}@{v}"),
            _ => identifier.to_string(),
        };
        let (command, args) = match registry_type {
            "pypi" => ("uvx".to_string(), vec![spec]),
            "oci" | "docker" => ("docker".to_string(), vec!["run".to_string(), "-i".to_string(), "--rm".to_string(), spec]),
            _ => ("npx".to_string(), vec!["-y".to_string(), spec]),
        };
        let env_keys = pkg
            .get("environmentVariables")
            .or_else(|| pkg.get("environment_variables"))
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|e| e.get("name").and_then(|n| n.as_str()).map(String::from))
                    .collect()
            })
            .unwrap_or_default();
        return Some(CatalogEntry {
            name,
            description,
            transport: "stdio".to_string(),
            command: Some(command),
            args,
            url: None,
            env_keys,
            source: "registry".to_string(),
            homepage,
        });
    }

    None
}

/// True if a registry list item is the latest published version of its server
/// (the API returns one item per version, so we dedupe on this).
fn is_latest(item: &Value) -> bool {
    item.get("_meta")
        .and_then(|m| m.get("io.modelcontextprotocol.registry/official"))
        .and_then(|o| o.get("isLatest"))
        .and_then(|v| v.as_bool())
        .unwrap_or(true)
}

/// Search the official MCP Registry. Empty query lists popular/recent servers.
pub fn search_registry(query: &str) -> Result<Vec<CatalogEntry>, String> {
    let q = query.trim();
    let url = if q.is_empty() {
        format!("{REGISTRY_URL}?limit=50")
    } else {
        format!("{REGISTRY_URL}?limit=50&search={}", urlencoding::encode(q))
    };
    let body: Value = ureq::get(&url)
        .timeout(std::time::Duration::from_secs(20))
        .call()
        .map_err(|e| e.to_string())?
        .into_json()
        .map_err(|e| e.to_string())?;

    let items = body
        .get("servers")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();

    Ok(items
        .iter()
        .filter(|item| is_latest(item))
        .filter_map(|item| map_server(item.get("server").unwrap_or(item)))
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn curated_is_nonempty_and_well_formed() {
        let c = curated();
        assert!(c.len() >= 20);
        for e in &c {
            assert!(!e.name.is_empty());
            // Each entry is either a remote (url) or a command, never neither.
            assert!(e.url.is_some() || e.command.is_some(), "{} has no target", e.name);
        }
    }

    #[test]
    fn curated_search_finds_popular_picks() {
        // The reported bug: searching a curated vendor must still surface it,
        // even though the live registry wouldn't return it.
        let vercel = filter_catalog(curated(), "vercel");
        assert_eq!(vercel.len(), 1);
        assert_eq!(vercel[0].name, "Vercel");
        // Description matches too (Postgres -> Neon/Supabase).
        assert!(filter_catalog(curated(), "postgres").iter().any(|e| e.name == "Neon"));
        // Empty query returns the full set.
        assert_eq!(filter_catalog(curated(), "").len(), curated().len());
    }

    #[test]
    fn maps_a_remote_server() {
        // Shape taken from a real registry.modelcontextprotocol.io response.
        let server = json!({
            "name": "ac.inference.sh/mcp",
            "title": "inference.sh",
            "description": "Run 150+ AI apps.",
            "remotes": [{ "type": "streamable-http", "url": "https://api.inference.sh/mcp" }]
        });
        let e = map_server(&server).unwrap();
        assert_eq!(e.name, "inference.sh");
        assert_eq!(e.transport, "http");
        assert_eq!(e.url.as_deref(), Some("https://api.inference.sh/mcp"));
        assert_eq!(e.source, "registry");
    }

    #[test]
    fn maps_an_npm_package_with_env() {
        let server = json!({
            "name": "io.github.acme/widget",
            "description": "A widget server.",
            "packages": [{
                "registryType": "npm",
                "identifier": "@acme/widget-mcp",
                "version": "1.2.3",
                "environmentVariables": [{ "name": "ACME_API_KEY" }]
            }]
        });
        let e = map_server(&server).unwrap();
        // No title -> falls back to the namespaced id.
        assert_eq!(e.name, "io.github.acme/widget");
        assert_eq!(e.transport, "stdio");
        assert_eq!(e.command.as_deref(), Some("npx"));
        assert_eq!(e.args, vec!["-y", "@acme/widget-mcp@1.2.3"]);
        assert_eq!(e.env_keys, vec!["ACME_API_KEY"]);
    }

    #[test]
    fn skips_isnt_latest() {
        let old = json!({ "_meta": { "io.modelcontextprotocol.registry/official": { "isLatest": false } } });
        let cur = json!({ "_meta": { "io.modelcontextprotocol.registry/official": { "isLatest": true } } });
        assert!(!is_latest(&old));
        assert!(is_latest(&cur));
    }
}
