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
    /// Publishing namespace from the official registry id, e.g. `io.github.acme`
    /// for `io.github.acme/widget`. A provenance signal (who published it), not a
    /// cryptographic guarantee. `None` for curated/user entries.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub publisher: Option<String>,
    /// Curated grouping for the browse view (e.g. "Databases"). Empty for registry
    /// and user entries, which surface flat in search results.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub category: String,
    /// Direct link to where the user creates this server's credential (e.g. the
    /// provider's API-token page). Powers the guided "go get your creds" step in
    /// Stacks (and the normal add flow). Curated entries only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub credentials_url: Option<String>,
    /// One-line hint on what credential to create (scopes, what to paste).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub setup_hint: Option<String>,
    /// Placeholder text for the URL field when the server is self-hosted or
    /// needs a user-specific endpoint. When present, the catalog UI opens
    /// ServerDialog instead of immediate-add so the user can enter their URL.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub url_hint: Option<String>,
}

/// Browse-view grouping for a curated server, keyed by name. Keeps the verified
/// entry list itself untouched; the UI orders the sections, not the arm order here.
fn category_for(name: &str) -> &'static str {
    match name {
        "GitHub" | "Vercel" | "Sentry" | "Cloudflare Docs" | "AWS" | "Kubernetes" | "Linode"
        | "Railway" => "Code & infrastructure",
        "Supabase" | "Neon" | "PostgreSQL" | "MongoDB" | "Elasticsearch" | "Qdrant" => "Databases",
        "Context7" | "DeepWiki" | "Hugging Face" | "OpenRouter" | "Brave Search" | "Exa"
        | "Tavily" | "Perplexity" | "DataForSEO" => "Search & knowledge",
        "Firecrawl" | "Apify" | "Browserbase" => "Web & automation",
        "Stripe" | "Notion" | "Composio" | "Linear" | "Atlassian" | "Asana" | "Airtable"
        | "Todoist" | "Slack" | "Resend" | "Figma" | "Postiz" | "Twilio" | "n8n"
        | "Langfuse" => "Apps & productivity",
        "Filesystem" | "Fetch" | "Git" | "Playwright" | "Sequential Thinking" | "Memory"
        | "Time" | "Chrome DevTools" => "Local tools",
        _ => "",
    }
}

/// Where to create the credential for a curated server, and a one-line hint, for
/// the guided "go get your creds" step in Stacks. Returns `(url, hint)`; an empty
/// `url` means there's no single page (a connection string you supply, OAuth, or
/// no auth) so only the hint shows. `None` = unknown / no guidance.
fn credentials_for(name: &str) -> Option<(&'static str, &'static str)> {
    Some(match name {
        // Token-based: the agent gets an API key Toolport vaults.
        "Linode" => (
            "https://cloud.linode.com/profile/tokens",
            "Create a Personal Access Token with read/write on the resources you need (Linodes, Volumes, Databases).",
        ),
        "AWS" => (
            "https://console.aws.amazon.com/iam/home#/security_credentials",
            "Create an access key (ID + secret) for an IAM user scoped to what the agent should touch.",
        ),
        "MongoDB" => (
            "https://cloud.mongodb.com",
            "Paste your MongoDB connection string (Atlas: Database > Connect > Drivers).",
        ),
        "Exa" => ("https://dashboard.exa.ai/api-keys", "Create an API key."),
        "Perplexity" => (
            "https://www.perplexity.ai/settings/api",
            "Create an API key (needs a small credit balance).",
        ),
        "DataForSEO" => (
            "https://app.dataforseo.com/api-access",
            "Copy your API login and password from the API Access dashboard.",
        ),
        "OpenRouter" => ("https://openrouter.ai/keys", "Create an API key."),
        "Qdrant" => (
            "https://cloud.qdrant.io",
            "Create a free cluster, then copy its URL and an API key (Cluster > API Keys).",
        ),
        "Hugging Face" => (
            "https://huggingface.co/settings/tokens",
            "Authenticate when prompted, or paste a read token.",
        ),
        "Resend" => ("https://resend.com/api-keys", "Create an API key with send access."),
        "Figma" => (
            "https://www.figma.com/settings",
            "Create a personal access token (Settings > Security > Personal access tokens).",
        ),
        "Slack" => (
            "https://api.slack.com/apps",
            "Create a Slack app, add a bot token (xoxb-...), and grab your team id.",
        ),
        "Twilio" => (
            "https://console.twilio.com",
            "Create an API key (API Key SID + Secret) in the Twilio Console.",
        ),
        "Postiz" => (
            "https://postiz.pro/settings/developers",
            "Create an API key in Settings > Developers > Public API.",
        ),
        // Config you supply (no single token page).
        "PostgreSQL" => (
            "",
            "Add your Postgres connection string (postgres://user:pass@host/db) to the server's arguments.",
        ),
        "Kubernetes" => ("", "Uses your local kubeconfig (~/.kube/config); nothing to paste."),
        "Filesystem" => (
            "",
            "No credential. After adding, point it at the directories the agent may access.",
        ),
        // OAuth: authorize in the browser, no manual token.
        "GitHub" | "Vercel" | "Sentry" | "Notion" | "Linear" | "Stripe" => (
            "",
            "OAuth: click Authenticate when prompted; no manual token needed.",
        ),
        // No auth at all.
        "Fetch" | "Context7" => ("", "No credential needed."),
        _ => return None,
    })
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
        publisher: None,
        category: String::new(),
        credentials_url: None,
        setup_hint: None,
        url_hint: None,
    };
    // Self-hosted server: the user supplies the URL (shown as placeholder).
    // transport is http because the server speaks MCP over HTTP, but the URL
    // is None — the catalog UI opens ServerDialog so the user enters their
    // instance endpoint before the server is created.
    let self_hosted = |name: &str, desc: &str, url_hint: &str, home: &str| CatalogEntry {
        name: name.to_string(),
        description: desc.to_string(),
        transport: "http".to_string(),
        command: None,
        args: vec![],
        url: None,
        env_keys: vec![],
        source: "curated".to_string(),
        homepage: Some(home.to_string()),
        publisher: None,
        category: String::new(),
        credentials_url: None,
        setup_hint: None,
        url_hint: Some(url_hint.to_string()),
    };
    // Local (stdio) servers: `command` + args, with any required secret env keys.
    let cmd = |name: &str, desc: &str, command: &str, args: &[&str], env: &[&str], home: &str| {
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
            publisher: None,
            category: String::new(),
            credentials_url: None,
            setup_hint: None,
            url_hint: None,
        }
    };

    let mut list = vec![
        // --- Payments & commerce ---
        http("Stripe", "Payments, customers, charges, and balances.", "https://mcp.stripe.com", "https://docs.stripe.com/mcp"),
        // --- Code, deploy & infra ---
        http("GitHub", "Repos, issues, PRs, and code search.", "https://api.githubcopilot.com/mcp/", "https://github.com/github/github-mcp-server"),
        http("Vercel", "Projects, deployments, and logs on Vercel.", "https://mcp.vercel.com", "https://vercel.com/docs/mcp/vercel-mcp"),
        http("Sentry", "Errors, issues, and releases from Sentry.", "https://mcp.sentry.dev/mcp", "https://docs.sentry.io"),
        http("Cloudflare Docs", "Search Cloudflare's documentation.", "https://docs.mcp.cloudflare.com/mcp", "https://developers.cloudflare.com/agents/model-context-protocol/"),
        cmd("AWS", "AWS APIs, docs, and best practices via AWS Labs MCP.", "uvx", &["awslabs.core-mcp-server@latest"], &["AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY"], "https://github.com/awslabs/mcp"),
        cmd("Kubernetes", "Inspect and manage Kubernetes clusters via your kubeconfig.", "npx", &["-y", "mcp-server-kubernetes"], &[], "https://github.com/Flux159/mcp-server-kubernetes"),
        cmd("Linode", "Manage Linode (Akamai) cloud: instances, volumes, NodeBalancers, databases, and networking.", "npx", &["-y", "@takashito/linode-mcp-server"], &["LINODE_API_TOKEN"], "https://github.com/takashito/linode-mcp-server"),
        http("Railway", "Deploy apps, manage environments, and pull variables on Railway.", "https://mcp.railway.com/mcp", "https://railway.com"),
        cmd("Chrome DevTools", "Control and inspect a live Chrome browser: traces, screenshots, network, console.", "npx", &["-y", "chrome-devtools-mcp@latest"], &[], "https://github.com/ChromeDevTools/chrome-devtools-mcp"),
        // --- Databases ---
        http("Supabase", "Query and manage your Supabase projects.", "https://mcp.supabase.com/mcp", "https://supabase.com/docs/guides/getting-started/mcp"),
        http("Neon", "Serverless Postgres: branches, queries, projects.", "https://mcp.neon.tech/mcp", "https://neon.tech/docs/ai/neon-mcp-server"),
        cmd("PostgreSQL", "Query a Postgres database (add your connection string to args).", "npx", &["-y", "@modelcontextprotocol/server-postgres"], &[], "https://github.com/modelcontextprotocol/servers"),
        cmd("MongoDB", "Query and manage MongoDB databases.", "npx", &["-y", "mongodb-mcp-server"], &["MDB_MCP_CONNECTION_STRING"], "https://github.com/mongodb-js/mongodb-mcp-server"),
        cmd("Elasticsearch", "Search and analytics over your Elasticsearch cluster.", "npx", &["-y", "@elastic/mcp-server-elasticsearch"], &["ES_URL", "ES_API_KEY"], "https://github.com/elastic/mcp-server-elasticsearch"),
        cmd("Qdrant", "Vector search and memory for RAG: store and query embeddings in Qdrant.", "uvx", &["mcp-server-qdrant"], &["QDRANT_URL", "QDRANT_API_KEY"], "https://github.com/qdrant/mcp-server-qdrant"),
        // --- Project management & docs ---
        http("Notion", "Search and edit Notion pages and databases.", "https://mcp.notion.com/mcp", "https://developers.notion.com"),
        http("Composio", "Connect AI agents to 1,000+ apps (Gmail, Slack, GitHub, Notion, Linear, and more).", "https://connect.composio.dev/mcp", "https://composio.dev"),
        http("Linear", "Issues, projects, and cycles in Linear.", "https://mcp.linear.app/mcp", "https://linear.app/docs"),
        http("Atlassian", "Jira issues and Confluence pages.", "https://mcp.atlassian.com/v1/mcp", "https://support.atlassian.com/atlassian-rovo-mcp-server/"),
        http("Asana", "Tasks, projects, and portfolios in Asana.", "https://mcp.asana.com/mcp", "https://developers.asana.com/docs/mcp-server"),
        cmd("Airtable", "Read and write records in your Airtable bases.", "npx", &["-y", "airtable-mcp-server"], &["AIRTABLE_API_KEY"], "https://github.com/domdomegg/airtable-mcp-server"),
        cmd("Todoist", "Manage Todoist tasks and projects.", "npx", &["-y", "@abhiz123/todoist-mcp-server"], &["TODOIST_API_TOKEN"], "https://github.com/abhiz123/todoist-mcp-server"),
        // --- Communication ---
        cmd("Slack", "Read and send Slack messages and manage channels.", "npx", &["-y", "@modelcontextprotocol/server-slack"], &["SLACK_BOT_TOKEN", "SLACK_TEAM_ID"], "https://github.com/modelcontextprotocol/servers"),
        cmd("Twilio", "Send SMS, make calls, and manage Twilio messaging and voice.", "npx", &["-y", "@twilio-alpha/mcp"], &["TWILIO_API_KEY", "TWILIO_API_SECRET"], "https://github.com/twilio-labs/mcp"),
        http("Postiz", "Schedule and publish social media posts across platforms.", "https://api.postiz.com/mcp", "https://postiz.pro"),
        // --- Knowledge & search ---
        http("Context7", "Up-to-date docs and code examples for libraries.", "https://mcp.context7.com/mcp", "https://github.com/upstash/context7"),
        http("DeepWiki", "Ask questions about any public GitHub repo. No auth.", "https://mcp.deepwiki.com/mcp", "https://deepwiki.com"),
        http("Hugging Face", "Models, datasets, and Spaces on Hugging Face.", "https://huggingface.co/mcp", "https://huggingface.co/settings/mcp"),
        http("OpenRouter", "Live model intelligence: list and compare models, prices, and your credits.", "https://mcp.openrouter.ai/mcp", "https://openrouter.ai/docs/mcp-server"),
        cmd("Brave Search", "Web search via the Brave Search API.", "npx", &["-y", "@modelcontextprotocol/server-brave-search"], &["BRAVE_API_KEY"], "https://github.com/modelcontextprotocol/servers"),
        cmd("Exa", "AI-native web search built for agents.", "npx", &["-y", "exa-mcp-server"], &["EXA_API_KEY"], "https://github.com/exa-labs/exa-mcp-server"),
        cmd("Tavily", "Web search and content extraction built for LLMs.", "npx", &["-y", "tavily-mcp"], &["TAVILY_API_KEY"], "https://github.com/tavily-ai/tavily-mcp"),
        cmd("Perplexity", "Ask Perplexity for cited, up-to-date answers.", "npx", &["-y", "server-perplexity-ask"], &["PERPLEXITY_API_KEY"], "https://github.com/ppl-ai/modelcontextprotocol"),
        cmd("DataForSEO", "SEO data: SERP tracking, keyword research, and competitor analysis.", "npx", &["-y", "dataforseo-mcp-server"], &["DATAFORSEO_USERNAME", "DATAFORSEO_PASSWORD"], "https://dataforseo.com"),
        cmd("Firecrawl", "Web scraping and data extraction from websites.", "npx", &["-y", "firecrawl-mcp"], &["FIRECRAWL_API_KEY"], "https://github.com/firecrawl/firecrawl-mcp-server"),
        cmd("Apify", "Run Apify actors for web scraping and automation.", "npx", &["-y", "@apify/actors-mcp-server"], &["APIFY_TOKEN"], "https://github.com/apify/actors-mcp-server"),
        cmd("Browserbase", "Cloud headless browsers agents can drive.", "npx", &["-y", "@browserbasehq/mcp-server-browserbase"], &["BROWSERBASE_API_KEY", "BROWSERBASE_PROJECT_ID"], "https://github.com/browserbase/mcp-server-browserbase"),
        // --- Email & comms already above; Design ---
        cmd("Figma", "Turn Figma designs into code (Framelink).", "npx", &["-y", "figma-developer-mcp", "--stdio"], &["FIGMA_API_KEY"], "https://github.com/GLips/Figma-Context-MCP"),
        // --- Email ---
        cmd("Resend", "Send transactional email through Resend.", "npx", &["-y", "resend-mcp"], &["RESEND_API_KEY"], "https://resend.com/docs"),
        // --- Self-hosted (user supplies URL) ---
        self_hosted("n8n", "Trigger, manage, and edit n8n workflows via MCP.", "https://your-instance.com/mcp-server/http", "https://n8n.io"),
        self_hosted("Langfuse", "Prompt management and observability for LLM apps.", "https://your-langfuse.com/mcp", "https://langfuse.com"),
        // --- Local utilities (no account needed) ---
        cmd("Filesystem", "Read and write files in directories you allow.", "npx", &["-y", "@modelcontextprotocol/server-filesystem"], &[], "https://github.com/modelcontextprotocol/servers"),
        cmd("Fetch", "Fetch a URL and return its content as markdown.", "uvx", &["mcp-server-fetch"], &[], "https://github.com/modelcontextprotocol/servers"),
        cmd("Git", "Read, search, and manipulate a local Git repo.", "uvx", &["mcp-server-git"], &[], "https://github.com/modelcontextprotocol/servers"),
        cmd("Playwright", "Drive a real browser for testing and scraping.", "npx", &["-y", "@playwright/mcp@latest"], &[], "https://github.com/microsoft/playwright-mcp"),
        cmd("Sequential Thinking", "Structured step-by-step reasoning for hard problems.", "npx", &["-y", "@modelcontextprotocol/server-sequential-thinking"], &[], "https://github.com/modelcontextprotocol/servers"),
        cmd("Memory", "A knowledge graph the agent reads and writes across sessions.", "npx", &["-y", "@modelcontextprotocol/server-memory"], &[], "https://github.com/modelcontextprotocol/servers"),
        cmd("Time", "Current time and timezone conversions.", "uvx", &["mcp-server-time"], &[], "https://github.com/modelcontextprotocol/servers"),
    ];
    for e in &mut list {
        e.category = category_for(&e.name).to_string();
        if let Some((url, hint)) = credentials_for(&e.name) {
            e.credentials_url = (!url.is_empty()).then(|| url.to_string());
            e.setup_hint = Some(hint.to_string());
        }
    }
    list
}

/// The popular set shown by default: the curated catalog.
pub fn popular() -> Vec<CatalogEntry> {
    curated()
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
pub fn search(query: &str) -> Result<Vec<CatalogEntry>, String> {
    let mut out = popular_matching(query);
    let mut seen: std::collections::HashSet<String> =
        out.iter().map(|e| e.name.to_lowercase()).collect();
    if !query.trim().is_empty() {
        // Propagate a registry/network failure instead of swallowing it: otherwise an
        // outage renders as an innocent "no results" in the UI with no retry. An empty
        // registry response is `Ok(empty)`, so only a real failure surfaces as an error.
        for e in search_registry(query)? {
            if seen.insert(e.name.to_lowercase()) {
                out.push(e);
            }
        }
    }
    Ok(out)
}

/// Turn one registry `server` object into a catalog entry. Prefers a hosted
/// remote (simplest to connect), else the first installable package.
/// A registry package spec safe to pass as an npx/uvx/docker argument: non-empty, no
/// leading dash (flag injection), bounded length, and only the characters real
/// package names use. Nothing that could become a separate flag or a shell token.
fn is_safe_package_id(spec: &str) -> bool {
    !spec.is_empty()
        && !spec.starts_with('-')
        && spec.len() <= 200
        && spec.chars().all(|c| {
            c.is_ascii_alphanumeric() || matches!(c, '@' | '/' | '-' | '_' | '.' | '+' | ':')
        })
}

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
    // Registry ids are namespaced (`io.github.acme/widget`); the namespace tells
    // you who published it - a provenance signal we surface in the catalog.
    let publisher = id.split_once('/').map(|(ns, _)| ns.to_string());

    if let Some(remote) = server
        .get("remotes")
        .and_then(|v| v.as_array())
        .and_then(|a| a.first())
    {
        if let Some(url) = remote.get("url").and_then(|v| v.as_str()) {
            // SECURITY: only real HTTP(S) endpoints from a registry entry; a
            // javascript:/file:/data: URL has no business here.
            if !(url.starts_with("https://") || url.starts_with("http://")) {
                return None;
            }
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
                publisher,
                category: String::new(),
                credentials_url: None,
                setup_hint: None,
                url_hint: None,
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
        // SECURITY: this spec becomes an argument to npx/uvx/docker for a one-click
        // install. Reject anything that isn't a plain package spec (a leading '-'
        // reads as a flag; shell metacharacters have no business in a package name).
        // Args are passed without a shell, but this is cheap defense in depth against
        // a malicious or MITM'd registry entry.
        if !is_safe_package_id(&spec) {
            return None;
        }
        let (command, args) = match registry_type {
            "pypi" => ("uvx".to_string(), vec![spec]),
            "oci" | "docker" => (
                "docker".to_string(),
                vec![
                    "run".to_string(),
                    "-i".to_string(),
                    "--rm".to_string(),
                    spec,
                ],
            ),
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
            publisher,
            category: String::new(),
            credentials_url: None,
            setup_hint: None,
            url_hint: None,
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
    use std::io::Read;
    let resp = ureq::get(&url)
        .timeout(std::time::Duration::from_secs(20))
        .call()
        .map_err(|e| e.to_string())?;
    // Cap the registry response (defense in depth against a huge or MITM'd body).
    let mut buf = Vec::new();
    resp.into_reader()
        .take(8 * 1024 * 1024)
        .read_to_end(&mut buf)
        .map_err(|e| e.to_string())?;
    let body: Value = serde_json::from_slice(&buf).map_err(|e| e.to_string())?;

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
            // Each entry has a target: a URL, a command, or a url_hint
            // (self-hosted servers where the user supplies the URL at add time).
            assert!(
                e.url.is_some() || e.command.is_some() || e.url_hint.is_some(),
                "{} has no target",
                e.name
            );
            // Every curated entry must land in a browse-view category.
            assert!(!e.category.is_empty(), "{} has no category", e.name);
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
        assert!(filter_catalog(curated(), "postgres")
            .iter()
            .any(|e| e.name == "Neon"));
        // Empty query returns the full set.
        assert_eq!(filter_catalog(curated(), "").len(), curated().len());
    }

    #[test]
    fn filter_catalog_multiword_uses_all_terms_fallback() {
        let c = curated();
        // "serverless postgres" is not a contiguous substring of Neon's text
        // ("Serverless Postgres: ..."), but both terms appear, so the all-terms
        // fallback must still surface it.
        let hits = filter_catalog(c.clone(), "serverless postgres");
        assert!(
            hits.iter().any(|e| e.name == "Neon"),
            "all-terms fallback should match Neon"
        );
        // A term present nowhere yields nothing.
        assert!(filter_catalog(c, "zzzznotacatalogword").is_empty());
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

    #[test]
    fn map_server_rejects_unsafe_specs() {
        // Leading-dash identifier (flag injection into npx) is dropped.
        let flag = json!({ "name": "io.x/y", "title": "Y",
            "packages": [{ "registryType": "npm", "identifier": "--unsafe-flag" }] });
        assert!(
            map_server(&flag).is_none(),
            "flag-injection identifier must be dropped"
        );
        // Shell metacharacters in the version are dropped.
        let meta = json!({ "name": "io.x/z", "title": "Z",
            "packages": [{ "registryType": "npm", "identifier": "pkg", "version": "1; rm -rf /" }] });
        assert!(
            map_server(&meta).is_none(),
            "shell metachars must be dropped"
        );
        // A non-http(s) remote URL is dropped.
        let scheme = json!({ "name": "io.x/w", "title": "W",
            "remotes": [{ "type": "streamable-http", "url": "file:///etc/passwd" }] });
        assert!(
            map_server(&scheme).is_none(),
            "non-http remote must be dropped"
        );
    }

    // Self-hosted catalog coverage (url_hint / setup_hint invariants), contributed by
    // @bradhallett (salvaged from PR #62 onto current main).
    #[test]
    fn self_hosted_entries_have_url_hint_not_url() {
        let c = curated();
        for e in &c {
            if e.url_hint.is_some() {
                // Self-hosted entries must NOT have a fixed URL (user supplies it).
                assert!(e.url.is_none(), "{} has both url and url_hint", e.name);
                // And must have transport http (they speak MCP over HTTP).
                assert_eq!(
                    e.transport, "http",
                    "{} has url_hint but transport is not http",
                    e.name
                );
            }
        }
    }

    #[test]
    fn url_hint_round_trips_through_serialization() {
        let e = curated()
            .into_iter()
            .find(|e| e.url_hint.is_some())
            .unwrap();
        let original_hint = e.url_hint.clone().unwrap();
        let json = serde_json::to_string(&e).unwrap();
        // url_hint is serialized (not skipped — it's present).
        assert!(json.contains("urlHint"), "url_hint should appear in JSON");
        let back: CatalogEntry = serde_json::from_str(&json).unwrap();
        assert_eq!(back.url_hint.as_deref(), Some(original_hint.as_str()));
    }

    #[test]
    fn n8n_and_langfuse_are_in_catalog() {
        let c = curated();
        assert!(
            c.iter().any(|e| e.name == "n8n"),
            "n8n missing from catalog"
        );
        assert!(
            c.iter().any(|e| e.name == "Langfuse"),
            "Langfuse missing from catalog"
        );
    }

    #[test]
    fn n8n_and_langfuse_have_categories() {
        let c = curated();
        for e in c.iter().filter(|e| e.name == "n8n" || e.name == "Langfuse") {
            assert!(!e.category.is_empty(), "{} has no category", e.name);
        }
    }

    #[test]
    fn self_hosted_entries_have_credential_hints() {
        // n8n and Langfuse should guide the user on their URL + credentials. On current
        // main that guidance lives in url_hint (adapted from Brad's setup_hint check).
        let c = curated();
        for name in ["n8n", "Langfuse"] {
            let e = c.iter().find(|e| e.name == name).unwrap();
            let hint = e.url_hint.as_deref().or(e.setup_hint.as_deref());
            assert!(
                hint.map(|h| !h.is_empty()).unwrap_or(false),
                "{name} should have a credential/setup hint"
            );
        }
    }

    #[test]
    fn registry_entries_have_no_url_hint() {
        // map_server (the MCP registry mapper) should never set url_hint.
        let server = json!({
            "name": "io.test/example",
            "title": "Example",
            "packages": [{ "registryType": "npm", "identifier": "example-mcp" }]
        });
        let entry = map_server(&server).unwrap();
        assert!(
            entry.url_hint.is_none(),
            "registry entries should not have url_hint"
        );
    }
}
