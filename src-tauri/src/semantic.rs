//! Optional semantic re-ranking for tool search.
//!
//! The lexical ranker (in the gateway) matches keywords, so a paraphrased need
//! ("charge a card") can rank a keyword-stuffed but wrong tool above the right one,
//! or miss it entirely. This module blends in embedding cosine similarity so intent,
//! not just shared words, drives the ranking.
//!
//! Design constraints (see docs/specs/semantic-search.md):
//!   - No bundled model / no binary bloat: embeddings come from an OpenAI-compatible
//!     `/v1/embeddings` endpoint the user already runs (LM Studio, Ollama) or a cloud
//!     one. Blocking `ureq`, matching the gateway's style.
//!   - Off by default. When off, or on any failure, the caller uses pure lexical
//!     ranking, so this can never make search worse than today.
//!   - Tool embeddings are cached on disk by content hash, so a catalog embeds once.

use std::collections::HashMap;
use std::path::PathBuf;

use serde_json::{json, Value};
use sha2::{Digest, Sha256};

/// Resolved semantic-search settings (from the registry, see `registry::Registry`).
#[derive(Debug, Clone)]
pub struct SemanticConfig {
    pub enabled: bool,
    pub endpoint: String,
    pub model: String,
    /// Weight of the semantic score vs lexical, 0.0 (pure lexical) .. 1.0 (pure semantic).
    pub blend: f32,
}

impl SemanticConfig {
    pub fn is_active(&self) -> bool {
        self.enabled && !self.endpoint.is_empty() && !self.model.is_empty()
    }

    /// Build from registry settings, with env overrides so a benchmark (or a single
    /// client) can toggle semantic search without editing the registry:
    ///   CONDUIT_SEMANTIC=on|off, CONDUIT_EMBED_ENDPOINT, CONDUIT_EMBED_MODEL,
    ///   CONDUIT_EMBED_BLEND. (The API key, if needed, is CONDUIT_EMBED_KEY.)
    pub fn resolve(enabled: bool, endpoint: String, model: String, blend: f32) -> Self {
        let env = |k: &str| std::env::var(k).ok().filter(|v| !v.is_empty());
        let enabled = match env("CONDUIT_SEMANTIC") {
            Some(v) => matches!(v.to_ascii_lowercase().as_str(), "on" | "1" | "true" | "yes"),
            None => enabled,
        };
        SemanticConfig {
            enabled,
            endpoint: env("CONDUIT_EMBED_ENDPOINT").unwrap_or(endpoint),
            model: env("CONDUIT_EMBED_MODEL").unwrap_or(model),
            blend: env("CONDUIT_EMBED_BLEND").and_then(|v| v.parse().ok()).unwrap_or(blend),
        }
    }
}

/// The text we embed for a tool: server, name, and description. Mirrors what the
/// lexical ranker reads, so both score the same signal.
pub fn tool_document(tool: &Value) -> String {
    let name = tool.get("name").and_then(Value::as_str).unwrap_or("");
    let desc = tool.get("description").and_then(Value::as_str).unwrap_or("");
    let server = name.split("__").next().unwrap_or("");
    format!("{server} {name}: {desc}")
}

fn doc_hash(model: &str, doc: &str) -> String {
    let mut h = Sha256::new();
    h.update(model.as_bytes()); // model in the key: different models -> different vectors
    h.update([0u8]);
    h.update(doc.as_bytes());
    let bytes = h.finalize();
    let mut s = String::with_capacity(32);
    for b in &bytes[..16] {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

fn cache_path() -> Option<PathBuf> {
    Some(crate::registry::conduit_dir()?.join("embeddings.json"))
}

fn load_cache() -> HashMap<String, Vec<f32>> {
    cache_path()
        .and_then(|p| std::fs::read_to_string(p).ok())
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default()
}

fn save_cache(cache: &HashMap<String, Vec<f32>>) {
    if let Some(path) = cache_path() {
        if let Ok(s) = serde_json::to_string(cache) {
            let _ = crate::registry::atomic_write(&path, &s);
        }
    }
}

/// Cosine similarity of two vectors. 0.0 on a length mismatch or zero vector, so a
/// bad embedding degrades to "no semantic signal" rather than poisoning the ranking.
pub fn cosine(a: &[f32], b: &[f32]) -> f32 {
    if a.len() != b.len() || a.is_empty() {
        return 0.0;
    }
    let mut dot = 0.0f32;
    let mut na = 0.0f32;
    let mut nb = 0.0f32;
    for i in 0..a.len() {
        dot += a[i] * b[i];
        na += a[i] * a[i];
        nb += b[i] * b[i];
    }
    if na == 0.0 || nb == 0.0 {
        return 0.0;
    }
    dot / (na.sqrt() * nb.sqrt())
}

/// POST a batch of texts to the embeddings endpoint; returns one vector per input,
/// in order. None on any transport/parse error (caller falls back to lexical).
fn embed_batch(cfg: &SemanticConfig, inputs: &[String]) -> Option<Vec<Vec<f32>>> {
    if inputs.is_empty() {
        return Some(Vec::new());
    }
    // Reuse the gateway's connect-time SSRF resolver so DNS rebinding or a redirect
    // cannot send the tool catalog (or CONDUIT_EMBED_KEY) to cloud metadata. Private
    // and loopback addresses remain allowed because local Ollama/LM Studio endpoints
    // are a supported configuration. Keep the short timeout so any failure falls back
    // promptly to the pure-lexical ranker.
    let agent = crate::downstream::guarded_agent_with_timeout(
        false,
        std::time::Duration::from_secs(10),
    );
    let mut req = agent.post(&cfg.endpoint).set("Content-Type", "application/json");
    if let Ok(key) = std::env::var("CONDUIT_EMBED_KEY") {
        if !key.is_empty() {
            req = req.set("Authorization", &format!("Bearer {key}"));
        }
    }
    let resp: Value = req
        .send_json(json!({ "model": cfg.model, "input": inputs }))
        .ok()?
        .into_json()
        .ok()?;
    let data = resp.get("data")?.as_array()?;
    let mut out = Vec::with_capacity(data.len());
    for item in data {
        let v: Vec<f32> = item
            .get("embedding")?
            .as_array()?
            .iter()
            .filter_map(|n| n.as_f64().map(|f| f as f32))
            .collect();
        if v.is_empty() {
            return None;
        }
        out.push(v);
    }
    (out.len() == inputs.len()).then_some(out)
}

/// Embed a single string (e.g. the query).
pub fn embed_query(cfg: &SemanticConfig, text: &str) -> Option<Vec<f32>> {
    embed_batch(cfg, std::slice::from_ref(&text.to_string()))?.into_iter().next()
}

/// Embeddings for each tool (keyed by tool name), using the on-disk cache and
/// embedding only the misses in one batch. Returns an empty map on failure so the
/// caller can fall back to lexical ranking.
pub fn embed_tools(cfg: &SemanticConfig, tools: &[&Value]) -> HashMap<String, Vec<f32>> {
    let mut cache = load_cache();
    let mut result: HashMap<String, Vec<f32>> = HashMap::new();

    // Figure out which tools need embedding (cache miss).
    let mut miss_names: Vec<String> = Vec::new();
    let mut miss_docs: Vec<String> = Vec::new();
    let mut miss_hashes: Vec<String> = Vec::new();
    for t in tools {
        let name = match t.get("name").and_then(Value::as_str) {
            Some(n) => n.to_string(),
            None => continue,
        };
        let doc = tool_document(t);
        let h = doc_hash(&cfg.model, &doc);
        if let Some(v) = cache.get(&h) {
            result.insert(name, v.clone());
        } else {
            miss_names.push(name);
            miss_docs.push(doc);
            miss_hashes.push(h);
        }
    }

    if !miss_docs.is_empty() {
        if let Some(vectors) = embed_batch(cfg, &miss_docs) {
            for ((name, h), v) in miss_names.iter().zip(miss_hashes.iter()).zip(vectors) {
                cache.insert(h.clone(), v.clone());
                result.insert(name.clone(), v);
            }
            save_cache(&cache);
        }
        // On embed failure we simply return what the cache already had (possibly
        // empty); the caller treats missing vectors as "no semantic signal".
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    fn embedding_config(endpoint: String) -> SemanticConfig {
        SemanticConfig {
            enabled: true,
            endpoint,
            model: "test-model".into(),
            blend: 0.5,
        }
    }

    #[test]
    fn cosine_basic() {
        assert!((cosine(&[1.0, 0.0], &[1.0, 0.0]) - 1.0).abs() < 1e-6);
        assert!(cosine(&[1.0, 0.0], &[0.0, 1.0]).abs() < 1e-6);
        // Length mismatch / empty -> 0, never panics.
        assert_eq!(cosine(&[1.0], &[1.0, 2.0]), 0.0);
        assert_eq!(cosine(&[], &[]), 0.0);
        assert_eq!(cosine(&[0.0, 0.0], &[1.0, 1.0]), 0.0);
    }

    #[test]
    fn tool_document_includes_server_name_desc() {
        let t = json!({ "name": "stripe__create_charge", "description": "Charge a card." });
        let d = tool_document(&t);
        assert!(d.contains("stripe"));
        assert!(d.contains("stripe__create_charge"));
        assert!(d.contains("Charge a card."));
    }

    #[test]
    fn doc_hash_is_model_scoped_and_stable() {
        let a = doc_hash("m1", "doc");
        assert_eq!(a, doc_hash("m1", "doc"));
        assert_ne!(a, doc_hash("m2", "doc")); // different model -> different key
        assert_ne!(a, doc_hash("m1", "other"));
    }

    #[test]
    fn is_active_requires_enabled_and_config() {
        let base = SemanticConfig {
            enabled: true,
            endpoint: "http://x/v1/embeddings".into(),
            model: "m".into(),
            blend: 0.5,
        };
        assert!(base.is_active());
        assert!(!SemanticConfig { enabled: false, ..base.clone() }.is_active());
        assert!(!SemanticConfig { endpoint: "".into(), ..base.clone() }.is_active());
        assert!(!SemanticConfig { model: "".into(), ..base }.is_active());
    }

    #[test]
    fn embedding_agent_allows_local_endpoints() {
        let listener = tiny_http::Server::http("127.0.0.1:0").unwrap();
        let port = listener.server_addr().to_ip().unwrap().port();
        let endpoint = format!("http://127.0.0.1:{port}/v1/embeddings");
        let server = std::thread::spawn(move || {
            let request = listener.recv().unwrap();
            let body = r#"{"data":[{"embedding":[1.0,2.0]}]}"#;
            let content_type = tiny_http::Header::from_bytes(
                &b"Content-Type"[..],
                &b"application/json"[..],
            )
            .unwrap();
            request
                .respond(tiny_http::Response::from_string(body).with_header(content_type))
                .unwrap();
        });

        assert_eq!(
            embed_query(&embedding_config(endpoint), "hello"),
            Some(vec![1.0, 2.0])
        );
        server.join().unwrap();
    }

    #[test]
    fn embedding_agent_does_not_follow_redirects() {
        use std::net::TcpListener;

        let redirect_target = TcpListener::bind("127.0.0.1:0").unwrap();
        redirect_target.set_nonblocking(true).unwrap();
        let target_url = format!("http://{}/stolen", redirect_target.local_addr().unwrap());

        let redirector = tiny_http::Server::http("127.0.0.1:0").unwrap();
        let port = redirector.server_addr().to_ip().unwrap().port();
        let endpoint = format!("http://127.0.0.1:{port}/v1/embeddings");
        let server = std::thread::spawn(move || {
            let request = redirector.recv().unwrap();
            let location = tiny_http::Header::from_bytes(&b"Location"[..], target_url.as_bytes())
                .unwrap();
            request
                .respond(
                    tiny_http::Response::empty(302).with_header(location),
                )
                .unwrap();
        });

        assert!(embed_query(&embedding_config(endpoint), "hello").is_none());
        server.join().unwrap();
        assert!(matches!(
            redirect_target.accept(),
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock
        ));
    }
}
