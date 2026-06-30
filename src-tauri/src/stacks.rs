//! Curated "stacks": role-based bundles of catalog servers with guided setup.
//!
//! A stack is just a named, ordered list of catalog entries (referenced by name),
//! resolved against [`catalog::curated`] so the UI gets each server's command,
//! env keys, and credential hints in one call. Applying a stack reuses the
//! existing add-server / profile / install primitives; nothing here writes state.

use serde::Serialize;

use crate::catalog::{self, CatalogEntry};

/// One curated stack: a use-case bundle the user can set up in one flow.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Stack {
    /// Stable id (kebab-case), e.g. "fullstack-web".
    pub id: String,
    pub name: String,
    pub description: String,
    /// The stack's servers, resolved to full catalog entries (with cred hints).
    /// A name that doesn't resolve is dropped, so the list is always usable.
    pub servers: Vec<CatalogEntry>,
}

/// The curated set of stacks. Each references catalog entries by name; we resolve
/// them here so a typo surfaces as a missing server in tests, not at runtime.
pub fn stacks() -> Vec<Stack> {
    let catalog = catalog::curated();
    let by_name: std::collections::HashMap<&str, &CatalogEntry> =
        catalog.iter().map(|e| (e.name.as_str(), e)).collect();

    let make = |id: &str, name: &str, desc: &str, names: &[&str]| Stack {
        id: id.to_string(),
        name: name.to_string(),
        description: desc.to_string(),
        servers: names
            .iter()
            .filter_map(|n| by_name.get(n).map(|e| (*e).clone()))
            .collect(),
    };

    vec![
        make(
            "fullstack-web",
            "Full-stack web dev",
            "Ship and run a web app: repo, deploys, database, and error tracking.",
            &["GitHub", "Vercel", "PostgreSQL", "Sentry", "Filesystem"],
        ),
        make(
            "backend-data",
            "Backend & data",
            "Work across your databases and code from one agent.",
            &["PostgreSQL", "MongoDB", "GitHub", "Fetch", "Filesystem"],
        ),
        make(
            "infra-devops",
            "Infra & DevOps",
            "Manage cloud infrastructure from your editor: Linode, Kubernetes, and AWS.",
            &["Linode", "Kubernetes", "AWS", "GitHub", "Sentry"],
        ),
        make(
            "research-docs",
            "Research & docs",
            "Search the web, pull up-to-date library docs, and write into Notion.",
            &["Context7", "Exa", "Perplexity", "Notion", "Fetch"],
        ),
        make(
            "ai-ml",
            "AI & ML",
            "Build with models and retrieval: model catalogs, a vector store, and up-to-date docs.",
            &["Hugging Face", "OpenRouter", "Qdrant", "Context7", "Exa"],
        ),
        make(
            "product-design",
            "Product & design",
            "Run product work from one place: issues, docs, designs, and team chat.",
            &["Linear", "Notion", "Figma", "Slack"],
        ),
        make(
            "founder",
            "Founder / indie SaaS",
            "Ship and run a small SaaS: payments, deploys, code, email, and issues.",
            &["Stripe", "Vercel", "GitHub", "Resend", "Linear"],
        ),
        make(
            "web-automation",
            "Web scraping & automation",
            "Pull data from any site and drive real browsers: search, scrape, extract, and automate.",
            &["Firecrawl", "Tavily", "Playwright", "Browserbase", "Apify"],
        ),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_stack_resolves_all_its_servers() {
        // The intended reference count, kept in sync with `stacks()` above. If a
        // server name is mistyped, it silently drops and this total falls short.
        let intended = 5 + 5 + 5 + 5 + 5 + 4 + 5 + 5;
        let resolved: usize = stacks().iter().map(|s| s.servers.len()).sum();
        assert_eq!(
            resolved, intended,
            "a stack references a server name not in the catalog"
        );
        // Every stack is non-empty and has a stable id + name.
        for s in stacks() {
            assert!(!s.servers.is_empty(), "stack {} is empty", s.id);
            assert!(!s.id.is_empty() && !s.name.is_empty());
        }
    }

    #[test]
    fn stack_servers_carry_credential_hints_where_expected() {
        let infra = stacks()
            .into_iter()
            .find(|s| s.id == "infra-devops")
            .unwrap();
        let linode = infra.servers.iter().find(|e| e.name == "Linode").unwrap();
        // Linode is token-based: it should carry a creds URL + a setup hint.
        assert!(linode.credentials_url.is_some());
        assert!(linode.setup_hint.is_some());
        assert!(linode.env_keys.iter().any(|k| k == "LINODE_API_TOKEN"));
    }
}
