//! Smart auth detection for remote servers.
//!
//! `probe_auth` figures out what a server needs - no auth, OAuth, or a pasted
//! token - by actually talking to it, and pairs that with vendor-specific
//! instructions for the big services so the user is never stuck guessing.

use serde::Serialize;

use crate::downstream::{DownstreamServer, HttpTransport};
use crate::{oauth, remote};

/// What a server needs to connect, plus how to get it.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AuthInfo {
    /// "none" | "oauth" | "token" | "unknown"
    pub kind: String,
    pub vendor: Option<String>,
    pub token_url: Option<String>,
    pub instructions: Option<String>,
}

impl AuthInfo {
    pub fn fallback() -> Self {
        AuthInfo {
            kind: "unknown".to_string(),
            vendor: None,
            token_url: None,
            instructions: None,
        }
    }
}

struct Vendor {
    /// Matched (case-insensitive) against the server URL.
    needle: &'static str,
    name: &'static str,
    /// Override the live probe for vendors with known auth behaviour.
    force_kind: Option<&'static str>,
    token_url: Option<&'static str>,
    instructions: &'static str,
}

fn vendors() -> &'static [Vendor] {
    &[
        Vendor {
            needle: "stripe.com",
            name: "Stripe",
            force_kind: None,
            token_url: Some("https://dashboard.stripe.com/apikeys"),
            instructions: "Sign in with OAuth, or create a restricted API key in the Stripe dashboard and paste it.",
        },
        Vendor {
            needle: "clerk",
            name: "Clerk",
            force_kind: Some("none"),
            token_url: None,
            instructions: "Clerk's MCP server connects without a token. Just enable it.",
        },
        Vendor {
            needle: "supabase",
            name: "Supabase",
            force_kind: None,
            token_url: Some("https://supabase.com/dashboard/account/tokens"),
            instructions: "Create a personal access token in Supabase account settings and paste it.",
        },
        Vendor {
            needle: "vercel",
            name: "Vercel",
            force_kind: None,
            token_url: Some("https://vercel.com/account/settings/tokens"),
            instructions: "Create a token in Vercel account settings and paste it.",
        },
        Vendor {
            needle: "inngest",
            name: "Inngest",
            force_kind: None,
            token_url: Some("https://app.inngest.com/settings/keys"),
            instructions: "Create a key in Inngest settings and paste it.",
        },
        Vendor {
            needle: "expo.dev",
            name: "Expo",
            force_kind: None,
            token_url: Some("https://expo.dev/settings/access-tokens"),
            instructions: "Sign in with OAuth, or create an access token in Expo settings.",
        },
        Vendor {
            needle: "revenuecat",
            name: "RevenueCat",
            force_kind: Some("token"),
            token_url: Some("https://www.revenuecat.com/docs/projects/authentication"),
            instructions: "RevenueCat's OAuth is limited to their approved partners, so use a key. In the RevenueCat dashboard open your project, go to Project settings then API Keys, and create a V2 secret key (read-only is fine). Paste it here.",
        },
        Vendor {
            needle: "cloudflare",
            name: "Cloudflare",
            force_kind: None,
            token_url: Some("https://dash.cloudflare.com/profile/api-tokens"),
            instructions: "Sign in with OAuth, or create an API token in Cloudflare profile settings.",
        },
        Vendor {
            needle: "github",
            name: "GitHub",
            force_kind: None,
            token_url: Some("https://github.com/settings/tokens"),
            instructions: "Create a personal access token in GitHub developer settings and paste it.",
        },
        Vendor {
            needle: "linear.app",
            name: "Linear",
            force_kind: None,
            token_url: Some("https://linear.app/settings/api"),
            instructions: "Sign in with OAuth, or create a personal API key in Linear settings.",
        },
        Vendor {
            needle: "sentry.io",
            name: "Sentry",
            force_kind: None,
            token_url: Some("https://sentry.io/settings/account/api/auth-tokens/"),
            instructions: "Create an auth token in Sentry account settings and paste it.",
        },
        Vendor {
            needle: "notion",
            name: "Notion",
            force_kind: None,
            token_url: Some("https://www.notion.so/my-integrations"),
            instructions: "Create an internal integration and paste its token.",
        },
    ]
}

fn match_vendor(url: &str) -> Option<&'static Vendor> {
    let lower = url.to_lowercase();
    vendors().iter().find(|v| lower.contains(v.needle))
}

/// Decide what a server needs: try connecting with no auth; if it works it needs
/// none; if it 401s, see whether OAuth is discoverable, else a token.
fn classify(url: &str) -> String {
    let transport = HttpTransport::with_auth(url, None);
    match DownstreamServer::connect("probe".to_string(), Box::new(transport)) {
        Ok(_) => "none".to_string(),
        Err(e) if remote::is_auth_error(&e) => match oauth::discover(url) {
            Ok(ep) if ep.registration_endpoint.is_some() => "oauth".to_string(),
            _ => "token".to_string(),
        },
        Err(_) => "unknown".to_string(),
    }
}

pub fn probe_auth(url: &str) -> AuthInfo {
    let vendor = match_vendor(url);
    let kind = match vendor.and_then(|v| v.force_kind) {
        Some(forced) => forced.to_string(),
        None => classify(url),
    };
    AuthInfo {
        kind,
        vendor: vendor.map(|v| v.name.to_string()),
        token_url: vendor.and_then(|v| v.token_url.map(String::from)),
        instructions: vendor.map(|v| v.instructions.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matches_known_vendors() {
        assert_eq!(match_vendor("https://mcp.stripe.com").unwrap().name, "Stripe");
        assert_eq!(
            match_vendor("https://mcp.revenuecat.ai/mcp").unwrap().name,
            "RevenueCat"
        );
        assert!(match_vendor("https://unknown.example.com").is_none());
    }

    #[test]
    fn forced_vendors_skip_the_network() {
        // RevenueCat and Clerk have known behaviour, so no live probe is needed.
        assert_eq!(probe_auth("https://mcp.revenuecat.ai/mcp").kind, "token");
        assert_eq!(probe_auth("https://mcp.clerk.dev/mcp").kind, "none");
    }

    #[test]
    fn fallback_is_unknown() {
        assert_eq!(AuthInfo::fallback().kind, "unknown");
    }
}
