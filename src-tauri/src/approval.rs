//! Human-in-the-loop (HITL) tool-approval: the contract both sides share.
//!
//! When HITL is on, the gateway holds a *gated* tool call and asks the Toolport app for a
//! human decision before it runs. The app hosts a small approval broker; every gateway
//! process (there is one per stdio client, plus the app's `--http` bridge) dials OUT to it,
//! sends the pending call, and blocks reading for the decision. Arguments travel over the
//! connection and never touch disk. Everything is fail-closed: no endpoint, no answer, a
//! timeout, or any transport error all mean DENY.
//!
//! This module is the piece both the gateway-side client and the app-side broker share:
//! the wire types, the gating policy, and the on-disk endpoint descriptor. Keeping it in
//! the lib means there is exactly one definition of the protocol.

use serde::{Deserialize, Serialize};

/// The broker descriptor's filename inside the Conduit data dir. The app writes it on
/// startup; every gateway process reads it. It holds ONLY the endpoint address and an auth
/// token, never any call payload.
pub const ENDPOINT_FILE: &str = "approval-endpoint.json";

/// Fail-closed timeout for a pending approval: if no human decides within this window, the
/// call is denied. (Configurable later; a sensible default for v1.)
pub const DEFAULT_TIMEOUT_SECS: u64 = 120;

/// The broker endpoint descriptor the app publishes and gateways read.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EndpointDescriptor {
    /// The address a gateway connects to (e.g. `127.0.0.1:PORT`, or a named-pipe / uds path
    /// once the transport is hardened). Opaque to policy.
    pub endpoint: String,
    /// A 128-bit random token the gateway must present. Defense-in-depth over the local-user
    /// filesystem trust boundary: only a process that can read the Conduit data dir (same as
    /// secrets) can obtain it.
    pub token: String,
}

/// Why a call was gated, surfaced in the approval UI.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalReason {
    /// The tool is annotated `destructiveHint: true`.
    Destructive,
    /// The tool's server has untrusted provenance (a shared or public-registry import).
    UntrustedSource,
    /// Both of the above.
    DestructiveAndUntrusted,
}

/// A request from a gateway to the broker: "a human should approve this call." The arguments
/// are included so the person can review them; they stay in memory on both ends.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ApprovalRequest {
    /// Auth token from the endpoint descriptor.
    pub token: String,
    /// Opaque per-call id; also the correlation key for the decision.
    pub id: String,
    /// Which client/agent triggered it (for display + attribution), when known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client: Option<String>,
    /// The downstream server the tool belongs to.
    pub server: String,
    /// The tool name.
    pub tool: String,
    /// Why it was gated, for the UI.
    pub reason: ApprovalReason,
    /// The exact arguments the human is approving.
    pub arguments: serde_json::Value,
    /// Fingerprint of the current tool definition, when the gateway can resolve it.
    /// Allowlist entries include this so a tool definition change re-requires approval.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tool_fingerprint: Option<String>,
}

/// The broker's answer to an [`ApprovalRequest`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalDecision {
    /// A human approved; the call runs.
    Approved,
    /// A human denied; the call is refused.
    Denied,
    /// A human was asked but did not decide within the fail-closed window; treated as a deny.
    Timeout,
    /// The gateway could not reach a live approval broker: no endpoint descriptor, a dead
    /// endpoint, or the transport failed before the request was ever handed off. Distinct
    /// from [`Timeout`] (a human *was* asked and didn't answer) so the agent-facing message
    /// and any audit can tell "the approval service is down" apart from "you didn't approve
    /// in time". Still fail-closed - it never lets the call proceed. The broker never sends
    /// this; it is only ever produced gateway-side.
    Unreachable,
}

impl ApprovalDecision {
    /// The security-critical predicate: ONLY an explicit human approval lets the call
    /// proceed. Denied, Timeout, Unreachable, and (at the call site) any transport error
    /// all block.
    pub fn is_approved(self) -> bool {
        matches!(self, ApprovalDecision::Approved)
    }
}

/// HITL gating policy: given whether a tool is destructive and whether its server has
/// untrusted provenance, decide if the call needs a human. `enabled` is the registry's
/// `human_approval` master switch. Returns the reason when gated, `None` when the call may
/// run without approval.
///
/// v1 gates destructive tools AND anything from an untrusted-provenance server (the same
/// shared/registry signal the SSRF connect-guard uses), so it does not rely solely on
/// servers that bother to set `destructiveHint`.
pub fn gate_reason(
    enabled: bool,
    is_destructive: bool,
    untrusted_source: bool,
) -> Option<ApprovalReason> {
    if !enabled {
        return None;
    }
    match (is_destructive, untrusted_source) {
        (true, true) => Some(ApprovalReason::DestructiveAndUntrusted),
        (true, false) => Some(ApprovalReason::Destructive),
        (false, true) => Some(ApprovalReason::UntrustedSource),
        (false, false) => None,
    }
}

/// The stable key for the "allow this tool past approval" lists (per-session in the broker,
/// persistent in the registry). One definition so both sides agree. `server` is already the
/// sanitized prefix, so `server/tool` is unambiguous.
pub fn allow_key(server: &str, tool: &str) -> String {
    format!("{server}/{tool}")
}

/// Fingerprint-bound allow key. This is intentionally distinct from the legacy
/// `server/tool` key so old broad allows don't silently keep bypassing approval.
pub fn fingerprint_allow_key(server: &str, tool: &str, fingerprint: &str) -> String {
    format!("{}/{}/{}", server, tool, fingerprint)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gate_is_off_when_disabled() {
        assert_eq!(gate_reason(false, true, true), None);
        assert_eq!(gate_reason(false, true, false), None);
    }

    #[test]
    fn gate_covers_destructive_and_untrusted() {
        assert_eq!(gate_reason(true, true, false), Some(ApprovalReason::Destructive));
        assert_eq!(gate_reason(true, false, true), Some(ApprovalReason::UntrustedSource));
        assert_eq!(
            gate_reason(true, true, true),
            Some(ApprovalReason::DestructiveAndUntrusted)
        );
        // A read-only tool from a trusted server is never gated, even with HITL on.
        assert_eq!(gate_reason(true, false, false), None);
    }

    #[test]
    fn only_explicit_approval_proceeds() {
        assert!(ApprovalDecision::Approved.is_approved());
        assert!(!ApprovalDecision::Denied.is_approved());
        assert!(!ApprovalDecision::Timeout.is_approved());
        // Unreachable is fail-closed exactly like the other non-approvals.
        assert!(!ApprovalDecision::Unreachable.is_approved());
    }

    #[test]
    fn unreachable_is_a_distinct_serde_variant() {
        // The variant must round-trip (it flows through the same decision type), and be
        // distinct from Timeout so callers can tell the two failure modes apart.
        let s = serde_json::to_string(&ApprovalDecision::Unreachable).unwrap();
        assert_eq!(s, "\"unreachable\"");
        let back: ApprovalDecision = serde_json::from_str(&s).unwrap();
        assert_eq!(back, ApprovalDecision::Unreachable);
        assert_ne!(ApprovalDecision::Unreachable, ApprovalDecision::Timeout);
    }

    #[test]
    fn wire_types_round_trip() {
        let req = ApprovalRequest {
            token: "tok".into(),
            id: "abc".into(),
            client: Some("cursor".into()),
            server: "db".into(),
            tool: "drop_table".into(),
            reason: ApprovalReason::Destructive,
            arguments: serde_json::json!({ "table": "users" }),
            tool_fingerprint: Some("v2:abc".into()),
        };
        let round: ApprovalRequest =
            serde_json::from_str(&serde_json::to_string(&req).unwrap()).unwrap();
        assert_eq!(round.tool, "drop_table");
        assert_eq!(round.reason, ApprovalReason::Destructive);
        assert_eq!(round.arguments["table"], "users");
        assert_eq!(round.tool_fingerprint.as_deref(), Some("v2:abc"));

        let dec: ApprovalDecision =
            serde_json::from_str(&serde_json::to_string(&ApprovalDecision::Approved).unwrap())
                .unwrap();
        assert!(dec.is_approved());
    }

    #[test]
    fn fingerprint_allow_key_binds_definition() {
        assert_eq!(
            fingerprint_allow_key("db", "drop_table", "v2:abc"),
            "db/drop_table/v2:abc"
        );
        assert_ne!(
            fingerprint_allow_key("db", "drop_table", "v2:abc"),
            allow_key("db", "drop_table")
        );
    }

    #[test]
    fn endpoint_descriptor_round_trips() {
        let d = EndpointDescriptor { endpoint: "127.0.0.1:8790".into(), token: "s3cret".into() };
        let round: EndpointDescriptor =
            serde_json::from_str(&serde_json::to_string(&d).unwrap()).unwrap();
        assert_eq!(round.endpoint, "127.0.0.1:8790");
        assert_eq!(round.token, "s3cret");
    }
}
