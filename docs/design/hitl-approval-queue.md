# Design: Human-in-the-Loop (HITL) Tool-Approval Queue

Status: P1 IMPLEMENTED in PR #82 (2026-07-02, rev 2 architecture). Remaining before merge: a runtime end-to-end check (needs the app running). Deferred to P2: named-pipe/uds transport hardening, an async "held, will resume" fallback, and tool+args-hash dedupe.

## Goal

Let a human approve or deny sensitive tool calls *out-of-band* before they execute,
holding the call until a decision (or a fail-closed timeout). Distinct from the existing
**agent-facing** `toolport_confirm`, where the *model* re-confirms its own destructive
call. HITL puts a *person* in the loop through the Toolport app. This is a genuine
security differentiator (the "approval queue" gap vs. Lunar MCPX / IBM ContextForge), so
it is worth building to a high bar rather than the minimal one.

## Architecture constraints (verified against the code)

1. **Many gateway processes, not one.** Each stdio client (Claude Desktop, Cursor, Claude
   Code) spawns its own `conduit-gateway` over stdio; the app also supervises one in
   `--http` mode (`lib.rs:1470-1541`). `ConfirmGuard` is in-memory **per process**
   (`conduit-gateway.rs:914-974`).
2. **No inbound control channel to a gateway** today; app->gateway is one-way via files
   under `~/.conduit/`, polled by mtime every ~1000ms (`conduit-gateway.rs:2073-2142`).
3. Observability today = shared JSONL the app polls (`inspect.jsonl` ring-50,
   `audit.jsonl`).
4. Existing destructive interception in `process_request` (`conduit-gateway.rs:1599-1642`):
   token stored in `ConfirmGuard`, returned to the model as an `isError` preview, replayed
   via `toolport_confirm` (`:1362-1389`), 60s TTL, `is_destructive` = `annotations.destructiveHint`.
5. Frontend (`src/components/`): `ActivityView.tsx` + `SettingsView.tsx`; the quarantine
   list/release UI is a good precedent for an approve/deny queue.

## The core problem

A HITL gate must (a) cover **all** gateway processes (the stdio ones are the main case),
(b) **block** the agent's call until a human decides, (c) never leak arguments to disk,
and (d) be **fail-closed**. Two obvious designs each fail one of these, which is what
drives the recommended one.

## DECISION: app-hosted approval broker; gateways dial out and long-poll

The Toolport **app** runs a tiny local **approval broker** (an OS-permissioned IPC
endpoint: a Windows **named pipe** / Unix **domain socket**, via the `interprocess` crate;
localhost-TCP+token is the fallback if the cross-platform IPC is painful). On start the app
writes `~/.conduit/approval-endpoint.json = { endpoint, token }` (token = 128-bit secret;
readable only by processes that can already read `~/.conduit/`, the same trust boundary as
secrets).

Flow for a gated call:
1. Gateway (`process_request`) reads the endpoint+token, **connects to the app**, and sends
   `{ client, server, tool, args, provenance, ts }` authenticated by the token.
2. The app shows it in a **Pending Approvals** queue (ActivityView) plus a prominent OS
   notification, and **holds the connection open**.
3. Gateway **blocks reading** that connection (with a timeout). On the human's click the app
   **pushes** `{ approved | denied, approver_ts }` back over the same connection.
4. Gateway wakes: approved -> `route_call` + real result; denied/timeout -> clear error.

**Why this is the best-in-class choice, it wins on every axis the two alternatives lose:**

- **Coverage:** every gateway process dials *out* to the one app broker, so stdio clients
  are covered, not just the app's own `--http` gateway.
- **No args on disk:** arguments travel over the socket and stay in memory. The disk only
  ever holds the endpoint descriptor (no payloads). This is the decisive privacy win.
- **Latency:** event-driven push, not poll intervals, approval feels instant.
- **Fail-closed by construction:** app not running -> the connect fails immediately -> deny
  with "open Toolport to approve". Timeout -> deny. Dropped connection -> deny.
- **Integrity:** the decision arrives over an authenticated socket from the trusted UI, not
  a file any local process could race to write.

### Alternatives considered (and why not)

- **A. Shared-file handshake** (gateway writes `pending/<token>.json`, app writes
  `decided/<token>.json`): works cross-process and reuses the poll pattern, BUT forces tool
  **arguments onto disk** and adds ~1-2s round-trip polling latency. Rejected on the
  disk-privacy and latency axes. (Kept as the low-effort fallback if the IPC broker proves
  too costly.)
- **B. HTTP endpoint on the app's `--http` gateway:** only reaches that one process; misses
  every stdio client. Rejected on coverage.

## The four decisions, resolved

1. **Blocking, not async.** Hold the agent's call until a decision; the agent just sees a
   slower tool and gets the real result or a denial. Async (return-pending-then-replay)
   leaks approval mechanics into the agent and creates a "looks failed" window. A parked
   call blocking that client's *other* calls is acceptable and arguably desirable (don't let
   the agent race ahead of a pending sensitive action); other clients are separate processes
   and unaffected.
2. **Scope: layered, security-first default.** v1 gates (a) `destructiveHint` tools AND
   (b) any tool from an **untrusted-provenance** server (`source` = shared/registry, the
   same trust signal the SSRF guard uses), with per-server / per-tool **overrides** designed
   in from day one (allowlist to skip, forcelist to always gate) and a configurable
   escalation to "all non-`readOnlyHint` tools." Reusing the provenance signal ties HITL to
   the existing trust model instead of relying solely on servers that bother to set
   `destructiveHint`.
3. **Timeout: fail-closed, generous, notified.** Default ~120s, configurable; no decision ->
   **deny**. Because a missed approval denies the call, pending items MUST raise a prominent
   OS notification so you don't miss the window.
4. **Args stay in memory** (resolved by the broker), no disk trade-off to make.

## Security analysis

- **Trust boundary** = the local user (same as `registry.json`/secrets). The endpoint token
  is defense-in-depth so a random local process can't register fake approvals or read
  pending args; OS-permissioned IPC (named pipe / uds) removes any network surface.
- **Tamper/replay:** single-use TTL'd tokens; decision only accepted over the authenticated
  broker connection.
- **DoS:** the broker caps the pending queue and rate-limits per client; excess -> deny.
- **Fail-closed everywhere:** app down, timeout, or dropped connection all deny. If HITL is
  ON, we never silently fall back to the weaker agent-confirm (that would defeat the gate);
  the error tells the human to open Toolport.
- **Audit:** app records approve/deny/timeout to `audit.jsonl` with capped/omitted args
  (never the full payload on disk), extending `record_held`.

## UX

- **ActivityView:** a Pending Approvals section (reuse quarantine's list/release pattern):
  client, server, tool, args, a provenance/trust badge, why-it-was-gated, a countdown, and
  Approve/Deny. Offer **approve-for-session** / **always-allow-this-tool** to curb fatigue.
- **Global:** an OS notification + badge when something is pending (time-sensitive).
- **SettingsView:** toggle `human_approval`, timeout, scope, and per-server/tool overrides.

## Phased plan

- **P1 (MVP):** app broker (IPC) + gateway client + blocking park + destructive/untrusted
  scope + ActivityView queue + fail-closed timeout + audit outcomes.
- **P2:** OS notification + approve-for-session/always-allow + Settings scope UI.
- **P3:** per-server/tool policy editor, multi-approver, "all non-readonly" escalation.

## Feasibility check to do first (before P1 code)

Verify the gateway's stdio **serve loop** can park one `tools/call` on the broker read
without stalling the process in a way that breaks liveness (it already blocks on `ureq` for
downstream calls, so a bounded blocking read fits the same model, but confirm request
dispatch and the ~1s registry watcher still tick while parked). If the loop is strictly
sequential, blocking is still fine (see decision 1); this check just confirms no deadlock
with the registry watcher / notifications.

## Longer-term note

The multi-process reality (one gateway per client) is the root complication. A future
**single shared gateway daemon** that all clients attach to would collapse HITL (one
broker, one `ConfirmGuard`) and simplify audit/attribution too. Out of scope here, but the
broker design is a stepping stone toward it.
