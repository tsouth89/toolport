# Contributing to Toolport

Thanks for your interest. Toolport is a local-first MCP gateway and manager: a
Tauri desktop app (Rust backend + React/TypeScript frontend) plus a separate
`conduit-gateway` binary that AI clients spawn.

Want to ask a question, float an idea, or talk through a change before you build
it? Join the [Discord](https://discord.gg/Xsn27MxdBA). New contributors welcome,
and we merge community PRs regularly.

## Quick start

Requires Node 20+ and the Rust toolchain.

```bash
npm install
npm run build:gateway   # build the gateway binary (clients spawn it; needed when running from source)
npm run tauri dev       # run the desktop app
```

On macOS/Linux, see the platform notes in the [README troubleshooting](README.md#troubleshooting).

## Development workflow

### What hot-reloads vs what needs a rebuild

| You changed                                             | What happens                                                                                                                                |
| ------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------- |
| React/TS frontend (`src/`)                              | Vite hot-reloads instantly — no restart needed                                                                                              |
| Rust backend (`src-tauri/src/`)                         | `npm run tauri dev` recompiles and restarts the app automatically                                                                           |
| Gateway binary (`src-tauri/src/bin/conduit-gateway.rs`) | **Not rebuilt by `tauri dev`.** Run `npm run build:gateway` after changes, then restart any connected clients so they re-spawn the gateway. |

The gateway is a separate binary that AI clients spawn as a subprocess. Packaged
releases bundle it, but when running from source you must build it manually:

```bash
npm run build:gateway   # one-time, or after gateway code changes
```

If a client reports the gateway "was not found," you forgot this step.

### Running tests

```bash
# Backend (Rust)
cargo test --manifest-path src-tauri/Cargo.toml

# Frontend unit tests (Vitest)
npm run test

# Frontend type-check + build
npx tsc --noEmit && npm run build
```

The Rust suite includes unit tests in each module (`clients`, `catalog`,
`registry`, `router`, `oauth`, etc.) and an integration test
(`tests/list_changed.rs`) that exercises the gateway's live tool-change
notification path. Frontend tests use [Vitest](https://vitest.dev) and live
alongside the code as `*.test.ts` files inside `src/`.

### Formatting

Prettier enforces consistent formatting across the frontend and docs. The CI
checks this on every PR, but you can fix issues locally before pushing:

```bash
npm run format        # format all files in place
npm run format:check  # check only (fails without writing — same as CI)
```

### Linting

ESLint catches code-quality issues and React anti-patterns. The CI runs it on
every PR:

```bash
npm run lint        # check
npm run lint:fix    # auto-fix what it can
```

Warnings are non-blocking. If you see a `react-hooks/set-state-in-effect`
warning, it's usually the standard Tauri pattern of loading data from the Rust
backend in a `useEffect` — review it for unnecessary re-renders, but it won't
block the build.

### Debugging

**Gateway verbose logging:** the gateway writes an always-on log (connection
lifecycle events) to a file in Toolport's data directory. Set `CONDUIT_DEBUG=1`
to also capture per-request traces (tool-call arguments, routing decisions,
downstream responses). "Copy diagnostics" in the app bundles this log with
version info and a registry summary for bug reports.

```bash
CONDUIT_DEBUG=1 npm run tauri dev
```

**Registry file:** stored at a stable per-user path (visible via "Open data dir"
in the app). The gateway watches this file and rebuilds live, so toggling a
server in the UI takes effect without restarting the client.

### Common gotchas

- **Gateway "not found" when running from source.** `npm run tauri dev` builds
  the app but not the gateway sidecar. Run `npm run build:gateway` once (and
  again after any change to `conduit-gateway.rs`).

- **macOS keychain prompts in dev.** An unsigned dev build gets an unstable
  code-signing identity, so the keychain re-prompts or denies reads. A signed
  release fixes this.

- **Linux: secrets fail without a keyring.** Secret storage uses the freedesktop
  Secret Service (libsecret). A headless box or a session without a running
  keyring daemon has nowhere to store secrets. Run in a desktop session with
  GNOME Keyring or KWallet unlocked.

For end-user troubleshooting (OAuth, AppImage, VS Code), see the
[README troubleshooting section](README.md#troubleshooting).

## Layout

- `src/` - React/TypeScript frontend (the app UI).
- `src-tauri/src/` - Rust backend:
  - `lib.rs` - Tauri commands (the bridge between UI and backend).
  - `registry.rs` - the server/profile registry (Toolport's source of truth).
  - `clients.rs` - detecting and editing AI client configs.
  - `downstream.rs` - talking to MCP servers (stdio + http transports).
  - `router.rs` - aggregating tools/resources and routing calls.
  - `oauth.rs` / `secrets.rs` / `remote.rs` - auth and the OS keychain.
  - `catalog.rs` - the curated + registry server catalog.
  - `bin/conduit-gateway.rs` - the gateway binary clients connect to.

## Before you open a PR

Run the [tests described above](#running-tests). Please match the surrounding
style: the code favors small, well-commented functions that explain the _why_.
Keep comments at the density of the file you're editing.

## Good places to start

- New curated catalog entries (real, verified MCP servers) in `catalog.rs`.
- Additional client support in `clients.rs` (a new AI tool's config format).
- Frontend polish: empty states, error messages, keyboard shortcuts.
- Tests for any of the above.

## Adding a curated catalog entry

The catalog is a hand-verified list of popular MCP servers in
`src-tauri/src/catalog.rs`. Each entry becomes a one-click "Add" button in the
browse view. Two helpers cover every case:

### Remote (HTTP/SSE) servers

Use the `http()` helper inside `curated()`:

```rust
http("My Service", "What it does, in one line.", "https://mcp.example.com/mcp", "https://example.com/docs"),
```

That's it — the URL is the server endpoint. Most hosted MCPs use streamable-http.

### Local (stdio) servers

Use the `cmd()` helper:

```rust
cmd("My Tool", "What it does.", "npx", &["-y", "@scope/package-name"], &["API_KEY"], "https://github.com/org/repo"),
```

- `command` — the executable (`npx`, `uvx`, `node`, etc.)
- `args` — passed as-is to the command
- `env` — **names only** (e.g. `&["API_KEY"]`). Values are vaulted in the OS
  keychain at runtime; never hardcode them here. An empty `&[]` means no auth.
- `homepage` — link to docs/source so users can learn more

### After adding the entry

1. **Add a category** in `category_for()` so the entry groups correctly in the
   browse view (e.g. `"Databases"`, `"Search & knowledge"`). Entries without a
   category appear flat in search.

2. **Add credential guidance** (optional) in `credentials_for()`. This powers the
   guided "go get your creds" step. Return `(url, hint)` where `url` is a direct
   link to the provider's token page, or `""` if there's no single page (OAuth,
   connection strings, or no auth). Return `None` if you have no guidance.

3. **Verify it runs.** Add the server in the app (or via the catalog search) and
   confirm it connects and exposes tools. If it needs an API key, enter one and
   check the probe succeeds.

4. **Run the tests:**

```bash
cargo test --manifest-path src-tauri/Cargo.toml catalog
```

The catalog tests verify every curated entry has a non-empty name, a valid
target (URL or command), and a browse-view category — your new entry will be
checked automatically.

**Reference PR:** [#19](https://github.com/tsouth89/toolport/pull/19) (Firecrawl
catalog entry — a single `cmd()` line + category).

## Adding a new client

Clients are AI tools that store MCP server configs on disk. Toolport detects each
client, reads its servers, and can install/write the gateway entry. All of this
is in `src-tauri/src/clients.rs`.

### 1. Identify the format

Check the client's config file and match it to a `Format` variant:

| Format               | Config shape                                       | Existing clients                 |
| -------------------- | -------------------------------------------------- | -------------------------------- |
| `JsonMcpServers`     | `{"mcpServers": {...}}`                            | Claude Desktop, Cursor, Windsurf |
| `JsonServers`        | `{"servers": {...}}`                               | VS Code                          |
| `JsonContextServers` | `{"context_servers": {...}}` (JSONC)               | Zed                              |
| `TomlMcpServers`     | `[mcp_servers.name]`                               | Codex                            |
| `YamlExtensions`     | `extensions:` map (Goose shape: `cmd`/`envs`)      | Goose                            |
| `YamlMcpServers`     | `mcp_servers:` map (Hermes shape: `command`/`env`) | Hermes                           |
| `YamlMcpServersList` | `mcpServers:` list                                 | Continue                         |

If the client uses a genuinely new format, add a variant to `enum Format` and a
parse function (follow the pattern of `parse_json` or `parse_toml`).

### 2. Add a path resolver

Add a function that returns the config file path:

```rust
fn my_client_path() -> Option<PathBuf> {
    // Most clients keep config under ~/.<name>/ or ~/Library/Application Support/.
    // Use home() for ~/. paths; see existing resolvers like cursor_path() or
    // vscode_path() for patterns. Always anchor to home_dir, not env vars.
    Some(home()?.join(".my-client").join("config.json"))
}
```

**Important:** the config file's parent directory is used as the "app installed?"
heuristic. If the parent is too broad (like `~` itself) or too narrow (only
created after first MCP use), add an entry to `install_override()`.

### 3. Register the client

Add a `ClientDef` to the `defs()` list:

```rust
ClientDef {
    id: "my-client",              // stable identifier, lowercase-kebab
    name: "My Client",            // display name
    format: Format::JsonMcpServers, // from step 1
    uses_connectors: false,       // true only for UI-managed clients (Claude Desktop)
    path: my_client_path,         // from step 2
    plugin_scan: None,            // Some(fn) only if the client has out-of-config servers
},
```

### 4. Add tests

Follow the existing conventions — at minimum:

- A registration test confirming the client appears in `defs()` with the right
  format:

  ```rust
  #[test]
  fn my_client_is_registered() {
      let d = defs().into_iter().find(|d| d.id == "my-client").unwrap();
      assert!(matches!(d.format, Format::JsonMcpServers));
      assert!((d.path)().is_some());
  }
  ```

- A path stability test (only if the path logic is non-trivial). See
  `client_config_paths_are_stable_across_platforms` for the pattern.

- A round-trip test if you added a new `Format` variant: write servers → read
  them back → verify they match. See `json_mcpservers_round_trips` for the
  pattern.

### 5. Verify

```bash
cargo test --manifest-path src-tauri/Cargo.toml clients
npm run tauri dev   # check the client appears in the sidebar
```

**Reference PR:** [#18](https://github.com/tsouth89/toolport/pull/18) (BoltAI
client — a path resolver, one `ClientDef`, and a registration test).

## Sign your commits (DCO)

Toolport uses the [Developer Certificate of Origin](https://developercertificate.org/)
(DCO): a lightweight way to state that you wrote the contribution and have the
right to submit it. There is **no copyright assignment**, you keep ownership of
your work.

Just add a `Signed-off-by` line to each commit with `git commit -s`:

```
Signed-off-by: Your Name <your@email.com>
```

That line means you agree to the DCO. That's all there is to it.

## Reporting issues

Bugs and ideas are welcome in [Issues](https://github.com/tsouth89/toolport/issues).
For security problems, see [SECURITY.md](SECURITY.md) (report privately, please).

## License

By contributing you agree your contributions are licensed under the repository's
[MIT license](LICENSE), which is and will remain the license for this repo (the
app and gateway). Toolport is open-core: the separate commercial Toolport Teams
server, under its own license, is what funds this free and open core.
