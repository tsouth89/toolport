# Contributing to Conduit

Thanks for your interest. Conduit is a local-first MCP gateway and manager: a
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

## Layout

- `src/` - React/TypeScript frontend (the app UI).
- `src-tauri/src/` - Rust backend:
  - `lib.rs` - Tauri commands (the bridge between UI and backend).
  - `registry.rs` - the server/profile registry (Conduit's source of truth).
  - `clients.rs` - detecting and editing AI client configs.
  - `downstream.rs` - talking to MCP servers (stdio + http transports).
  - `router.rs` - aggregating tools/resources and routing calls.
  - `oauth.rs` / `secrets.rs` / `remote.rs` - auth and the OS keychain.
  - `catalog.rs` - the curated + registry server catalog.
  - `bin/conduit-gateway.rs` - the gateway binary clients connect to.

## Before you open a PR

```bash
# backend
cargo test --manifest-path src-tauri/Cargo.toml
# frontend
npx tsc --noEmit && npm run build
```

Please match the surrounding style: the code favors small, well-commented
functions that explain the *why*. Keep comments at the density of the file you're
editing.

## Good places to start

- New curated catalog entries (real, verified MCP servers) in `catalog.rs`.
- Additional client support in `clients.rs` (a new AI tool's config format).
- Frontend polish: empty states, error messages, keyboard shortcuts.
- Tests for any of the above.

## Sign your commits (DCO)

Conduit uses the [Developer Certificate of Origin](https://developercertificate.org/)
(DCO): a lightweight way to state that you wrote the contribution and have the
right to submit it. There is **no copyright assignment**, you keep ownership of
your work.

Just add a `Signed-off-by` line to each commit with `git commit -s`:

```
Signed-off-by: Your Name <your@email.com>
```

That line means you agree to the DCO. That's all there is to it.

## Reporting issues

Bugs and ideas are welcome in [Issues](https://github.com/tsouth89/conduit/issues).
For security problems, see [SECURITY.md](SECURITY.md) (report privately, please).

## License

By contributing you agree your contributions are licensed under the repository's
[MIT license](LICENSE), which is and will remain the license for this repo (the
app and gateway). Conduit is open-core: the separate commercial Conduit Teams
server, under its own license, is what funds this free and open core.
