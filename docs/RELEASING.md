# Releasing

Releases are built by CI on a version tag (`.github/workflows/release.yml`).

1. Bump the version to match the tag in:
   - `src-tauri/tauri.conf.json` (`version`), drives the installer filename
   - `src-tauri/Cargo.toml` (`version`)
   - `package.json` (`version`)
   - `src-tauri/Cargo.lock` (run `cargo check` after bumping `Cargo.toml` to refresh it)
   - `server.json` only when publishing a matching standalone `@tsouth89/conduit-gateway` package
2. Commit the bump.
3. Tag and push:

   ```bash
   git tag v0.2.0
   git push origin v0.2.0
   ```

CI builds installers for **Windows** (NSIS), **macOS** (dmg), and **Linux**
(deb + AppImage), each with the gateway bundled, and attaches them to a **draft**
release with auto-generated notes. Review it on the Releases page and click
**Publish**.

## Manual fallback

If you'd rather build locally:

```bash
npm run tauri:bundle
gh release create v0.2.0 \
  "src-tauri/target/release/bundle/nsis/Toolport_0.2.0_x64-setup.exe" \
  --title "Toolport v0.2.0" --generate-notes
```

## Signing

macOS installers are signed and notarized, and Windows installers are signed via
Azure Trusted Signing (when the `AZURE_*` secrets/variables are set; otherwise the
Windows build falls back to unsigned). Windows uses a standard certificate, so
SmartScreen reputation still accrues with downloads. See [SIGNING.md](SIGNING.md)
for details.
