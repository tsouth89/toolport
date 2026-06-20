# Releasing

Releases are built by CI on a version tag (`.github/workflows/release.yml`).

1. Bump the version to match the tag in:
   - `src-tauri/tauri.conf.json` (`version`) — drives the installer filename
   - `src-tauri/Cargo.toml` (`version`)
   - `package.json` (`version`)
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
  "src-tauri/target/release/bundle/nsis/conduit_0.2.0_x64-setup.exe" \
  --title "Conduit v0.2.0" --generate-notes
```

## Signing

Installers are currently unsigned (SmartScreen warning). See
[SIGNING.md](SIGNING.md) for the plan and how to wire signing into the build.
