# Windows: MSIX filesystem virtualization vs the gateway data dir

Regression note for a real bug found 2026-07-05. Keep this in mind whenever a
path under `%USERPROFILE%\AppData` is shared between the Toolport app and a
client-spawned gateway.

## The bug

When `toolport-gateway` is spawned by an MSIX-packaged client (e.g. the Claude
desktop app, package id `Claude_pzs8sxrjxfjjc`), the child process inherits the
package's app container, and Windows MSIX filesystem virtualization redirects
opens under `%USERPROFILE%\AppData\Roaming\Conduit` to the package's shadow
copy:

```
C:\Users\<user>\AppData\Local\Packages\<pkg>\LocalCache\Roaming\Conduit
```

The shadow can be days stale. Observed effects:

1. The gateway read a frozen `registry.json`, so server/profile changes made in
   the app never reached Claude-spawned gateways (the mtime watcher watched the
   frozen shadow too).
2. The gateway read a stale `approval-endpoint.json` pointing at a dead broker
   port, so with "Require human approval" enabled every gated call fail-closed
   as "not approved in time" and the approval UI never appeared.

## The wrong assumption (do not reintroduce it)

An earlier `conduit_dir()` comment claimed home-derived paths (spelling out
`\AppData\Roaming` from the profile dir instead of using the `APPDATA` known
folder) are not redirected by MSIX. That is empirically false: the redirect is
a filesystem _filter_ keyed on the target path at open time, not on how the
path string was derived. Verified by writing a probe file to `%APPDATA%` from
inside the Claude container and finding it in the package `LocalCache`.

## The fix (`registry::conduit_dir`)

- Detect containerization once per process via `GetCurrentPackageFamilyName`:
  Conduit's own binaries never ship as MSIX, so package identity always means
  "spawned inside another app's container".
- When containerized, address the same directory through its loopback-UNC twin,
  `\\localhost\C$\Users\<user>\AppData\Roaming\Conduit`. SMB serves those opens
  from the real filesystem, outside the virtualization filter (verified on the
  affected machine). Reachability is probed against the profile dir first; if
  the UNC view is unavailable the natural path is kept (no worse than before)
  and the gateway logs a loud warning plus a `dir_resolution=VirtualizedFallback`
  line in `gateway.log`.
- Everything derives from `conduit_dir()` (registry + its watcher, tool cache,
  approval endpoint descriptor, audit/security logs, secrets file), so the
  de-virtualization covers all of them. `CONDUIT_REGISTRY` still overrides the
  registry path explicitly.

## Manual test plan

From a shell running _inside_ an MSIX app container (e.g. `Invoke-CommandInDesktopPackage`,
or any shell spawned by the packaged client):

1. Spawn `toolport-gateway` and check `gateway.log` for
   `dir_resolution=Devirtualized` and a `\\localhost\C$\...` registry path.
2. Change a server/profile in the Toolport app; confirm the containerized
   gateway's watcher picks it up (tools/list changes within the poll interval).
3. Restart the Toolport app (fresh approval broker port), trigger a destructive
   call through the containerized gateway with "Require human approval" on, and
   confirm the approval prompt appears and an Approve routes the call.
