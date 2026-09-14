# akivili — Plugin SDK for celestia-island

> Named after Akivili, the Trailblaze Aeon from *Honkai: Star Rail* — the spirit of
> trailblazing third-party agent ecosystems.

`akivili` is the standalone plugin SDK extracted from `entelecheia`: the agent plugin
host, the TypeScript execution pipeline, and the plugin registry that powers
Layer-3 community agents.

## What it provides

- **Plugin host** (`packages/plugin_host`) — loads and dispatches TypeScript plugins
  (`handleRequest` / `onMessage` / `name` globals) on the Boa JS engine, with host
  capabilities injected via `dispatch` / `registerMcpTool`.
- **TypeScript execution pipeline** (`packages/iepl`) — TS→JS transpilation with SWC
  plus AST safety validation, shared with the IEPL engine consumers.
- **Plugin registry** (`packages/registry`) — discoverable, uninstallable, auditable
  plugin resources for any host runtime (detailed below), plus the
  `akivili-plugin` CLI for humans and ops.
- **Egress network guard** (`packages/guard`) — URL/IP policy enforcement for
  outbound HTTP with DNS-rebinding-safe resolution, dependency-light so service
  crates can consume it without pulling in the Boa runtime.
- **Plugin contract** — the effective TS global API contract
  (`handleRequest` / `onMessage` / `dispatch` / `registerMcpTool` /
  `__plugin_state`) documented in `docs/architecture.md`.

## Where plugins live

Plugins are defined inside a project's `.amphoreus/` directory (agent manifests,
`plugin.ts` sources, and the Layer-3 subscription config), mirroring the role
CLAUDE.md / AGENTS.md play for agent configuration.

## The plugin registry (`akivili_registry`)

The registry unifies scattered extension mechanisms behind one model: hosts
declare *what plugin resources they accept* (`HostAcceptance`), plugin management
lives in the registry (`Registry`), and hosts are *fed* an ordered series of
resources at startup which they load one by one (`ResourceFeed` → `ResourceHandle`).

- **Manifests** — a plugin store is a plain root directory with one subdirectory
  per plugin, each described by an `akivili.plugin.toml` manifest: `id`
  (`^[a-z0-9]+$`, unique), `version`, `provider`, and a list of resource entries
  (`kind`, optional `name`, `order`, and an `Inline` JSON or `File` payload with
  optional `sha256`). The enable/disable switch lives in a `registry-state.json`
  at the store root — never inside a plugin directory — so toggling a plugin never
  mutates plugin-owned files, and deleting the subdirectory fully uninstalls it.
- **Feed semantics** — `Registry::feed(&HostAcceptance)` filters enabled plugins'
  entries down to the kinds the host accepts, ordered by `order` (ties broken by
  plugin id, then manifest position). A feed is a snapshot: file payloads are read
  and digested at feed time, so hosts always load exactly the bytes the audit
  trail recorded.
- **Audit** — every discovery, validation, rejection, enable/disable toggle, fed
  item, load, unload, and loud failure lands in an append-only JSONL log (nine
  event classes: `discovered`, `validated`, `rejected`, `enabled`, `disabled`,
  `fed`, `loaded`, `unloaded`, `failed`), flushed per append and fail-loud to open.
- **Resource kinds** — an open set (`^[a-z0-9-]+(\.[a-z0-9-]+)+$`); services may
  define their own kinds without touching this crate. Well-known kinds today:
  `webui.style`, `webui.theme`, `webui.module`, `sandbox.env`, `tool.mcp`.
- **Path confinement** — file payloads are only ever read from inside the owning
  plugin's own directory; absolute paths, `..` walks, and symlink escapes are
  rejected at scan time and re-checked at feed/load time.
- **Runtime-local resources** — in-process registrations
  (`Registry::register_local`, the analogue of the plugin host's
  `registerMcpTool`) never touch the disk store.

The v1 API is deliberately synchronous (`std::fs`) so the crate stays consumable
from any runtime. See the `packages/registry` rustdoc for the full reference.

## The `akivili-plugin` CLI

`akivili-plugin` is a thin shell over the registry library, for humans and ops.
The repository is private (it will not be published to crates.io), so the CLI is
installed from source — this requires members with repo access (GitHub
credentials for `celestia-island/akivili`):

```sh
cargo install --git https://github.com/celestia-island/akivili.git akivili-plugin
```

| Command | Effect |
|---|---|
| `list` | List discovered plugins (id / version / provider / enabled / resources) |
| `check` | Scan and validate the store; exits non-zero on any rejection |
| `enable <id>` | Enable a plugin (recorded in `registry-state.json` and the audit log) |
| `disable <id>` | Disable a plugin |
| `audit [N]` | Show the last N audit events (default 20), oldest first |

Flags: `--store <dir>` (default `./plugins`) and `--audit <path>` (default
`<store>/registry-audit.jsonl`).

`list` opens the registry quietly (no scan replay into the audit log, so listing
does not grow the trail); `check` / `enable` / `disable` keep the full audited
open; `audit` reads the log directly and never opens the registry.

## Store and audit path mapping — read before running against a consumer

The CLI defaults assume a standalone store: `./plugins` with the audit log
embedded at `<store>/registry-audit.jsonl`. Consumers differ —
**shittim-chest** (the main consumer) uses:

- store: `./data/plugins`
- audit: `./data/registry-audit.jsonl` — a **sibling** of the store directory,
  not inside it (chest's `DEFAULT_STORE_DIR` / `DEFAULT_AUDIT_PATH` in
  `packages/core/src/plugin_registry.rs`; both overridable via its `[plugins]`
  config).

Running the CLI bare in chest's working directory goes wrong twice: the default
store `./plugins` does not exist there (the open fails loudly with *"cannot read
plugin store …"*), and passing only `--store ./data/plugins` would derive the
audit path `./data/plugins/registry-audit.jsonl` — forking a second audit trail
*inside* the plugin store that the service never reads. Always pass both flags
explicitly when operating a chest layout:

```sh
akivili-plugin --store ./data/plugins --audit ./data/registry-audit.jsonl list
```

## License

SySL-1.0 — see [LICENSE](LICENSE).

## Repository layout

```
packages/plugin_host/   plugin host core (Boa TS runtime, router, state)
packages/iepl/          TypeScript → JavaScript pipeline (SWC + Boa)
packages/registry/      plugin registry (manifests, feed, audit, akivili-plugin CLI)
packages/guard/         egress network guard (URL/IP policy, DNS-rebinding-safe)
docs/                   architecture & contract documentation
res/logo/               brand assets (temporary celestia-island logo)
```

Development happens on feature branches off `master`; `master` holds reviewed,
squashed merges.
