# akivili — Plugin SDK for celestia-island

> Named after Akivili, the Trailblaze Aeon from *Honkai: Star Rail* — the spirit of
> trailblazing third-party agent ecosystems.

`akivili` is the standalone plugin SDK extracted from `entelecheia`: the agent plugin
host and the TypeScript execution pipeline that powers Layer-3 community agents.

## What it provides

- **Plugin host** (`packages/plugin_host`) — loads and dispatches TypeScript plugins
  (`handleRequest` / `onMessage` / `name` globals) on the Boa JS engine, with host
  capabilities injected via `dispatch` / `registerMcpTool`.
- **TypeScript execution pipeline** (`packages/iepl`) — TS→JS transpilation with SWC
  plus AST safety validation, shared with the IEPL engine consumers.
- **Plugin contract** — the effective TS global API contract
  (`handleRequest` / `onMessage` / `dispatch` / `registerMcpTool` /
  `__plugin_state`) documented in `docs/architecture.md`.

## Where plugins live

Plugins are defined inside a project's `.amphoreus/` directory (agent manifests,
`plugin.ts` sources, and the Layer-3 subscription config), mirroring the role
CLAUDE.md / AGENTS.md play for agent configuration.

## License

SySL-1.0 — see [LICENSE](LICENSE).

## Repository layout

```
packages/plugin_host/   plugin host core (Boa TS runtime, router, state)
packages/iepl/          TypeScript → JavaScript pipeline (SWC + Boa)
docs/                   architecture & contract documentation
res/logo/               brand assets (temporary celestia-island logo)
```

Development flows on the `dev` branch; `master` holds reviewed, squashed merges.
