# Changelog

## [0.1.0] - 2026-08-07

### Feat

- Bootstrap the workspace skeleton (workspace layout, CI, docs, licensing)
- Migrate the plugin host (`ts_plugin` / `plugin_router` / `plugin_state`,
  WIT contract, egress guard) and the IEPL TypeScript pipeline (`akivili_iepl`)
  out of entelecheia (PLAN §11)
- Cache the SWC transpile result per plugin so dispatches reuse the compiled JS
  instead of re-transpiling on every call
- Install the ring rustls crypto provider at host construction for the
  `rustls-no-provider` reqwest feature
