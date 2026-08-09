# Changelog

## [Unreleased]

### Fix

- Remove the unused `async-trait` workspace dependency
- Rebuild the HTTP client when `with_network_guard` changes so the redirect
  policy uses the same guard as the pre-request check
- Track plana dependencies on the `master` branch (AGENTS.md §2.2)

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

### Security

- Port sandbox validation from entelecheia wave 2: run `validate_js` on both
  transpiled and plain JS plugin code before evaluation
- Apply the egress guard to the plugin HTTP client (connect timeout + redirect
  policy re-checking every hop against the guard allow-list)
