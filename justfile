# akivili — plugin SDK workspace.
#
# Shared celestia-devtools recipes — NOT in git. Stage with: just fetch.
# `import?` silently skips when absent, so this justfile parses pre-fetch.
import? "./.just/celestia-devtools.just"

set shell := ["bash", "-c"]
set windows-shell := ["bash.exe", "-c"]
set unstable
set lists

# Local recipes (no external dependencies)
check:
    cargo check --workspace --all-targets

fmt:
    cargo fmt --all

lint:
    cargo clippy --workspace --lib --bins -- -D warnings

test:
    cargo test --workspace
