# akivili — plugin SDK workspace.
#
# Shared celestia-devtools recipes — NOT in git. Stage with: just fetch.
# `import?` silently skips when absent, so this justfile parses pre-fetch.
import? "./.just/git-bash-interop.just"
import? "./.just/celestia-devtools.just"

set shell := ["bash", "-c"]
set windows-shell := ["bash.exe", "-c"]
set unstable
set lists

# Stage shared celestia-devtools recipes into .just/ (gitignored).
[script('bash')]
fetch URL='':
    #!/usr/bin/env bash
    set -euo pipefail
    out=.just/celestia-devtools.just
    mkdir -p .just
    if [ -n "{{URL}}" ]; then
      echo "[fetch] {{URL}} -> $out"
      curl -fsSL "{{URL}}" -o "$out"
    elif command -v celestia-devtools >/dev/null 2>&1; then
      src=$(celestia-devtools include-path)
      echo "[fetch] local celestia-devtools include -> $out"
      cp "$src/celestia-devtools.just" "$out"
    else
      echo "[fetch] fetching from GitHub raw"
      curl -fsSL https://raw.githubusercontent.com/celestia-island/celestia-devtools/master/src/celestia_devtools/recipes/celestia-devtools.just -o "$out"
    fi
    echo "[fetch] staged $out"

# Local recipes (no external dependencies)
check:
    cargo check --workspace --all-targets

fmt:
    cargo fmt --all

lint:
    cargo clippy --workspace --lib --bins -- -D warnings

test:
    cargo test --workspace
