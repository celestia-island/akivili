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

# T-F track item 1 (D6, _reports/tairitsu-hikari-wasi-browser-20261121/PLAN.md
# §3-D6): the resolved graph must stay free of the plotters family —
# criterion's default features pull plotters -> plotters-backend/svg, which
# drags bindgen-family edges into the target-independent lock. ptc pins
# criterion to cargo_bench_support only; this recipe is the standing
# assertion that the edge stays gone. Polarity: `cargo tree -i <pkg>` exits 0
# (printing reverse deps) when the package IS in the graph, so a zero exit
# here is the failure.
tf-lock-assert:
    #!/usr/bin/env bash
    set -o pipefail
    bad=0
    # criterion-plot is criterion 0.5.1's MANDATORY dependency (no optional
    # flag — features cannot drop it), but it only pulls cast + itertools,
    # never plotters; it is therefore deliberately NOT in the asserted set.
    for pkg in plotters plotters-backend plotters-svg; do
        if cargo tree --workspace -i "$pkg" >/dev/null 2>&1; then
            echo "FAIL: $pkg is back in the dependency graph:"
            cargo tree --workspace -i "$pkg" 2>/dev/null | head -5
            bad=1
        fi
    done
    if [ "$bad" = 1 ]; then
        echo "T-F lock assertion failed — plotters family must stay out of the graph (D6)."
        exit 1
    fi
    echo "ok: plotters family absent from the resolved graph (3 packages checked)"

test:
    cargo test --workspace
