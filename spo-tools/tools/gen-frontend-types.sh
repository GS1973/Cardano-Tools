#!/usr/bin/env bash
# Regenerate the SPO frontend wire types and re-point the role-neutral
# types at the @airgap-core/frontend package.
#
# ts_rs resolves each type's `export_to` path relative to the *consuming*
# crate, so a neutral type that lives in airgap-core but is referenced by
# the SPO crates gets re-written into scattered locations and the cross-file
# import is a (broken) relative path. A plain `cargo test --workspace` runs
# the export tests in parallel, which both truncates the per-type file (a
# write race) and leaves the broken relative import — never commit those.
# The committed bindings are produced ONLY by this script, which:
#   0. refreshes airgap-core's canonical core-wire.ts (the neutral types),
#   1. regenerates the SPO bindings single-threaded (no truncation race),
#   2. re-points the neutral import at the @airgap-core/frontend package alias,
#   3. deletes the ts_rs cross-crate scatter (not consumed; served by the
#      package instead).
#
# The role-neutral types are re-exported by the hand-written
# shared-frontend/src/types/core.ts (a stable surface ts_rs never rewrites),
# so this script does not append a facade to the generated wire.ts.
#
# Pass --check to verify the committed bindings are in sync with the Rust
# source instead of rewriting them: it regenerates the SPO bindings, diffs
# them against the working tree, restores the tree, and exits non-zero on
# drift. Run it locally before committing a wire-type change; it is also
# the command CI's "Frontend type-binding drift" step runs. That step lives
# in the build-test job, which is gated behind the AIRGAP_CORE_WIRED
# repository variable until airgap-core is published and checked out
# alongside this repo.
set -euo pipefail
cd "$(dirname "$0")/.."

CHECK=0
if [[ "${1:-}" == "--check" ]]; then
  CHECK=1
fi

WIRE=shared-frontend/src/types/wire.ts
HANDLERS=shared-frontend/src/types/handlers.ts
ALIAS='@airgap-core/frontend/types/core-wire'

if [[ "$CHECK" == "1" ]]; then
  # SPO-scoped sync check: regenerate just the SPO bindings (the neutral
  # airgap-core types are imported via the package alias, not re-derived
  # here), compare, and leave the working tree untouched.
  cargo test --quiet export_bindings -- --test-threads=1 >/dev/null
  sed -i -E "s#from \"[^\"]*core-wire\"#from \"$ALIAS\"#" "$WIRE" "$HANDLERS"
  rm -rf shared/frontend online-tool/frontend/src/types/core-wire.ts signer/frontend/src/types/core-wire.ts
  if ! git diff --quiet -- "$WIRE" "$HANDLERS"; then
    echo "ERROR: committed frontend wire types are out of sync with the Rust source." >&2
    echo "Run tools/gen-frontend-types.sh and commit the regenerated bindings." >&2
    git --no-pager diff -- "$WIRE" "$HANDLERS" >&2
    git checkout -- "$WIRE" "$HANDLERS"
    exit 1
  fi
  echo "Frontend wire types are in sync with the Rust source."
  exit 0
fi

# 0. Canonical neutral types live in airgap-core.
( cd ../airgap-core && cargo test --quiet export_bindings -- --test-threads=1 >/dev/null )

# 1. Regenerate SPO bindings (single-threaded: avoid the same-file truncation race).
cargo test --quiet export_bindings -- --test-threads=1 >/dev/null

# 2. Re-point neutral imports at the package alias.
sed -i -E "s#from \"[^\"]*core-wire\"#from \"$ALIAS\"#" "$WIRE" "$HANDLERS"

# 3. Remove the ts_rs cross-crate scatter.
rm -rf shared/frontend online-tool/frontend/src/types/core-wire.ts signer/frontend/src/types/core-wire.ts

echo "Frontend wire types regenerated and re-pointed at $ALIAS."
