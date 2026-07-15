#!/usr/bin/env bash
# Regenerate the DRep frontend wire types and re-point the role-neutral
# types at the @airgap-core/frontend package.
#
# ts_rs resolves each type's `export_to` path relative to the *consuming*
# crate, so the neutral airgap-core types (ChainContext, UtxoInput)
# referenced by `shared`'s wire types get re-written into
# shared/frontend/src/types/core-wire.ts and the cross-file import in
# wire.ts is a (broken) relative path. A plain `cargo test --workspace`
# runs the export tests in parallel, which both truncates the per-type
# file (a write race) and leaves the broken relative import — never commit
# those. The committed bindings are produced ONLY by this script, which:
#   0. refreshes airgap-core's canonical core-wire.ts (the neutral types),
#   1. regenerates the DRep bindings single-threaded (no truncation race),
#   2. re-points the neutral import at the @airgap-core/frontend package alias.
#
# Unlike spo-tools, the ts_rs cross-crate scatter
# (shared/frontend/src/types/core-wire.ts) is a committed snapshot in this
# repo, so it is regenerated in place rather than deleted, and the --check
# mode diffs it too — a drift between the snapshot and airgap-core's Rust
# source fails the check.
#
# The role-neutral error types are re-exported by the hand-written
# shared-frontend/src/types/errors.ts (a stable surface ts_rs never
# rewrites), so this script does not append a facade to the generated
# wire.ts.
#
# Pass --check to verify the committed bindings are in sync with the Rust
# source instead of rewriting them: it regenerates the DRep bindings, diffs
# them against the working tree, restores the tree, and exits non-zero on
# drift. Run it locally before committing a wire-type change; it is also
# the command CI's "Frontend type-binding drift" step runs (airgap-core is
# a path dependency, so it is already checked out alongside this repo).
set -euo pipefail
cd "$(dirname "$0")/.."

CHECK=0
if [[ "${1:-}" == "--check" ]]; then
  CHECK=1
fi

WIRE=shared-frontend/src/types/wire.ts
CORE=shared/frontend/src/types/core-wire.ts
ALIAS='@airgap-core/frontend/types/core-wire'

if [[ "$CHECK" == "1" ]]; then
  # DRep-scoped sync check: regenerate just the DRep bindings (the neutral
  # airgap-core types are re-derived into the committed snapshot as a side
  # effect, which is exactly the drift this check guards), compare, and
  # leave the working tree untouched.
  cargo test --quiet export_bindings -- --test-threads=1 >/dev/null
  sed -i -E "s#from \"[^\"]*core-wire\"#from \"$ALIAS\"#" "$WIRE"
  if ! git diff --quiet -- "$WIRE" "$CORE"; then
    echo "ERROR: committed frontend wire types are out of sync with the Rust source." >&2
    echo "Run tools/gen-frontend-types.sh and commit the regenerated bindings." >&2
    git --no-pager diff -- "$WIRE" "$CORE" >&2
    git checkout -- "$WIRE" "$CORE"
    exit 1
  fi
  echo "Frontend wire types are in sync with the Rust source."
  exit 0
fi

# 0. Canonical neutral types live in airgap-core.
( cd ../airgap-core && cargo test --quiet export_bindings -- --test-threads=1 >/dev/null )

# 1. Regenerate DRep bindings (single-threaded: avoid the same-file truncation race).
cargo test --quiet export_bindings -- --test-threads=1 >/dev/null

# 2. Re-point neutral imports at the package alias.
sed -i -E "s#from \"[^\"]*core-wire\"#from \"$ALIAS\"#" "$WIRE"

echo "Frontend wire types regenerated and re-pointed at $ALIAS."
