#!/usr/bin/env bash
# Off-chain timings of all schemes; writes results/timings.csv.
# Extra arguments are passed on, e.g. `--n 5,10 --iters 50 --scheme icy-n`.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
mkdir -p "$ROOT/results"
cd "$ROOT/advrf"
cargo run --quiet --release --bin timings -- "$@" | tee "$ROOT/results/timings.csv"
cargo run --quiet --release --bin timings_report -- "$ROOT/results/timings.csv" "$ROOT/results/timings.md" > /dev/null
