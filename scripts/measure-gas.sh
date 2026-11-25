#!/usr/bin/env bash
# Measures the gas of every on-chain verifier with real transactions on a
# local anvil node (Osaka rules, EIP-2537 precompiles), then writes
# results/gas.csv and results/gas.md.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PORT="${PORT:-8545}"
# First default anvil account; only used on the local test node.
KEY=0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80

mkdir -p "$ROOT/results"
(cd "$ROOT/advrf" && cargo run --quiet --release --bin vectors -- "$ROOT/vectors")

anvil --hardfork osaka --gas-limit 60000000 --port "$PORT" --silent &
ANVIL=$!
trap 'kill $ANVIL 2>/dev/null || true' EXIT
sleep 2

cd "$ROOT/contracts"
rm -rf broadcast/Measure.s.sol
forge script script/Measure.s.sol --rpc-url "http://127.0.0.1:$PORT" --private-key "$KEY" --broadcast --slow -q
RUN="$(ls broadcast/Measure.s.sol/*/run-latest.json)"

cd "$ROOT/advrf"
cargo run --quiet --release --bin gas_report -- "$ROOT/contracts/$RUN" "$ROOT/results/labels.csv" "$ROOT/results"
