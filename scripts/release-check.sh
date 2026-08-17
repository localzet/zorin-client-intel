#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

echo "[1/6] JavaScript syntax"
node --check web/probe.js

echo "[2/6] Shell syntax"
bash -n scripts/*.sh sensors/linux-tcp/entrypoint.sh

echo "[3/6] Rust formatting"
cargo fmt --all -- --check

echo "[4/6] Rust lint"
cargo clippy --workspace --all-targets -- -D warnings

echo "[5/6] Rust tests"
cargo test --workspace

echo "[6/6] Release build"
cargo build --release -p client-intel-collector

echo "Release checks passed."
