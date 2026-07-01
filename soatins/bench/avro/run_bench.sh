#!/usr/bin/env bash
# Build and run the four Avro-writer benchmarks (C++/avro_glue, C/avro-c, Rust/apache-avro, Python/fastavro)
# against the same WideRow schema and row formula, then verify every output file with fastavro. See
# README.md for prerequisites, what's being compared, and why.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SOATINS_INCLUDE="$SCRIPT_DIR/../../include"
N="${1:-500000}"
OUT_DIR="$(mktemp -d)"
trap 'rm -rf "$OUT_DIR"' EXIT

echo "== building =="
g++ -std=c++20 -O2 -I "$SOATINS_INCLUDE" "$SCRIPT_DIR/bench_cpp.cpp" -o "$OUT_DIR/bench_cpp"
gcc -O2 "$SCRIPT_DIR/bench_c.c" -o "$OUT_DIR/bench_c" -lavro
(cd "$SCRIPT_DIR/bench_rust" && cargo build --release --quiet)

echo "== running ($N rows) =="
cpp_out="$("$OUT_DIR/bench_cpp" "$OUT_DIR/out_cpp.avro" "$N")"; echo "$cpp_out"
c_out="$("$OUT_DIR/bench_c" "$OUT_DIR/out_c.avro" "$N")"; echo "$c_out"
rust_out="$("$SCRIPT_DIR/bench_rust/target/release/bench_rust" "$OUT_DIR/out_rust.avro" "$N")"; echo "$rust_out"
python_out="$(python3 "$SCRIPT_DIR/bench_python.py" "$OUT_DIR/out_python.avro" "$N")"; echo "$python_out"

echo "== verifying (fastavro cross-check) =="
python3 "$SCRIPT_DIR/verify.py" "$N" "$OUT_DIR/out_cpp.avro" "$OUT_DIR/out_c.avro" "$OUT_DIR/out_rust.avro" "$OUT_DIR/out_python.avro"

# Only reached if verify.py exited 0 (set -e above) -- a result never lands in the README unverified.
echo "== updating README =="
python3 "$SCRIPT_DIR/update_readme.py" --n "$N" --cpp "$cpp_out" --c "$c_out" --rust "$rust_out" --python "$python_out"
