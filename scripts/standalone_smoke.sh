#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Yoav Bendor
#
# Dependency-light smoke runner for the header-only parsing core — builds and runs the tests that need
# nothing but the nanotins + soatins include trees (no nanoarrow / boost / stdexec FetchContent). This is
# the path that works in a sealed sandbox or an offline CI runner where FetchContent can't reach GitHub;
# the full suite (incl. the Arrow/bulk paths) is built the canonical way by the `cmake-smoke` CI job.
#
# Usage:
#   scripts/standalone_smoke.sh
#
# The bulk determinism tests additionally need stdexec + nanoarrow + boost headers. They are built and run
# only when those include directories are supplied via env (space-separated -I-ready paths), e.g.:
#   STDEXEC_INC=/path/stdexec/include NANOARROW_INC=/path/nanoarrow/src \
#   BOOST_INC="/path/describe/include /path/mp11/include ..." scripts/standalone_smoke.sh

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CXX="${CXX:-g++}"
CXXSTD="${CXXSTD:--std=c++20}"
OUT="$(mktemp -d)"
trap 'rm -rf "$OUT"' EXIT

INC=(-I "$ROOT/nanotins/include" -I "$ROOT/soatins/include")

run_test() {  # name source [extra g++ args...]
    local name="$1" src="$2"; shift 2
    echo "=== building $name ==="
    "$CXX" $CXXSTD -O1 "${INC[@]}" "$@" "$ROOT/nanotins/tests/$src" -o "$OUT/$name"
    "$OUT/$name"
}

# --- zero-dependency tests (header-only, no external libs) -------------------------------------------
run_test tlv_cursor      test_tlv_cursor.cpp
run_test ipv4_options    test_ipv4_options.cpp
run_test ipv6_children   test_ipv6_children.cpp
run_test someip          test_someip.cpp
run_test someip_sd       test_someip_sd.cpp

# --- bulk determinism tests (only when stdexec + nanoarrow + boost headers are provided) -------------
if [[ -n "${STDEXEC_INC:-}" && -n "${NANOARROW_INC:-}" && -n "${BOOST_INC:-}" ]]; then
    EXTRA=(-pthread -I "$STDEXEC_INC" -I "$NANOARROW_INC")
    for b in $BOOST_INC; do EXTRA+=(-I "$b"); done
    run_test ipv4_options_bulk  test_ipv4_options_bulk.cpp  "${EXTRA[@]}"
    run_test ipv6_children_bulk test_ipv6_children_bulk.cpp "${EXTRA[@]}"
else
    echo "note: skipping bulk tests (set STDEXEC_INC / NANOARROW_INC / BOOST_INC to enable them here;"
    echo "      they are covered by the cmake-smoke CI job in any case)."
fi

echo "standalone_smoke: ok"
