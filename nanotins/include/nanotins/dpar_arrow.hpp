// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Yoav Bendor

#pragma once

// Arrow export for DPAR rule tables. A palette Kind accumulates rows into a `std::vector<Row>`
// (dpar_palette.hpp); each Row is a boost-described struct, so it already maps to a columnar SoA. This
// header turns such a table into an Arrow record batch (a nanoarrow ArrowArray + ArrowSchema) for a
// columnar sink (e.g. the nanolance Lance writer). It is the only DPAR header that pulls in nanoarrow —
// dpar_palette.hpp stays nanoarrow-free — so a consumer that only needs NDJSON never compiles it.
//
// A vector<Row> is row-major, so we materialize it into a vector-backed soatins::soa<Row> (resize +
// store, which applies the reflected be<>/bits<> column conversions) and reuse soatins::to_arrow — the
// same Arrow production path the rest of the stack uses. No bespoke per-column glue.

#include "nanotins/dpar_palette.hpp"

#include "soatins/arrow_glue.hpp"
#include "soatins/reflect.hpp"

#include <nanoarrow/nanoarrow.h>

#include <cstddef>
#include <string>
#include <vector>

namespace nanotins::dpar {

// Struct schema for a rule table's Row (one column per described field). The caller owns `out` and must
// release it with ArrowSchemaRelease/`out.release(&out)`.
template <class Row>
bool table_schema(ArrowSchema& out, std::string& error) {
    return soatins::arrow_schema<Row>(out, error);
}

// Realize a rule table (std::vector<Row>) as an Arrow record batch. The caller owns `out` and must
// release it with `out.release(&out)`. Returns false + `error` on failure (e.g. an unsupported column
// type). An empty table yields a valid zero-length batch.
template <class Row>
bool table_to_arrow(const std::vector<Row>& rows, ArrowArray& out, std::string& error) {
    soatins::soa<Row> s;  // vector-backed (soa_dynamic)
    s.resize(rows.size());
    for (std::size_t i = 0; i < rows.size(); ++i) {
        s.store(i, rows[i]);
    }
    return soatins::to_arrow(s, out, error);
}

}  // namespace nanotins::dpar
