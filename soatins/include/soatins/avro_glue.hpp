// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Yoav Bendor

#pragma once

// Host-only glue: realize the reflected column list as an Avro record schema (.avsc JSON) + Avro
// binary-encoded bytes, with no external codegen (no avrogencpp, no schema-derived C++ classes).
// Mirrors arrow_glue.hpp's shape: walk `for_each_column<T>`, map each column's `arrow_kind` to an Avro
// type for the schema, and its `elem` to Avro's binary encoding for the row. Avro's binary format carries
// no field tags -- a record is just its fields' encodings concatenated in schema order -- so reflection
// is enough; no separate wire-format/codegen layer is needed.
//
// Caveats (kept out of this first cut; revisit only if a real use needs them): u64 values above
// INT64_MAX wrap when zigzag-encoded as Avro `long` (Avro has no unsigned type), and float/double are
// written via memcpy, which is only correct on little-endian hosts (matching this codebase's existing
// no-swap assumption for host-order scalars elsewhere, e.g. arrow_glue's nt_append_value).

#include "soatins/reflect.hpp"

#include <cstdint>
#include <cstring>
#include <string>
#include <type_traits>
#include <vector>

namespace soatins {

// ---- schema (.avsc JSON) ---------------------------------------------------------------------------

inline std::string avro_type_json(arrow_kind kind, int fixed_width, const std::string& fixed_name) {
    switch (kind) {
        case arrow_kind::i8:
        case arrow_kind::u8:
        case arrow_kind::i16:
        case arrow_kind::u16:
        case arrow_kind::i32: return "\"int\"";
        // u32/i64/u64 all fit (u64 aside from its top-bit values -- see file header) in Avro's 64-bit
        // zigzag "long".
        case arrow_kind::u32:
        case arrow_kind::i64:
        case arrow_kind::u64: return "\"long\"";
        case arrow_kind::f32: return "\"float\"";
        case arrow_kind::f64: return "\"double\"";
        case arrow_kind::boolean: return "\"boolean\"";
        case arrow_kind::string: return "\"string\"";
        case arrow_kind::large_binary: return "\"bytes\"";
        case arrow_kind::fixed_binary:
            return "{\"type\":\"fixed\",\"name\":\"" + fixed_name + "\",\"size\":" +
                   std::to_string(fixed_width) + "}";
    }
    return "\"null\"";
}

// Avro record schema for T: {"type":"record","name":record_name,"fields":[...]}. One JSON field per
// flattened column (bits<> sub-fields included), in declaration order -- the same order the binary
// encoder below writes them in, since Avro's wire format has no field tags to reorder by.
template <class T>
std::string avro_schema_json(const std::string& record_name) {
    std::string out = "{\"type\":\"record\",\"name\":\"" + record_name + "\",\"fields\":[";
    bool first = true;
    for_each_column<T>([&]<std::size_t I, class Col>() {
        if (!first) {
            out += ",";
        }
        first = false;
        const std::string name = Col::name();
        out += "{\"name\":\"" + name +
               "\",\"type\":" + avro_type_json(Col::kind, Col::fixed_width, record_name + "_" + name) + "}";
    });
    out += "]}";
    return out;
}

// ---- binary encoding --------------------------------------------------------------------------------

inline void avro_put_zigzag(std::vector<std::uint8_t>& out, std::int64_t v) {
    std::uint64_t z = (static_cast<std::uint64_t>(v) << 1) ^ static_cast<std::uint64_t>(v >> 63);
    while (z > 0x7f) {
        out.push_back(static_cast<std::uint8_t>((z & 0x7f) | 0x80));
        z >>= 7;
    }
    out.push_back(static_cast<std::uint8_t>(z));
}

template <class Scalar>
void avro_put_le_bytes(std::vector<std::uint8_t>& out, const Scalar& v) {
    unsigned char raw[sizeof(Scalar)];
    std::memcpy(raw, &v, sizeof(Scalar));
    out.insert(out.end(), raw, raw + sizeof(Scalar));
}

// Append one column value's Avro encoding (dispatch by host element type, same style as arrow_glue's
// nt_append_value): zigzag varint for int/long, raw little-endian bytes for float/double, one byte for
// boolean, and the raw N bytes for a fixed-size array (already host-order -- never zigzagged).
template <class Elem>
void avro_append_value(std::vector<std::uint8_t>& out, const Elem& v) {
    if constexpr (std::is_same_v<Elem, bool>) {
        out.push_back(v ? 1 : 0);
    } else if constexpr (std::is_floating_point_v<Elem>) {
        avro_put_le_bytes(out, v);
    } else if constexpr (std::is_signed_v<Elem> || std::is_unsigned_v<Elem>) {
        avro_put_zigzag(out, static_cast<std::int64_t>(v));
    } else {
        // std::array<uint8_t, N> -> Avro `fixed`: raw bytes, no length prefix.
        out.insert(out.end(), v.begin(), v.end());
    }
}

// Avro binary encoding of one row of T: the flattened columns' encodings concatenated in schema order
// (no field tags -- Avro relies on both sides sharing the schema).
template <class T>
std::vector<std::uint8_t> to_avro_bytes(const T& row) {
    std::vector<std::uint8_t> out;
    for_each_column<T>([&]<std::size_t I, class Col>() { avro_append_value(out, Col::get(row)); });
    return out;
}

}  // namespace soatins
