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

#include <array>
#include <cstdint>
#include <cstring>
#include <ostream>
#include <random>
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

// Conservative per-column upper bound on encoded size, so a batch encode can reserve once instead of
// growing on every row: 1 byte for bool, 4/8 for float/double, sizeof(N) for a fixed array, and a zigzag
// varint's worst case (ceil(bits/7) + 1 sign byte) for int/long.
template <class Elem>
constexpr std::size_t avro_max_value_bytes() {
    if constexpr (std::is_same_v<Elem, bool>) {
        return 1;
    } else if constexpr (std::is_same_v<Elem, float>) {
        return 4;
    } else if constexpr (std::is_same_v<Elem, double>) {
        return 8;
    } else if constexpr (std::is_signed_v<Elem> || std::is_unsigned_v<Elem>) {
        return sizeof(Elem) == 1 ? 2 : sizeof(Elem) == 2 ? 3 : sizeof(Elem) == 4 ? 5 : 10;
    } else {
        return sizeof(Elem);  // std::array<uint8_t, N> fixed
    }
}
template <class T, std::size_t... I>
constexpr std::size_t avro_max_row_bytes_impl(std::index_sequence<I...>) {
    return (avro_max_value_bytes<typename col_at<T, I>::elem>() + ... + std::size_t{0});
}
template <class T>
inline constexpr std::size_t avro_max_row_bytes =
    avro_max_row_bytes_impl<T>(std::make_index_sequence<column_count<T>>{});

// ---- Object Container File (OCF): stream many rows without resending the schema -------------------
//
// Avro's own container format: the schema is written ONCE in a file header, then data streams as
// independent blocks (row count + byte length + concatenated row encodings + a sync marker). Pairs
// naturally with column_sink<T,N>: bind write_block as the flush callback and every full chunk becomes
// one block, with the SoA's columns encoded directly, row-major, straight into the output stream --
// no per-flush schema write, no reconstructing a T, no per-row heap allocation (the block buffer below is
// reserved once and reused, cleared rather than freed, across every block), and one write() syscall per
// block (prefix + rows + sync in a single contiguous buffer, not four separate stream writes).
//
// No compression codec beyond "null": deflate/snappy would pull in an external codec dependency, which
// is out of scope for a no-codegen reflection nucleus.

// Encode a zigzag varint into `buf` (must have room for the 10-byte int64 worst case); returns the byte
// count. The no-allocation building block both avro_write_zigzag (below) and write_block's in-place
// length prefix use.
inline int avro_zigzag_bytes(std::int64_t v, unsigned char* buf) {
    std::uint64_t z = (static_cast<std::uint64_t>(v) << 1) ^ static_cast<std::uint64_t>(v >> 63);
    int n = 0;
    while (z > 0x7f) {
        buf[n++] = static_cast<unsigned char>((z & 0x7f) | 0x80);
        z >>= 7;
    }
    buf[n++] = static_cast<unsigned char>(z);
    return n;
}

inline void avro_write_zigzag(std::ostream& os, std::int64_t v) {
    unsigned char buf[10];
    const int n = avro_zigzag_bytes(v, buf);
    os.write(reinterpret_cast<const char*>(buf), n);
}

inline void avro_write_string(std::ostream& os, const std::string& s) {
    avro_write_zigzag(os, static_cast<std::int64_t>(s.size()));
    os.write(s.data(), static_cast<std::streamsize>(s.size()));
}

template <class T>
void avro_ocf_write_header(std::ostream& os, const std::string& record_name,
                            const std::array<std::uint8_t, 16>& sync) {
    static constexpr char magic[4] = {'O', 'b', 'j', '\x01'};
    os.write(magic, 4);
    avro_write_zigzag(os, 2);  // two metadata entries: avro.schema, avro.codec
    avro_write_string(os, "avro.schema");
    avro_write_string(os, avro_schema_json<T>(record_name));
    avro_write_string(os, "avro.codec");
    avro_write_string(os, "null");
    avro_write_zigzag(os, 0);  // terminate the metadata map
    os.write(reinterpret_cast<const char*>(sync.data()), static_cast<std::streamsize>(sync.size()));
}

template <class T>
class avro_ocf_writer {
public:
    // Writes the OCF header (magic + schema + codec + a fresh random sync marker) immediately -- the one
    // and only schema write for the whole file, however many blocks follow.
    avro_ocf_writer(std::ostream& os, const std::string& record_name) : os_(&os) {
        std::random_device rd;
        std::mt19937_64 gen(rd());
        std::uniform_int_distribution<int> dist(0, 255);
        for (auto& b : sync_) {
            b = static_cast<std::uint8_t>(dist(gen));
        }
        avro_ocf_write_header<T>(*os_, record_name, sync_);
    }

    // Encode rows [0, count) of a soa<T, N-or-dynamic> as one data block and append it to the stream:
    // count, byte length, then each row's columns encoded in place straight from the SoA (Col::get(row)
    // is never called -- there is no row -- just s.column<I>()[i]), followed by the sync marker. A no-op
    // when count == 0 (e.g. column_sink::finish() draining an already-empty tail), so it's safe to bind
    // directly as a flush callback.
    //
    // The block's length prefix (an Avro long) can only be written once the encoded byte count is known,
    // but that shouldn't cost a second buffer: block_ reserves `max_prefix` bytes of dead space up front,
    // encodes rows starting right after it (so the -- usually much larger -- row payload is written into
    // its final position exactly once, no copy/shift), then the two prefix varints are encoded backwards
    // from the end of that gap. The result is one os_->write() per block covering prefix + rows + sync,
    // instead of the four separate stream writes (and no extra buffer) a naive version would need.
    template <class Soa>
    void write_block(const Soa& s, std::size_t count) {
        if (count == 0) {
            return;
        }
        block_.clear();
        block_.reserve(max_prefix + count * avro_max_row_bytes<T> + sync_.size());
        block_.resize(max_prefix, 0);  // dead space for the count/length prefix, filled in below
        for (std::size_t i = 0; i < count; ++i) {
            for_each_column<T>(
                [&]<std::size_t I, class Col>() { avro_append_value(block_, s.template column<I>()[i]); });
        }
        const std::size_t rows_bytes = block_.size() - max_prefix;
        block_.insert(block_.end(), sync_.begin(), sync_.end());

        unsigned char count_buf[10];
        unsigned char len_buf[10];
        const int count_n = avro_zigzag_bytes(static_cast<std::int64_t>(count), count_buf);
        const int len_n = avro_zigzag_bytes(static_cast<std::int64_t>(rows_bytes), len_buf);
        const std::size_t prefix_start = max_prefix - static_cast<std::size_t>(count_n + len_n);
        std::memcpy(block_.data() + prefix_start, count_buf, static_cast<std::size_t>(count_n));
        std::memcpy(block_.data() + prefix_start + count_n, len_buf, static_cast<std::size_t>(len_n));

        os_->write(reinterpret_cast<const char*>(block_.data() + prefix_start),
                   static_cast<std::streamsize>(block_.size() - prefix_start));
    }

private:
    // Two zigzag int64 varints, worst case 10 bytes each: the max count+length prefix write_block needs.
    static constexpr std::size_t max_prefix = 20;

    std::ostream* os_;
    std::array<std::uint8_t, 16> sync_{};
    std::vector<std::uint8_t> block_;  // reused across blocks: cleared, never freed
};

}  // namespace soatins
