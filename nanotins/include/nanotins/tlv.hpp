// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Yoav Bendor

#pragma once

// A bounds-checked, allocation-free cursor over variable-length wire records — the device-safe
// generalisation of vbvx's SRv6TlvIterator (see docs/the_case_for_learning_from_vbvx.md). Two shapes:
//
//   tlv_cursor   walks [type][len][value] records (IPv6 Hop-by-Hop / Destination options, SRv6 SRH TLVs,
//                with optional 1-byte Pad1) between [p, end).
//   repeat_at    indexes a fixed-stride array (e.g. an SRv6 segment list: N x 16-byte IPv6 addresses).
//
// Everything here is NANOTINS_HD (host + device callable), POD / trivially copyable (so a GPU bulk kernel
// can capture it by value), C++20, no STL containers, no allocation, no exceptions. Every read is bounded
// by `end`; a malformed record stops the walk rather than reading out of bounds.

#include "soatins/portability.hpp"  // NANOTINS_HD

#include <cstddef>
#include <cstdint>
#include <type_traits>

namespace nanotins {

// One decoded TLV record. `value` points into the packet buffer (nullptr for a 1-byte pad record).
struct tlv_record {
    std::uint8_t type;
    std::uint8_t length;        // value length in bytes (0 for a 1-byte pad)
    const std::uint8_t* value;  // -> packet bytes, length bytes (nullptr for a 1-byte pad)
};

// Padding convention for the TLV space being walked.
//   ipv6_options : RFC 8200 4.2 — type 0 is Pad1 (a lone byte, no length/value); type 1 is PadN.
//   raw          : every record is [type][len][value]; no 1-byte special case.
enum class tlv_pad : std::uint8_t { ipv6_options, raw };

// Bounds-checked, allocation-free cursor over [type][len][value] records in [p, end). Trivially copyable.
struct tlv_cursor {
    const std::uint8_t* p = nullptr;
    const std::uint8_t* end = nullptr;
    tlv_pad pad = tlv_pad::ipv6_options;

    // Decode the next record into `out`; return false at end-of-region or on a record that would run past
    // `end` (never reads out of bounds). After false, the cursor is exhausted.
    NANOTINS_HD bool next(tlv_record& out) noexcept {
        if (p == nullptr || p >= end) {
            return false;
        }
        const std::uint8_t t = p[0];
        if (pad == tlv_pad::ipv6_options && t == 0) {  // Pad1: a single byte, no length/value
            out = tlv_record{0, 0, nullptr};
            p += 1;
            return true;
        }
        if (p + 2 > end) {  // need type + length
            return false;
        }
        const std::uint8_t len = p[1];
        if (p + std::size_t{2} + len > end) {  // value must fit inside the region
            return false;
        }
        out = tlv_record{t, len, p + 2};
        p += std::size_t{2} + len;
        return true;
    }
};

// Count the records in [p, end) without emitting (the count pass for the bulk path). Device-safe; bounded
// by the same logic as tlv_cursor::next, so it can never run away on malformed input.
NANOTINS_HD inline std::uint32_t tlv_count(const std::uint8_t* p, const std::uint8_t* end,
                                           tlv_pad pad) noexcept {
    tlv_cursor c{p, end, pad};
    tlv_record r{};
    std::uint32_t n = 0;
    while (c.next(r)) {
        ++n;
    }
    return n;
}

// Index a fixed-stride record array (e.g. SRv6 segment list: base = first segment, stride = 16, count =
// last_entry + 1). Returns the i-th record's start, or nullptr if i is out of range or the record would
// run past `end`. Device-safe.
NANOTINS_HD inline const std::uint8_t* repeat_at(const std::uint8_t* base, std::uint32_t count,
                                                 std::uint32_t stride, const std::uint8_t* end,
                                                 std::uint32_t i) noexcept {
    if (base == nullptr || i >= count) {
        return nullptr;
    }
    const std::uint8_t* q = base + std::size_t{i} * stride;
    return (q + stride <= end) ? q : nullptr;
}

static_assert(std::is_trivially_copyable_v<tlv_cursor>, "tlv_cursor must be POD for GPU capture");
static_assert(std::is_trivially_copyable_v<tlv_record>, "tlv_record must be POD for GPU capture");

}  // namespace nanotins
