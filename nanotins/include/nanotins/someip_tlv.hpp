// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Yoav Bendor

#pragma once

// A bounds-checked, allocation-free cursor over SOME/IP TLV members — the AUTOSAR-SOME/IP sibling of the
// IPv6/SRv6 tlv_cursor (tlv.hpp). The wire grammar is different enough that the two cannot share code:
//
//   tlv.hpp           [type:1][len:1][value]            1-byte type, 1-byte length, Pad1/PadN special case.
//   someip_tlv.hpp    [tag:2][len:0|1|2|4][value]       2-byte big-endian tag whose wire-type bits pick the
//                                                        length-field width; no padding.
//
// SOME/IP TLV tag (2 bytes, big-endian, PRS_SOMEIP):
//   bit 15      reserved
//   bits 14-12  wire type (selects how the value length is encoded)
//   bits 11-0   data ID (the IDL member id; an unknown id is skipped, the whole point of TLV)
//
// Wire type -> value length:
//   0..3  base data type 8/16/32/64-bit  -> implicit length 1/2/4/8, NO length field on the wire
//   5     complex, 1-byte length field
//   6     complex, 2-byte length field
//   7     complex, 4-byte length field
//   4     complex, length-field width is taken from the IDL config (LengthFieldSize), NOT on the wire ->
//         cannot be skipped generically, so the cursor stops here (a config-aware decoder resumes it).
//
// IMPORTANT (scope): whether a SOME/IP payload is TLV-serialized at all is an IDL/configuration decision,
// not something visible on the wire — standard SOME/IP serialization is flat. So, unlike the IPv6 option
// space (self-describing) or SOME/IP-SD (self-describing), this cursor is NOT auto-applied in the DAG. It is
// a primitive a config-aware caller drives over a payload region it knows is TLV; it can tabulate the
// structural (data_id, wire_type, length) of each top-level member without the IDL, but interpreting the
// VALUES still needs the model.
//
// Everything here is NANOTINS_HD (host + device callable), POD / trivially copyable (capturable by a GPU
// bulk kernel), C++20, no STL containers, no allocation, no exceptions. Every read is bounded by `end`; a
// malformed or config-dependent (wire type 4) member stops the walk rather than reading out of bounds.

#include "soatins/portability.hpp"  // NANOTINS_HD

#include <cstddef>
#include <cstdint>
#include <type_traits>

namespace nanotins {

// Wire-type codes (tag bits 14-12).
inline constexpr std::uint8_t kSomeipTlvWt8 = 0;       // base 8-bit
inline constexpr std::uint8_t kSomeipTlvWt16 = 1;      // base 16-bit
inline constexpr std::uint8_t kSomeipTlvWt32 = 2;      // base 32-bit
inline constexpr std::uint8_t kSomeipTlvWt64 = 3;      // base 64-bit
inline constexpr std::uint8_t kSomeipTlvWtConfig = 4;  // complex, length-field width from IDL config
inline constexpr std::uint8_t kSomeipTlvWtLen8 = 5;    // complex, 1-byte length field
inline constexpr std::uint8_t kSomeipTlvWtLen16 = 6;   // complex, 2-byte length field
inline constexpr std::uint8_t kSomeipTlvWtLen32 = 7;   // complex, 4-byte length field

// One decoded TLV member. `value` points into the payload buffer (nullptr for a zero-length value).
struct someip_tlv_record {
    std::uint16_t data_id;      // 12-bit IDL member id (tag bits 11-0)
    std::uint8_t wire_type;     // 3-bit wire type (tag bits 14-12)
    std::uint32_t length;       // value length in bytes (implicit for wire types 0..3)
    const std::uint8_t* value;  // -> payload bytes, `length` bytes (nullptr when length == 0)
};

namespace detail_someip_tlv {
NANOTINS_HD inline std::uint16_t rd_be16(const std::uint8_t* p) noexcept {
    return static_cast<std::uint16_t>((static_cast<std::uint16_t>(p[0]) << 8) | p[1]);
}
NANOTINS_HD inline std::uint32_t rd_be32(const std::uint8_t* p) noexcept {
    return (static_cast<std::uint32_t>(p[0]) << 24) | (static_cast<std::uint32_t>(p[1]) << 16) |
           (static_cast<std::uint32_t>(p[2]) << 8) | static_cast<std::uint32_t>(p[3]);
}
}  // namespace detail_someip_tlv

// Bounds-checked, allocation-free cursor over SOME/IP TLV members in [p, end). Trivially copyable.
struct someip_tlv_cursor {
    const std::uint8_t* p = nullptr;
    const std::uint8_t* end = nullptr;

    // Decode the next member into `out`; return false at end-of-region, on a member that would run past
    // `end`, or on wire type 4 (config-dependent width — not skippable without the IDL). Never reads out of
    // bounds. After false, the cursor is exhausted.
    NANOTINS_HD bool next(someip_tlv_record& out) noexcept {
        if (p == nullptr || p + 2 > end) {  // need the 2-byte tag
            return false;
        }
        const std::uint16_t tag = detail_someip_tlv::rd_be16(p);
        const std::uint8_t wt = static_cast<std::uint8_t>((tag >> 12) & 0x7);  // ignores the reserved bit 15
        const std::uint16_t id = static_cast<std::uint16_t>(tag & 0x0FFF);
        const std::uint8_t* q = p + 2;  // first byte after the tag
        std::uint32_t len = 0;
        switch (wt) {
            case kSomeipTlvWt8: len = 1; break;
            case kSomeipTlvWt16: len = 2; break;
            case kSomeipTlvWt32: len = 4; break;
            case kSomeipTlvWt64: len = 8; break;
            case kSomeipTlvWtLen8:
                if (q + 1 > end) return false;
                len = q[0];
                q += 1;
                break;
            case kSomeipTlvWtLen16:
                if (q + 2 > end) return false;
                len = detail_someip_tlv::rd_be16(q);
                q += 2;
                break;
            case kSomeipTlvWtLen32:
                if (q + 4 > end) return false;
                len = detail_someip_tlv::rd_be32(q);
                q += 4;
                break;
            default:  // kSomeipTlvWtConfig (4): length-field width is IDL-configured, not on the wire -> stop
                return false;
        }
        if (q + len > end) {  // the value must fit inside the region
            return false;
        }
        out = someip_tlv_record{id, wt, len, (len == 0) ? nullptr : q};
        p = q + len;
        return true;
    }
};

// Count the members in [p, end) without emitting (the count pass for a bulk path). Device-safe; bounded by
// the same logic as someip_tlv_cursor::next, so it can never run away on malformed input.
NANOTINS_HD inline std::uint32_t someip_tlv_count(const std::uint8_t* p, const std::uint8_t* end) noexcept {
    someip_tlv_cursor c{p, end};
    someip_tlv_record r{};
    std::uint32_t n = 0;
    while (c.next(r)) {
        ++n;
    }
    return n;
}

static_assert(std::is_trivially_copyable_v<someip_tlv_cursor>, "someip_tlv_cursor must be POD for GPU capture");
static_assert(std::is_trivially_copyable_v<someip_tlv_record>, "someip_tlv_record must be POD for GPU capture");

}  // namespace nanotins
