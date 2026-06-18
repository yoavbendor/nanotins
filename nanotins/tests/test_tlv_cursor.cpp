// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Yoav Bendor

// Phase 1: the tlv_cursor / repeat_at primitive (nanotins/tlv.hpp), standalone over raw byte buffers.
// Covers Pad1/PadN, mixed options, truncated/malformed records (must stop, never read past end),
// tlv_count == number of next() yields, repeat_at bounds, and a randomized fuzz loop asserting that every
// emitted record's [value, value+length) stays within the region.

#include "nanotins/tlv.hpp"

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <vector>

#define CHECK(cond)                                                            \
    do {                                                                       \
        if (!(cond)) {                                                         \
            std::fprintf(stderr, "FAIL %s:%d %s\n", __FILE__, __LINE__, #cond); \
            std::exit(1);                                                      \
        }                                                                      \
    } while (0)

namespace {

using nanotins::repeat_at;
using nanotins::tlv_count;
using nanotins::tlv_cursor;
using nanotins::tlv_pad;
using nanotins::tlv_record;

// Collect all records the cursor yields, asserting each value range is in-bounds.
std::vector<tlv_record> walk_all(const std::vector<std::uint8_t>& buf, tlv_pad pad) {
    std::vector<tlv_record> out;
    tlv_cursor c{buf.data(), buf.data() + buf.size(), pad};
    tlv_record r{};
    int guard = 0;
    while (c.next(r)) {
        CHECK(++guard < 100000);  // must terminate
        if (r.value != nullptr) {
            CHECK(r.value >= buf.data());
            CHECK(r.value + r.length <= buf.data() + buf.size());  // never out of bounds
        }
        out.push_back(r);
    }
    return out;
}

}  // namespace

int main() {
    // 1. Empty region -> no records.
    {
        std::vector<std::uint8_t> b;
        CHECK(walk_all(b, tlv_pad::ipv6_options).empty());
        CHECK(tlv_count(b.data(), b.data(), tlv_pad::ipv6_options) == 0);
    }

    // 2. A single Pad1 (type 0) -> one 1-byte record, no value.
    {
        std::vector<std::uint8_t> b = {0x00};
        auto rs = walk_all(b, tlv_pad::ipv6_options);
        CHECK(rs.size() == 1);
        CHECK(rs[0].type == 0 && rs[0].length == 0 && rs[0].value == nullptr);
    }

    // 3. PadN (type 1, len 2) + a real option (type 5, len 3) + a trailing Pad1.
    {
        std::vector<std::uint8_t> b = {0x01, 0x02, 0x00, 0x00,         // PadN, 2 zero bytes
                                       0x05, 0x03, 0xAA, 0xBB, 0xCC,   // option type 5, 3-byte value
                                       0x00};                          // Pad1
        auto rs = walk_all(b, tlv_pad::ipv6_options);
        CHECK(rs.size() == 3);
        CHECK(rs[0].type == 1 && rs[0].length == 2);
        CHECK(rs[1].type == 5 && rs[1].length == 3);
        CHECK(rs[1].value[0] == 0xAA && rs[1].value[1] == 0xBB && rs[1].value[2] == 0xCC);
        CHECK(rs[2].type == 0 && rs[2].length == 0);
        CHECK(tlv_count(b.data(), b.data() + b.size(), tlv_pad::ipv6_options) == 3);
    }

    // 4. raw mode: type 0 is NOT a 1-byte pad — it's [type=0][len][value].
    {
        std::vector<std::uint8_t> b = {0x00, 0x02, 0x11, 0x22, 0x05, 0x00};
        auto rs = walk_all(b, tlv_pad::raw);
        CHECK(rs.size() == 2);
        CHECK(rs[0].type == 0 && rs[0].length == 2 && rs[0].value[0] == 0x11);
        CHECK(rs[1].type == 5 && rs[1].length == 0);
    }

    // 5. Truncated: a [type][len] claiming a value that runs past end -> stop before it, no OOB read.
    {
        std::vector<std::uint8_t> b = {0x05, 0x03, 0xAA, 0xBB};  // claims 3 value bytes, only 2 present
        auto rs = walk_all(b, tlv_pad::ipv6_options);
        CHECK(rs.empty());  // the only record is malformed -> nothing yielded
        CHECK(tlv_count(b.data(), b.data() + b.size(), tlv_pad::ipv6_options) == 0);
    }

    // 6. A valid record followed by a truncated one -> yield the first, stop at the second.
    {
        std::vector<std::uint8_t> b = {0x05, 0x01, 0xAA, 0x06, 0x04, 0x01};  // 2nd claims 4, has 1
        auto rs = walk_all(b, tlv_pad::ipv6_options);
        CHECK(rs.size() == 1);
        CHECK(rs[0].type == 5 && rs[0].length == 1);
    }

    // 7. A lone [type] with no length byte (raw mode) at the very end -> stop.
    {
        std::vector<std::uint8_t> b = {0x05};
        CHECK(walk_all(b, tlv_pad::raw).empty());
    }

    // 8. repeat_at bounds: 3 segments of stride 16.
    {
        std::vector<std::uint8_t> seg(3 * 16, 0);
        for (int i = 0; i < 3; ++i) seg[i * 16] = static_cast<std::uint8_t>(0x10 + i);
        const std::uint8_t* end = seg.data() + seg.size();
        CHECK(repeat_at(seg.data(), 3, 16, end, 0) == seg.data());
        CHECK(repeat_at(seg.data(), 3, 16, end, 2) == seg.data() + 32);
        CHECK(repeat_at(seg.data(), 3, 16, end, 3) == nullptr);          // index out of count
        CHECK(repeat_at(seg.data(), 4, 16, end, 3) == nullptr);          // 4th would run past end
        CHECK(repeat_at(nullptr, 3, 16, end, 0) == nullptr);            // null base
    }

    // 9. Fuzz: random buffers must always terminate and never report an out-of-bounds value range.
    {
        std::srand(12345);
        for (int iter = 0; iter < 20000; ++iter) {
            const std::size_t n = static_cast<std::size_t>(std::rand() % 64);
            std::vector<std::uint8_t> b(n);
            for (auto& x : b) x = static_cast<std::uint8_t>(std::rand() & 0xFF);
            walk_all(b, (iter & 1) ? tlv_pad::raw : tlv_pad::ipv6_options);  // CHECKs run inside
        }
    }

    std::printf("tlv_cursor: ok (Pad1/PadN, mixed, truncation, raw mode, repeat_at, 20k fuzz)\n");
    return 0;
}
