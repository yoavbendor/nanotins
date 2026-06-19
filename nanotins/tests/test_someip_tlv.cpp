// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Yoav Bendor

// Phase 3: the someip_tlv_cursor primitive (nanotins/someip_tlv.hpp), standalone over raw payload buffers —
// the SOME/IP-TLV sibling of test_tlv_cursor. Covers tag bit-field extraction (wire type / data id, reserved
// bit ignored), the base wire types 0..3 (implicit 1/2/4/8 length, no length field), the complex wire types
// 5/6/7 (1/2/4-byte length field), the wire-type-4 stop (config-dependent width), truncation (must stop,
// never read past end), someip_tlv_count == number of next() yields, and a randomized fuzz loop asserting
// every emitted value range stays within the region.

#include "nanotins/someip_tlv.hpp"

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

using nanotins::someip_tlv_count;
using nanotins::someip_tlv_cursor;
using nanotins::someip_tlv_record;

// Append a 2-byte big-endian SOME/IP TLV tag: reserved(1) | wire_type(3) | data_id(12).
void put_tag(std::vector<std::uint8_t>& b, std::uint8_t wt, std::uint16_t id) {
    b.push_back(static_cast<std::uint8_t>((wt << 4) | ((id >> 8) & 0x0F)));
    b.push_back(static_cast<std::uint8_t>(id & 0xFF));
}
void put_be16(std::vector<std::uint8_t>& b, std::uint16_t v) {
    b.push_back(static_cast<std::uint8_t>(v >> 8));
    b.push_back(static_cast<std::uint8_t>(v));
}
void put_be32(std::vector<std::uint8_t>& b, std::uint32_t v) {
    for (int i = 3; i >= 0; --i) b.push_back(static_cast<std::uint8_t>(v >> (8 * i)));
}

// Collect all members the cursor yields, asserting each value range is in-bounds.
std::vector<someip_tlv_record> walk_all(const std::vector<std::uint8_t>& buf) {
    std::vector<someip_tlv_record> out;
    someip_tlv_cursor c{buf.data(), buf.data() + buf.size()};
    someip_tlv_record r{};
    int guard = 0;
    while (c.next(r)) {
        CHECK(++guard < 100000);
        if (r.value != nullptr) {
            CHECK(r.value >= buf.data());
            CHECK(r.value + r.length <= buf.data() + buf.size());  // never out of bounds
        } else {
            CHECK(r.length == 0);
        }
        out.push_back(r);
    }
    return out;
}

}  // namespace

int main() {
    // 1. Empty region -> no members.
    {
        std::vector<std::uint8_t> b;
        CHECK(walk_all(b).empty());
        CHECK(someip_tlv_count(b.data(), b.data()) == 0);
    }

    // 2. Tag bit-field extraction: wire type 5, data id 0x123 -> tag 0x51 0x23.
    {
        std::vector<std::uint8_t> b;
        put_tag(b, /*wt=*/5, /*id=*/0x123);
        b.push_back(0x00);  // 1-byte length field = 0 -> empty value
        CHECK(b[0] == 0x51 && b[1] == 0x23);
        auto rs = walk_all(b);
        CHECK(rs.size() == 1);
        CHECK(rs[0].wire_type == 5 && rs[0].data_id == 0x123 && rs[0].length == 0 && rs[0].value == nullptr);
    }

    // 3. The reserved bit 15 is ignored (does not bleed into wire type or data id).
    {
        std::vector<std::uint8_t> b = {0x80, 0x00, 0x42};  // reserved set, wt 0, id 0 -> 8-bit base, value 0x42
        auto rs = walk_all(b);
        CHECK(rs.size() == 1);
        CHECK(rs[0].wire_type == 0 && rs[0].data_id == 0 && rs[0].length == 1 && rs[0].value[0] == 0x42);
    }

    // 4. Base wire types 0..3 carry implicit 1/2/4/8-byte values (no length field on the wire).
    {
        std::vector<std::uint8_t> b;
        put_tag(b, 0, 0x001); b.push_back(0xAA);                                  // 8-bit
        put_tag(b, 1, 0x002); put_be16(b, 0xBBCC);                                // 16-bit
        put_tag(b, 2, 0x003); put_be32(b, 0xDDEEFF00);                            // 32-bit
        put_tag(b, 3, 0x004); for (int i = 0; i < 8; ++i) b.push_back(0x10 + i);  // 64-bit
        auto rs = walk_all(b);
        CHECK(rs.size() == 4);
        CHECK(rs[0].wire_type == 0 && rs[0].length == 1 && rs[0].value[0] == 0xAA);
        CHECK(rs[1].wire_type == 1 && rs[1].length == 2 && rs[1].value[0] == 0xBB && rs[1].value[1] == 0xCC);
        CHECK(rs[2].wire_type == 2 && rs[2].length == 4 && rs[2].data_id == 0x003);
        CHECK(rs[3].wire_type == 3 && rs[3].length == 8 && rs[3].value[7] == 0x17);
    }

    // 5. Complex wire types 5/6/7: 1/2/4-byte length fields, then that many value bytes; mixed run.
    {
        std::vector<std::uint8_t> b;
        put_tag(b, 5, 0x010); b.push_back(0x03); b.push_back(1); b.push_back(2); b.push_back(3);  // len8 = 3
        put_tag(b, 6, 0x020); put_be16(b, 2); b.push_back(9); b.push_back(8);                     // len16 = 2
        put_tag(b, 7, 0x030); put_be32(b, 1); b.push_back(0x77);                                  // len32 = 1
        auto rs = walk_all(b);
        CHECK(rs.size() == 3);
        CHECK(rs[0].wire_type == 5 && rs[0].data_id == 0x010 && rs[0].length == 3 && rs[0].value[2] == 3);
        CHECK(rs[1].wire_type == 6 && rs[1].length == 2 && rs[1].value[0] == 9 && rs[1].value[1] == 8);
        CHECK(rs[2].wire_type == 7 && rs[2].length == 1 && rs[2].value[0] == 0x77);
        CHECK(someip_tlv_count(b.data(), b.data() + b.size()) == 3);
    }

    // 6. A valid member followed by wire type 4 -> yield the first, then stop (config-dependent width).
    {
        std::vector<std::uint8_t> b;
        put_tag(b, 0, 0x001); b.push_back(0x55);  // a clean 8-bit base member
        put_tag(b, 4, 0x002); b.push_back(0x00); b.push_back(0x00);  // wt 4: cannot skip without the IDL
        auto rs = walk_all(b);
        CHECK(rs.size() == 1);
        CHECK(rs[0].data_id == 0x001 && rs[0].value[0] == 0x55);
        CHECK(someip_tlv_count(b.data(), b.data() + b.size()) == 1);
    }

    // 7. Truncated value: a len16 member claiming 4 bytes with only 2 present -> stop before it, no OOB read.
    {
        std::vector<std::uint8_t> b;
        put_tag(b, 6, 0x010); put_be16(b, 4); b.push_back(0xAA); b.push_back(0xBB);  // claims 4, has 2
        auto rs = walk_all(b);
        CHECK(rs.empty());
        CHECK(someip_tlv_count(b.data(), b.data() + b.size()) == 0);
    }

    // 8. Truncated length field: a len32 tag with only 2 of the 4 length bytes present -> stop.
    {
        std::vector<std::uint8_t> b;
        put_tag(b, 7, 0x010); b.push_back(0x00); b.push_back(0x00);  // length field cut short
        CHECK(walk_all(b).empty());
    }

    // 9. A lone tag with no following bytes (base type needs a value) -> stop, no OOB.
    {
        std::vector<std::uint8_t> b;
        put_tag(b, 2, 0x010);  // 32-bit base, but no value bytes follow
        CHECK(walk_all(b).empty());
        // ...and a lone single byte (not even a full tag) -> stop.
        std::vector<std::uint8_t> b2 = {0x20};
        CHECK(walk_all(b2).empty());
    }

    // 10. A valid member followed by a truncated one -> yield the first, stop at the second.
    {
        std::vector<std::uint8_t> b;
        put_tag(b, 0, 0x001); b.push_back(0x11);                              // ok
        put_tag(b, 5, 0x002); b.push_back(0x05); b.push_back(0xAA);           // claims 5, has 1
        auto rs = walk_all(b);
        CHECK(rs.size() == 1 && rs[0].data_id == 0x001);
    }

    // 11. Fuzz: random buffers must always terminate and never report an out-of-bounds value range.
    {
        std::srand(98765);
        for (int iter = 0; iter < 20000; ++iter) {
            const std::size_t n = static_cast<std::size_t>(std::rand() % 64);
            std::vector<std::uint8_t> b(n);
            for (auto& x : b) x = static_cast<std::uint8_t>(std::rand() & 0xFF);
            walk_all(b);  // CHECKs run inside
        }
    }

    std::printf("someip_tlv: ok (tag bits, wt 0-3 base, wt 5/6/7 length fields, wt4 stop, truncation, 20k fuzz)\n");
    return 0;
}
