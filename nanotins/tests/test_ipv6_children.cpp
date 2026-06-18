// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Yoav Bendor

// Phase 4: IPv6 variable-length child tables (SRv6 segment list + Hop-by-Hop / Destination-Options / SRH
// TLV options) via the tlv_cursor / repeat_at primitives. Builds synthetic frames and asserts the segment
// addresses (incl. order), the option type/len, the SRH-TLV container tagging, and bounds-safety on a
// malformed SRH that over-claims its segment count.

#include "nanotins/ipv6_children.hpp"

#include <array>
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

using namespace nanotins;

struct Frame {
    std::vector<std::uint8_t> b;
    void u8(std::uint8_t v) { b.push_back(v); }
    void u16(std::uint16_t v) { b.push_back(v >> 8); b.push_back(v & 0xFF); }
    void u32(std::uint32_t v) { for (int i = 3; i >= 0; --i) b.push_back((v >> (8 * i)) & 0xFF); }
    void fill(std::size_t n, std::uint8_t v = 0) { for (std::size_t i = 0; i < n; ++i) b.push_back(v); }
};

void put_eth(Frame& f) { f.fill(6, 0x11); f.fill(6, 0x22); f.u16(0x86DD); }
void put_ipv6(Frame& f, std::uint8_t nh) {
    f.u8(0x60); f.u8(0); f.u16(0); f.u16(0); f.u8(nh); f.u8(64); f.fill(16, 0xAA); f.fill(16, 0xBB);
}
void put_udp(Frame& f) { f.u16(1); f.u16(2); f.u16(8); f.u16(0); }
void put_tcp(Frame& f) { f.u16(1); f.u16(2); f.u32(0); f.u32(0); f.u16(0x5000); f.u16(0); f.u16(0); f.u16(0); }

// Raw SRH with explicit fields (so malformed cases can over-claim). Segment i is filled with byte 0x30+i.
void put_srh_raw(Frame& f, std::uint8_t next, std::uint8_t hel, std::uint8_t segleft, std::uint8_t last_entry,
                 std::uint8_t nseg_to_write, const std::vector<std::uint8_t>& tlv) {
    f.u8(next); f.u8(hel); f.u8(4); f.u8(segleft); f.u8(last_entry); f.u8(0); f.u16(0xBEEF);
    for (std::uint8_t s = 0; s < nseg_to_write; ++s) f.fill(16, static_cast<std::uint8_t>(0x30 + s));
    for (auto x : tlv) f.u8(x);
}
// Well-formed SRH: nseg segments + optional tlv bytes, hdr_ext_len/last_entry computed.
void put_srh(Frame& f, std::uint8_t next, std::uint8_t nseg, std::uint8_t segleft,
             const std::vector<std::uint8_t>& tlv = {}) {
    const std::size_t total = 8 + std::size_t{nseg} * 16 + tlv.size();
    CHECK(total % 8 == 0);  // fixtures must be 8-byte aligned
    put_srh_raw(f, next, static_cast<std::uint8_t>(total / 8 - 1), segleft,
                static_cast<std::uint8_t>(nseg - 1), nseg, tlv);
}
// Hop-by-Hop / Dest-Opts of exactly 8 bytes carrying one option [type][len=4][4 bytes].
void put_opt8(Frame& f, std::uint8_t next, std::uint8_t opt_type) {
    f.u8(next); f.u8(0); f.u8(opt_type); f.u8(4); f.fill(4, 0xCC);
}

constexpr int kEth = node_id_v<EthNode, L2L3Graph>;

}  // namespace

int main() {
    // 1. SRH with 3 segments, no TLVs -> 3 segment rows in order, addresses 0x30/0x31/0x32.
    {
        Frame f; put_eth(f); put_ipv6(f, 43); put_srh(f, 17, /*nseg=*/3, /*segleft=*/3); put_udp(f);
        dag_tables<L2L3Graph> t; ipv6_child_tables k;
        dag_decode_packet_with_children<L2L3Graph>(7, f.b.data(), f.b.size(), t, k, kEth);
        CHECK(k.srh_segment.size() == 3);
        CHECK(k.opt.size() == 0);
        for (std::uint8_t i = 0; i < 3; ++i) {
            CHECK(k.srh_segment.packet_id[i] == 7);
            CHECK(k.srh_segment.srh_order[i] == 0);
            CHECK(k.srh_segment.segment_index[i] == i);
            std::array<std::uint8_t, 16> exp{}; exp.fill(static_cast<std::uint8_t>(0x30 + i));
            CHECK(k.srh_segment.address[i] == exp);
        }
    }

    // 2. Hop-by-Hop with one option (type 5, len 4) -> one opt row, container 0.
    {
        Frame f; put_eth(f); put_ipv6(f, 0); put_opt8(f, 6, /*opt_type=*/5); put_tcp(f);
        dag_tables<L2L3Graph> t; ipv6_child_tables k;
        dag_decode_packet_with_children<L2L3Graph>(1, f.b.data(), f.b.size(), t, k, kEth);
        CHECK(k.srh_segment.size() == 0);
        CHECK(k.opt.size() == 1);
        CHECK(k.opt.container_type[0] == 0);
        CHECK(k.opt.opt_type[0] == 5);
        CHECK(k.opt.opt_len[0] == 4);
    }

    // 3. SRH with 2 segments + 1 TLV (type 5, len 6) -> 2 segments + 1 opt row, container 43.
    {
        std::vector<std::uint8_t> tlv = {5, 6, 0, 0, 0, 0, 0, 0};  // [type=5][len=6][6 value bytes] = 8 bytes
        Frame f; put_eth(f); put_ipv6(f, 43); put_srh(f, 17, /*nseg=*/2, /*segleft=*/2, tlv); put_udp(f);
        dag_tables<L2L3Graph> t; ipv6_child_tables k;
        dag_decode_packet_with_children<L2L3Graph>(2, f.b.data(), f.b.size(), t, k, kEth);
        CHECK(k.srh_segment.size() == 2);
        CHECK(k.opt.size() == 1);
        CHECK(k.opt.container_type[0] == 43);
        CHECK(k.opt.opt_type[0] == 5);
        CHECK(k.opt.opt_len[0] == 6);
    }

    // 4. Destination Options with one option (type 6) -> container 60.
    {
        Frame f; put_eth(f); put_ipv6(f, 60); put_opt8(f, 17, /*opt_type=*/6); put_udp(f);
        dag_tables<L2L3Graph> t; ipv6_child_tables k;
        dag_decode_packet_with_children<L2L3Graph>(3, f.b.data(), f.b.size(), t, k, kEth);
        CHECK(k.opt.size() == 1);
        CHECK(k.opt.container_type[0] == 60);
        CHECK(k.opt.opt_type[0] == 6);
    }

    // 5. Malformed: SRH says hdr_ext_len=2 (24 bytes -> room for 1 segment) but last_entry=9 (claims 10).
    //    Must emit only the segments that fit, never read out of bounds.
    {
        Frame f; put_eth(f); put_ipv6(f, 43);
        put_srh_raw(f, 17, /*hel=*/2, /*segleft=*/9, /*last_entry=*/9, /*nseg_to_write=*/1, {});
        // pad the frame so the IPv6 base + 8-byte SRH fixed part are present; SRH claims 24 bytes total.
        f.fill(8, 0);  // only one segment (16) actually present after the 8-byte fixed part
        dag_tables<L2L3Graph> t; ipv6_child_tables k;
        dag_decode_packet_with_children<L2L3Graph>(9, f.b.data(), f.b.size(), t, k, kEth);
        CHECK(k.srh_segment.size() <= 1);  // bounded; no crash, no OOB
    }

    std::printf("ipv6_children: ok (segments, options, SRH TLVs, dest-opts, malformed bounds)\n");
    return 0;
}
