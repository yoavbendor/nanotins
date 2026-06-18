// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Yoav Bendor

// IPv4 options as a variable-length child table (one row per option), via the tlv_cursor ipv4_options mode.
// IPv4 options live INSIDE the IPv4 header (between the 20-byte fixed part and IHL*4), so the option walk
// hangs off the Ipv4Node — unlike IPv6 extension headers, which are their own DAG nodes. Builds synthetic
// frames and asserts the option type/length (incl. the single-byte NOP/EOOL markers and the IPv4
// self-inclusive length semantics), that EOOL terminates the walk, that a header with no options yields no
// rows, and bounds-safety on a header whose IHL over-claims past the captured bytes.

#include "nanotins/ipv4_children.hpp"

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

void put_eth(Frame& f) { f.fill(6, 0x11); f.fill(6, 0x22); f.u16(0x0800); }
void put_udp(Frame& f) { f.u16(1); f.u16(2); f.u16(8); f.u16(0); }
void put_tcp(Frame& f) { f.u16(1); f.u16(2); f.u32(0); f.u32(0); f.u16(0x5000); f.u16(0); f.u16(0); f.u16(0); }

// IPv4 header with explicit IHL and option bytes appended. `ihl_override` lets a malformed case claim more
// header than `opts` actually provides (to exercise the clamp); pass 0 to derive it from opts.
void put_ipv4(Frame& f, std::uint8_t proto, const std::vector<std::uint8_t>& opts,
              std::uint8_t ihl_override = 0) {
    const std::uint8_t ihl = ihl_override ? ihl_override
                                          : static_cast<std::uint8_t>((20 + opts.size()) / 4);
    f.u8(static_cast<std::uint8_t>(0x40 | ihl));  // version 4 | ihl
    f.u8(0);                                      // dscp/ecn
    f.u16(0);                                     // total_length (unused by the walk)
    f.u16(0);                                     // identification
    f.u16(0);                                     // flags + frag_offset = 0 (first fragment -> L4 parsed)
    f.u8(64);                                     // ttl
    f.u8(proto);                                  // protocol
    f.u16(0);                                     // checksum
    f.fill(4, 0xC0);                              // src
    f.fill(4, 0xC8);                              // dst
    for (auto x : opts) f.u8(x);                  // options
}

constexpr int kEth = node_id_v<EthNode, L2L3Graph>;
constexpr int kIpv4 = node_id_v<Ipv4Node, L2L3Graph>;

}  // namespace

int main() {
    // 1. No options (IHL = 5) -> the IPv4 row is emitted but no option rows.
    {
        Frame f; put_eth(f); put_ipv4(f, 17, {}); put_udp(f);
        dag_tables<L2L3Graph> t; ipv4_child_tables k;
        dag_decode_packet_with_ipv4_children<L2L3Graph>(1, f.b.data(), f.b.size(), t, k, kEth);
        CHECK(std::get<kIpv4>(t).size() == 1);  // fixed IPv4 row still appended
        CHECK(k.opt.size() == 0);
    }

    // 2. One Router-Alert-shaped option (type 0x94, on-wire len 4) -> one row, opt_len = 4 (the wire octet).
    {
        Frame f; put_eth(f); put_ipv4(f, 6, {0x94, 0x04, 0x00, 0x00}); put_tcp(f);
        dag_tables<L2L3Graph> t; ipv4_child_tables k;
        dag_decode_packet_with_ipv4_children<L2L3Graph>(2, f.b.data(), f.b.size(), t, k, kEth);
        CHECK(k.opt.size() == 1);
        CHECK(k.opt.packet_id[0] == 2);
        CHECK(k.opt.opt_type[0] == 0x94);
        CHECK(k.opt.opt_len[0] == 4);
    }

    // 3. A multi-byte option that fills the whole option area (type 0x44 "timestamp", on-wire len 8).
    {
        Frame f; put_eth(f); put_ipv4(f, 17, {0x44, 0x08, 0, 0, 0, 0, 0, 0}); put_udp(f);
        dag_tables<L2L3Graph> t; ipv4_child_tables k;
        dag_decode_packet_with_ipv4_children<L2L3Graph>(3, f.b.data(), f.b.size(), t, k, kEth);
        CHECK(k.opt.size() == 1);
        CHECK(k.opt.opt_type[0] == 0x44);
        CHECK(k.opt.opt_len[0] == 8);
    }

    // 4. Single-byte markers: NOP, NOP, EOOL (+ one trailing padding byte the EOOL terminates before).
    //    -> three rows (1,1,0) each of on-wire length 1; padding after EOOL is not emitted.
    {
        Frame f; put_eth(f); put_ipv4(f, 17, {0x01, 0x01, 0x00, 0x00}); put_udp(f);
        dag_tables<L2L3Graph> t; ipv4_child_tables k;
        dag_decode_packet_with_ipv4_children<L2L3Graph>(4, f.b.data(), f.b.size(), t, k, kEth);
        CHECK(k.opt.size() == 3);
        CHECK(k.opt.opt_type[0] == 1 && k.opt.opt_len[0] == 1);  // NOP
        CHECK(k.opt.opt_type[1] == 1 && k.opt.opt_len[1] == 1);  // NOP
        CHECK(k.opt.opt_type[2] == 0 && k.opt.opt_len[2] == 1);  // EOOL
    }

    // 5. Mixed: a 4-byte option then NOP/NOP/NOP/EOOL filling an 8-byte option area -> 5 rows.
    {
        Frame f; put_eth(f);
        put_ipv4(f, 6, {0x94, 0x04, 0x00, 0x00, 0x01, 0x01, 0x01, 0x00});
        put_tcp(f);
        dag_tables<L2L3Graph> t; ipv4_child_tables k;
        dag_decode_packet_with_ipv4_children<L2L3Graph>(5, f.b.data(), f.b.size(), t, k, kEth);
        CHECK(k.opt.size() == 5);
        CHECK(k.opt.opt_type[0] == 0x94 && k.opt.opt_len[0] == 4);
        CHECK(k.opt.opt_type[1] == 1 && k.opt.opt_type[2] == 1 && k.opt.opt_type[3] == 1);
        CHECK(k.opt.opt_type[4] == 0);  // EOOL
    }

    // 6. Malformed: IHL claims a 40-byte header (IHL = 10 -> 20 option bytes) but only 4 option bytes are
    //    actually present. The option walk must clamp to the captured bytes — bounded, no OOB read.
    {
        Frame f; put_eth(f); put_ipv4(f, 17, {0x94, 0x04, 0x00, 0x00}, /*ihl_override=*/10);
        // no L4 appended; the frame ends right after the 4 present option bytes.
        dag_tables<L2L3Graph> t; ipv4_child_tables k;
        dag_decode_packet_with_ipv4_children<L2L3Graph>(6, f.b.data(), f.b.size(), t, k, kEth);
        CHECK(k.opt.size() <= 4);  // bounded; no crash, no OOB
    }

    std::printf("ipv4_options: ok (no-opts, router-alert, timestamp, NOP/EOOL, mixed, malformed clamp)\n");
    return 0;
}
