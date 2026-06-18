// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Yoav Bendor

// Phase 2: IPv6 extension-header chain walk + the L4 correctness fix. Builds synthetic Ethernet/IPv6
// frames with extension headers (Hop-by-Hop, Fragment, SRv6 SRH, chains) and asserts the DAG now (a) emits
// a per-type row for each extension header and (b) reaches the correct TCP/UDP node past the chain — which
// it did NOT before this change (it treated next_header as the L4 protocol and stopped). Also exercises a
// malformed header (must stop gracefully, no crash / no OOB).

#include "nanotins/dag_decode.hpp"
#include "nanotins/spec_dag.hpp"

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <initializer_list>
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

// Big-endian (network order) frame builder.
struct Frame {
    std::vector<std::uint8_t> b;
    void u8(std::uint8_t v) { b.push_back(v); }
    void u16(std::uint16_t v) { b.push_back(v >> 8); b.push_back(v & 0xFF); }
    void u32(std::uint32_t v) { for (int i = 3; i >= 0; --i) b.push_back((v >> (8 * i)) & 0xFF); }
    void fill(std::size_t n, std::uint8_t v = 0) { for (std::size_t i = 0; i < n; ++i) b.push_back(v); }
    void raw(std::initializer_list<std::uint8_t> xs) { for (auto x : xs) b.push_back(x); }
};

void put_eth(Frame& f) {
    f.fill(6, 0x11);  // dst
    f.fill(6, 0x22);  // src
    f.u16(0x86DD);    // IPv6
}
void put_ipv6(Frame& f, std::uint8_t next_header) {
    f.u8(0x60); f.u8(0); f.u16(0);  // version=6, tc=0, flow=0
    f.u16(0);                        // payload_length (not validated by the walk)
    f.u8(next_header);
    f.u8(64);                        // hop limit
    f.fill(16, 0xAA);                // src
    f.fill(16, 0xBB);                // dst
}
void put_udp(Frame& f, std::uint16_t sp, std::uint16_t dp) { f.u16(sp); f.u16(dp); f.u16(8); f.u16(0); }
void put_tcp(Frame& f, std::uint16_t sp, std::uint16_t dp) {
    f.u16(sp); f.u16(dp); f.u32(1); f.u32(2); f.u16(0x5000 /*data_offset=5*/); f.u16(0); f.u16(0); f.u16(0);
}
// Hop-by-Hop / Dest-Opts with hdr_ext_len=0 (8 bytes) and a PadN filling the option area.
void put_hbh8(Frame& f, std::uint8_t next_header) {
    f.u8(next_header); f.u8(0);          // preamble: next, hdr_ext_len=0
    f.u8(1); f.u8(4); f.fill(4, 0);      // PadN type=1 len=4 + 4 zero bytes  (6 bytes -> total 8)
}
// SRv6 SRH with `nseg` 16-byte segments, no TLVs.
void put_srh(Frame& f, std::uint8_t next_header, std::uint8_t nseg, std::uint8_t segments_left) {
    const std::size_t total = 8 + std::size_t{nseg} * 16;  // 8-byte aligned by construction
    f.u8(next_header);
    f.u8(static_cast<std::uint8_t>(total / 8 - 1));  // hdr_ext_len
    f.u8(4);                                          // routing_type = 4 (SRH)
    f.u8(segments_left);
    f.u8(static_cast<std::uint8_t>(nseg - 1));        // last_entry
    f.u8(0);                                          // flags
    f.u16(0xBEEF);                                    // tag
    for (std::uint8_t s = 0; s < nseg; ++s) f.fill(16, static_cast<std::uint8_t>(0x30 + s));
}
void put_fragment(Frame& f, std::uint8_t next_header, std::uint16_t frag_off, std::uint8_t more,
                  std::uint32_t id) {
    f.u8(next_header); f.u8(0);
    f.u16(static_cast<std::uint16_t>((frag_off << 3) | (more & 1)));
    f.u32(id);
}
// Authentication Header (next=51): length (payload_len+2)*4. payload_len=4 -> 24 bytes (12 fixed + 12 ICV).
void put_ah(Frame& f, std::uint8_t next_header) {
    f.u8(next_header); f.u8(4); f.u16(0); f.u32(0x1000 /*spi*/); f.u32(7 /*seq*/); f.fill(12, 0xEE /*ICV*/);
}

// node-id shortcuts
constexpr int kIp6 = node_id_v<Ipv6Node, L2L3Graph>;
constexpr int kTcp = node_id_v<TcpNode, L2L3Graph>;
constexpr int kUdp = node_id_v<UdpNode, L2L3Graph>;
constexpr int kHbh = node_id_v<Ipv6HopByHopNode, L2L3Graph>;
constexpr int kRtg = node_id_v<Ipv6RoutingNode, L2L3Graph>;
constexpr int kFrg = node_id_v<Ipv6FragmentNode, L2L3Graph>;
constexpr int kAh = node_id_v<Ipv6AhNode, L2L3Graph>;

template <int Node>
std::size_t rows(const dag_tables<L2L3Graph>& t) { return std::get<Node>(t).size(); }

}  // namespace

int main() {
    // A. Plain IPv6 + UDP (no extension headers): baseline, must still work.
    {
        Frame f; put_eth(f); put_ipv6(f, 17); put_udp(f, 1000, 2000);
        dag_tables<L2L3Graph> t;
        dag_decode_packet<L2L3Graph>(0, f.b.data(), f.b.size(), t, kEthRoot);
        CHECK(rows<kIp6>(t) == 1);
        CHECK(rows<kUdp>(t) == 1);
        CHECK(rows<kTcp>(t) == 0);
        CHECK(rows<kHbh>(t) == 0);
        CHECK(std::get<kUdp>(t).column<1>()[0] == 2000);  // dst_port
    }

    // B. IPv6 + Hop-by-Hop + TCP — THE regression: before the fix, next_header=0 stopped with no L4.
    {
        Frame f; put_eth(f); put_ipv6(f, 0); put_hbh8(f, 6); put_tcp(f, 1111, 80);
        dag_tables<L2L3Graph> t;
        dag_decode_packet<L2L3Graph>(0, f.b.data(), f.b.size(), t, kEthRoot);
        CHECK(rows<kIp6>(t) == 1);
        CHECK(rows<kHbh>(t) == 1);
        CHECK(rows<kTcp>(t) == 1);                          // L4 now reached
        CHECK(rows<kUdp>(t) == 0);
        CHECK(std::get<kHbh>(t).column<0>()[0] == 6);       // hop-by-hop next_header
        CHECK(std::get<kTcp>(t).column<1>()[0] == 80);      // dst_port
    }

    // C. IPv6 + Fragment + UDP.
    {
        Frame f; put_eth(f); put_ipv6(f, 44); put_fragment(f, 17, /*off=*/0, /*more=*/1, 0xABCD);
        put_udp(f, 5, 6);
        dag_tables<L2L3Graph> t;
        dag_decode_packet<L2L3Graph>(0, f.b.data(), f.b.size(), t, kEthRoot);
        CHECK(rows<kFrg>(t) == 1);
        CHECK(rows<kUdp>(t) == 1);
        // Ipv6FragmentSpec field order: 0 next_header, 1 reserved, 2 frag_offset, 3 res2, 4 more_fragments,
        // 5 identification.
        CHECK(std::get<kFrg>(t).column<0>()[0] == 17);     // next_header
        CHECK(std::get<kFrg>(t).column<2>()[0] == 0);      // frag_offset
        CHECK(std::get<kFrg>(t).column<4>()[0] == 1);      // more_fragments
        CHECK(std::get<kFrg>(t).column<5>()[0] == 0xABCD); // identification
    }

    // D. IPv6 + SRv6 SRH (2 segments) + UDP.
    {
        Frame f; put_eth(f); put_ipv6(f, 43); put_srh(f, 17, /*nseg=*/2, /*segleft=*/2); put_udp(f, 7, 8);
        dag_tables<L2L3Graph> t;
        dag_decode_packet<L2L3Graph>(0, f.b.data(), f.b.size(), t, kEthRoot);
        CHECK(rows<kRtg>(t) == 1);
        CHECK(rows<kUdp>(t) == 1);
        CHECK(std::get<kRtg>(t).column<2>()[0] == 4);   // routing_type
        CHECK(std::get<kRtg>(t).column<3>()[0] == 2);   // segments_left
        CHECK(std::get<kRtg>(t).column<4>()[0] == 1);   // last_entry (nseg-1)
        CHECK(std::get<kRtg>(t).column<6>()[0] == 0xBEEF);  // tag
    }

    // E. Chain: IPv6 + SRH + Hop-by-Hop + TCP (two ext headers, then L4).
    {
        Frame f; put_eth(f); put_ipv6(f, 43); put_srh(f, 0, 2, 0); put_hbh8(f, 6); put_tcp(f, 9, 10);
        dag_tables<L2L3Graph> t;
        dag_decode_packet<L2L3Graph>(0, f.b.data(), f.b.size(), t, kEthRoot);
        CHECK(rows<kRtg>(t) == 1);
        CHECK(rows<kHbh>(t) == 1);
        CHECK(rows<kTcp>(t) == 1);
    }

    // F. Malformed: Hop-by-Hop claims a length that runs past the packet — must stop, no crash, no L4.
    {
        Frame f; put_eth(f); put_ipv6(f, 0);
        f.u8(6); f.u8(200);  // next=6, hdr_ext_len=200 -> advance 1608 bytes, far past the buffer
        f.fill(4, 0);        // only a few bytes follow
        dag_tables<L2L3Graph> t;
        dag_decode_packet<L2L3Graph>(0, f.b.data(), f.b.size(), t, kEthRoot);
        CHECK(rows<kIp6>(t) == 1);
        CHECK(rows<kHbh>(t) == 1);   // the 2-byte preamble fit, so the row was emitted
        CHECK(rows<kTcp>(t) == 0);   // but the chain could not continue -> no bogus L4
        CHECK(rows<kUdp>(t) == 0);
    }

    // G. Continuation fragment (frag_offset != 0): the bytes after the fragment header are payload data,
    //    NOT an L4 header — must NOT emit a (bogus) L4 row. The fragment row itself is still emitted.
    {
        Frame f; put_eth(f); put_ipv6(f, 44);
        put_fragment(f, 17, /*frag_off=*/185, /*more=*/1, 0xABCD);  // non-zero offset
        f.fill(20, 0x77);  // fragment payload data (not a UDP header)
        dag_tables<L2L3Graph> t;
        dag_decode_packet<L2L3Graph>(0, f.b.data(), f.b.size(), t, kEthRoot);
        CHECK(rows<kFrg>(t) == 1);                       // fragment row present
        CHECK(std::get<kFrg>(t).column<2>()[0] == 185);  // frag_offset
        CHECK(rows<kUdp>(t) == 0);                        // NO bogus L4 on a continuation fragment
        CHECK(rows<kTcp>(t) == 0);
    }

    // H. Authentication Header (next=51) -> UDP: AH is not encrypted, so L4 follows; advance must use the
    //    (payload_len+2)*4 length so UDP is found at the right offset.
    {
        Frame f; put_eth(f); put_ipv6(f, 51); put_ah(f, 17); put_udp(f, 100, 200);
        dag_tables<L2L3Graph> t;
        dag_decode_packet<L2L3Graph>(0, f.b.data(), f.b.size(), t, kEthRoot);
        CHECK(rows<kAh>(t) == 1);
        CHECK(rows<kUdp>(t) == 1);
        CHECK(std::get<kUdp>(t).column<1>()[0] == 200);  // dst_port (L4 reached past AH's 24 bytes)
    }

    // I. ESP (next=50): encrypted — the walk must stop cleanly with no L4 and no crash.
    {
        Frame f; put_eth(f); put_ipv6(f, 50); f.fill(24, 0x99);  // opaque ESP bytes
        dag_tables<L2L3Graph> t;
        dag_decode_packet<L2L3Graph>(0, f.b.data(), f.b.size(), t, kEthRoot);
        CHECK(rows<kIp6>(t) == 1);
        CHECK(rows<kUdp>(t) == 0);
        CHECK(rows<kTcp>(t) == 0);
    }

    std::printf("ipv6_ext_walk: ok (chain walk + L4 fix: hbh/frag/srh/chain/malformed/cont-frag/ah/esp)\n");
    return 0;
}
