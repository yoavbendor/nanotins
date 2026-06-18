// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Yoav Bendor

// Phase 5: the IPv6 child tables (SRv6 segments + IPv6/SRH options) must be byte-identical whether built
// serially (dag_decode_packet_with_children) or via the bulk count->scan->scatter path
// (ipv6_children_bulk), and identically whether the bulk scatter runs in-thread or on a thread pool. This
// is the determinism proof the GPU path needs: every write index is a pure function of the packet's
// prefix-summed base + emit order. Runs over a large randomized batch mixing every extension shape.

#include "nanotins/dag_bulk.hpp"
#include "nanotins/dag_decode.hpp"
#include "nanotins/ipv6_children.hpp"
#include "nanotins/ipv6_children_bulk.hpp"
#include "nanotins/spec_dag.hpp"

#include <exec/static_thread_pool.hpp>

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <vector>

using G = nanotins::L2L3Graph;

namespace {

#define CHECK(cond)                                                             \
    do {                                                                        \
        if (!(cond)) {                                                          \
            std::fprintf(stderr, "FAIL %s:%d %s\n", __FILE__, __LINE__, #cond); \
            std::exit(1);                                                       \
        }                                                                       \
    } while (0)

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
void put_srh(Frame& f, std::uint8_t next, std::uint8_t nseg, const std::vector<std::uint8_t>& tlv) {
    const std::size_t total = 8 + std::size_t{nseg} * 16 + tlv.size();
    f.u8(next); f.u8(static_cast<std::uint8_t>(total / 8 - 1)); f.u8(4); f.u8(nseg); f.u8(nseg - 1);
    f.u8(0); f.u16(0xBEEF);
    for (std::uint8_t s = 0; s < nseg; ++s) f.fill(16, static_cast<std::uint8_t>(0x30 + s));
    for (auto x : tlv) f.u8(x);
}
void put_opt8(Frame& f, std::uint8_t next, std::uint8_t opt_type) {
    f.u8(next); f.u8(0); f.u8(opt_type); f.u8(4); f.fill(4, 0xCC);
}
void put_fragment(Frame& f, std::uint8_t next) { f.u8(next); f.u8(0); f.u16(0); f.u32(0xABCD); }

// One of seven extension shapes, parameterized by i so the batch has multi-row variety.
std::vector<std::uint8_t> make_packet(std::size_t i) {
    Frame f;
    put_eth(f);
    const std::vector<std::uint8_t> tlv6 = {5, 6, 0, 0, 0, 0, 0, 0};  // [type5][len6][6 bytes]
    switch (i % 7) {
        case 0: put_ipv6(f, 17); put_udp(f); break;                                   // plain
        case 1: put_ipv6(f, 0); put_opt8(f, 6, 5); put_tcp(f); break;                 // hop-by-hop opt
        case 2: put_ipv6(f, 43); put_srh(f, 17, static_cast<std::uint8_t>(1 + i % 4), {}); put_udp(f); break;
        case 3: put_ipv6(f, 43); put_srh(f, 17, 2, tlv6); put_udp(f); break;          // srh + tlv
        case 4: put_ipv6(f, 44); put_fragment(f, 17); put_udp(f); break;              // fragment
        case 5: put_ipv6(f, 60); put_opt8(f, 17, 6); put_udp(f); break;               // dest-opts
        case 6: put_ipv6(f, 43); put_srh(f, 0, 3, {}); put_opt8(f, 6, 7); put_tcp(f); break;  // srh + hbh
    }
    return f.b;
}

bool child_equal(const nanotins::ipv6_child_tables& a, const nanotins::ipv6_child_tables& b) {
    return a.srh_segment.packet_id == b.srh_segment.packet_id &&
           a.srh_segment.srh_order == b.srh_segment.srh_order &&
           a.srh_segment.segment_index == b.srh_segment.segment_index &&
           a.srh_segment.address == b.srh_segment.address && a.opt.packet_id == b.opt.packet_id &&
           a.opt.container_type == b.opt.container_type && a.opt.opt_type == b.opt.opt_type &&
           a.opt.opt_len == b.opt.opt_len;
}

}  // namespace

int main() {
    const int root = nanotins::kEthRoot;
    constexpr std::size_t N = 100000;

    std::vector<std::vector<std::uint8_t>> bufs;
    bufs.reserve(N);
    for (std::size_t i = 0; i < N; ++i) bufs.push_back(make_packet(i));

    std::vector<nanotins::dag_packet> pkts;
    pkts.reserve(N);
    for (std::size_t i = 0; i < N; ++i) pkts.push_back({bufs[i].data(), bufs[i].size(), i});

    // Reference: sequential decode of fixed + child tables, packet by packet.
    nanotins::dag_tables<G> ref_tabs;
    nanotins::ipv6_child_tables ref_kids;
    for (const auto& p : pkts) {
        nanotins::dag_decode_packet_with_children<G>(p.packet_id, p.data, p.size, ref_tabs, ref_kids, root);
    }

    // Bulk child tables, serial executor.
    nanotins::ipv6_child_tables kids_serial;
    nanotins::ipv6_children_bulk<G>(pkts, kids_serial, root, [](std::size_t nt, std::size_t n, auto k) {
        nanotins::serial_for_each(nt, n, k);
    });

    // Bulk child tables, thread-pool executor (the real parallel scatter).
    nanotins::ipv6_child_tables kids_pool;
    exec::static_thread_pool pool{4};
    auto sched = pool.get_scheduler();
    nanotins::ipv6_children_bulk<G>(pkts, kids_pool, root, [&](std::size_t nt, std::size_t n, auto k) {
        nanotins::bulk_for_each(sched, nt, n, k);
    });

    CHECK(child_equal(ref_kids, kids_serial));
    CHECK(child_equal(ref_kids, kids_pool));

    // sanity: the batch actually produced a lot of segment + option rows.
    CHECK(ref_kids.srh_segment.size() > N / 4);
    CHECK(ref_kids.opt.size() > N / 8);

    std::printf("ipv6_children_bulk: ok (serial == bulk == pool; %zu packets, %zu segments, %zu options)\n",
                N, ref_kids.srh_segment.size(), ref_kids.opt.size());
    return 0;
}
