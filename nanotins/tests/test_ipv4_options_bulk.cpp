// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Yoav Bendor

// The IPv4 option child table must be byte-identical whether built serially
// (dag_decode_packet_with_ipv4_children) or via the bulk count->scan->scatter path (ipv4_children_bulk),
// and identically whether the bulk scatter runs in-thread or on a thread pool. This is the determinism
// proof the GPU path needs: every write index is a pure function of the packet's prefix-summed base + emit
// order. Runs over a large randomized batch mixing every option shape (and a non-IPv4 packet, to prove the
// option walk fires only on the Ipv4Node).

#include "nanotins/dag_bulk.hpp"
#include "nanotins/dag_decode.hpp"
#include "nanotins/ipv4_children.hpp"
#include "nanotins/ipv4_children_bulk.hpp"
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
void put_eth4(Frame& f) { f.fill(6, 0x11); f.fill(6, 0x22); f.u16(0x0800); }
void put_eth6(Frame& f) { f.fill(6, 0x11); f.fill(6, 0x22); f.u16(0x86DD); }
void put_ipv6(Frame& f, std::uint8_t nh) {
    f.u8(0x60); f.u8(0); f.u16(0); f.u16(0); f.u8(nh); f.u8(64); f.fill(16, 0xAA); f.fill(16, 0xBB);
}
void put_udp(Frame& f) { f.u16(1); f.u16(2); f.u16(8); f.u16(0); }
void put_tcp(Frame& f) { f.u16(1); f.u16(2); f.u32(0); f.u32(0); f.u16(0x5000); f.u16(0); f.u16(0); f.u16(0); }
void put_ipv4(Frame& f, std::uint8_t proto, const std::vector<std::uint8_t>& opts) {
    const std::uint8_t ihl = static_cast<std::uint8_t>((20 + opts.size()) / 4);
    f.u8(static_cast<std::uint8_t>(0x40 | ihl)); f.u8(0); f.u16(0); f.u16(0); f.u16(0); f.u8(64); f.u8(proto);
    f.u16(0); f.fill(4, 0xC0); f.fill(4, 0xC8);
    for (auto x : opts) f.u8(x);
}

// One of seven shapes, parameterized by i so the batch has multi-row variety.
std::vector<std::uint8_t> make_packet(std::size_t i) {
    Frame f;
    switch (i % 7) {
        case 0: put_eth4(f); put_ipv4(f, 17, {}); put_udp(f); break;                              // no options
        case 1: put_eth4(f); put_ipv4(f, 6, {0x94, 0x04, 0x00, 0x00}); put_tcp(f); break;         // router alert
        case 2: put_eth4(f); put_ipv4(f, 17, {0x44, 0x08, 0, 0, 0, 0, 0, 0}); put_udp(f); break;  // timestamp
        case 3: put_eth4(f); put_ipv4(f, 17, {0x01, 0x01, 0x00, 0x00}); put_udp(f); break;        // NOP/NOP/EOOL
        case 4: put_eth4(f); put_ipv4(f, 6, {0x94, 0x04, 0x00, 0x00, 0x01, 0x01, 0x01, 0x00}); put_tcp(f); break;
        case 5: put_eth6(f); put_ipv6(f, 17); put_udp(f); break;                                  // non-IPv4
        case 6: put_eth4(f); put_ipv4(f, 17, {0x07, 0x07, 0, 0, 0, 0, 0, 0x00}); put_udp(f); break;  // RR + EOOL
    }
    return f.b;
}

bool opt_equal(const nanotins::ipv4_child_tables& a, const nanotins::ipv4_child_tables& b) {
    return a.opt.packet_id == b.opt.packet_id && a.opt.opt_type == b.opt.opt_type &&
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

    // Reference: sequential decode of fixed + IPv4 option tables, packet by packet.
    nanotins::dag_tables<G> ref_tabs;
    nanotins::ipv4_child_tables ref_kids;
    for (const auto& p : pkts) {
        nanotins::dag_decode_packet_with_ipv4_children<G>(p.packet_id, p.data, p.size, ref_tabs, ref_kids, root);
    }

    // Bulk option table, serial executor.
    nanotins::ipv4_child_tables kids_serial;
    nanotins::ipv4_children_bulk<G>(pkts, kids_serial, root, [](std::size_t nt, std::size_t n, auto k) {
        nanotins::serial_for_each(nt, n, k);
    });

    // Bulk option table, thread-pool executor (the real parallel scatter).
    nanotins::ipv4_child_tables kids_pool;
    exec::static_thread_pool pool{4};
    auto sched = pool.get_scheduler();
    nanotins::ipv4_children_bulk<G>(pkts, kids_pool, root, [&](std::size_t nt, std::size_t n, auto k) {
        nanotins::bulk_for_each(sched, nt, n, k);
    });

    CHECK(opt_equal(ref_kids, kids_serial));
    CHECK(opt_equal(ref_kids, kids_pool));

    // sanity: the batch actually produced a lot of option rows.
    CHECK(ref_kids.opt.size() > N / 2);

    std::printf("ipv4_options_bulk: ok (serial == bulk == pool; %zu packets, %zu options)\n", N,
                ref_kids.opt.size());
    return 0;
}
