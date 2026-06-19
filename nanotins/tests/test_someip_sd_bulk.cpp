// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Yoav Bendor

// SOME/IP Phase 2b: the SOME/IP-SD child tables (entries + options) must be byte-identical whether built
// serially (dag_decode_packet_with_someip_sd) or via the bulk count->scan->scatter path (someip_sd_bulk),
// and identically whether the bulk scatter runs in-thread or on a thread pool. This is the determinism
// proof the GPU path needs: every write index is a pure function of the packet's prefix-summed base + emit
// order. Runs over a large randomized batch mixing entry counts, IPv4/IPv6/config options, non-SD SOME/IP
// messages (zero children), and plain UDP (no SomeipNode at all).

#include "nanotins/dag_bulk.hpp"
#include "nanotins/dag_decode.hpp"
#include "nanotins/someip_sd.hpp"
#include "nanotins/someip_sd_bulk.hpp"
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

struct Vec {
    std::vector<std::uint8_t> b;
    void u8(std::uint8_t v) { b.push_back(v); }
    void u16(std::uint16_t v) { b.push_back(v >> 8); b.push_back(v & 0xFF); }
    void u32(std::uint32_t v) { for (int i = 3; i >= 0; --i) b.push_back((v >> (8 * i)) & 0xFF); }
    void fill(std::size_t n, std::uint8_t v = 0) { for (std::size_t i = 0; i < n; ++i) b.push_back(v); }
};

// A 16-byte SD entry.
void append_entry(Vec& sd, std::uint8_t type, std::uint16_t service, std::uint16_t instance,
                  std::uint8_t major, std::uint32_t ttl, std::uint32_t minor, std::uint8_t no1,
                  std::uint8_t no2) {
    sd.u8(type); sd.u8(0); sd.u8(0); sd.u8(static_cast<std::uint8_t>((no1 << 4) | (no2 & 0x0F)));
    sd.u16(service); sd.u16(instance);
    sd.u8(major); sd.u8((ttl >> 16) & 0xFF); sd.u8((ttl >> 8) & 0xFF); sd.u8(ttl & 0xFF);
    sd.u32(minor);
}
void append_ipv4_opt(Vec& sd, std::uint8_t type, std::uint32_t addr, std::uint8_t l4, std::uint16_t port) {
    sd.u16(0x0009); sd.u8(type); sd.u8(0); sd.u32(addr); sd.u8(0); sd.u8(l4); sd.u16(port);
}
void append_ipv6_opt(Vec& sd, std::uint8_t type, std::uint8_t seed, std::uint8_t l4, std::uint16_t port) {
    sd.u16(0x0015); sd.u8(type); sd.u8(0);
    for (int i = 0; i < 16; ++i) sd.u8(static_cast<std::uint8_t>(seed + i));
    sd.u8(0); sd.u8(l4); sd.u16(port);
}
void append_config_opt(Vec& sd, std::uint8_t n) {  // generic (non-endpoint) option: type 0x01 + n data bytes
    sd.u16(static_cast<std::uint16_t>(n)); sd.u8(0x01); sd.fill(n, 0x5A);
}

// Assemble eth/ipv4/udp(:dport)/someip(service/method) + the given SD payload bytes into one packet.
std::vector<std::uint8_t> assemble(std::uint16_t dport, std::uint16_t service, std::uint16_t method,
                                   const std::vector<std::uint8_t>& sd_payload) {
    Vec f;
    f.fill(6, 0x11); f.fill(6, 0x22); f.u16(0x0800);                 // eth
    f.u8(0x45); f.u8(0); f.u16(0); f.u16(0); f.u16(0);               // ipv4 [0..9]
    f.u8(64); f.u8(17); f.u16(0); f.u32(0); f.u32(0);                // ttl, proto=UDP, csum, src, dst
    f.u16(40000); f.u16(dport); f.u16(8); f.u16(0);                  // udp
    f.u16(service); f.u16(method); f.u32(static_cast<std::uint32_t>(8 + sd_payload.size()));  // someip msg id+len
    f.u16(0); f.u16(0); f.u8(1); f.u8(1); f.u8(0x02); f.u8(0);       // req id, versions, msgtype, rc
    for (auto x : sd_payload) f.u8(x);
    return f.b;
}

// Build an SD payload (preamble + entries + options arrays) from entry/option byte blobs.
std::vector<std::uint8_t> sd_payload(const std::vector<std::uint8_t>& entries,
                                     const std::vector<std::uint8_t>& options) {
    Vec sd;
    sd.u8(0xC0); sd.fill(3, 0);                                       // flags + reserved
    sd.u32(static_cast<std::uint32_t>(entries.size()));
    for (auto x : entries) sd.u8(x);
    sd.u32(static_cast<std::uint32_t>(options.size()));
    for (auto x : options) sd.u8(x);
    return sd.b;
}

// Six packet shapes, parameterized by i for multi-row variety.
std::vector<std::uint8_t> make_packet(std::size_t i) {
    const std::uint16_t sd = nanotins::kSomeipSdPort;
    switch (i % 6) {
        case 0: {  // 1 OfferService entry + 1 IPv4 endpoint option
            Vec e, o;
            append_entry(e, nanotins::kSdEntryOfferService, static_cast<std::uint16_t>(0x1000 + i), 1, 2, 3,
                         static_cast<std::uint32_t>(i), 1, 0);
            append_ipv4_opt(o, nanotins::kSdOptIpv4Endpoint, 0xC0A80100u + (i & 0xFF), 17,
                            static_cast<std::uint16_t>(30000 + (i & 0x3FF)));
            return assemble(sd, 0xFFFF, 0x8100, sd_payload(e.b, o.b));
        }
        case 1: {  // 2 entries (Find + Offer), no options
            Vec e;
            append_entry(e, nanotins::kSdEntryFindService, 0x2000, 0, 1, 10, 0, 0, 0);
            append_entry(e, nanotins::kSdEntryOfferService, 0x2000, 1, 1, 10, 7, 0, 0);
            return assemble(sd, 0xFFFF, 0x8100, sd_payload(e.b, {}));
        }
        case 2: {  // 0 entries, 1 IPv6 endpoint option
            Vec o;
            append_ipv6_opt(o, nanotins::kSdOptIpv6Endpoint, static_cast<std::uint8_t>(i), 6,
                            static_cast<std::uint16_t>(40000 + (i & 0xFF)));
            return assemble(sd, 0xFFFF, 0x8100, sd_payload({}, o.b));
        }
        case 3: {  // (1..3) Subscribe entries + an IPv4 option + a config option
            Vec e, o;
            const int n = 1 + static_cast<int>(i % 3);
            for (int k = 0; k < n; ++k)
                append_entry(e, nanotins::kSdEntrySubscribeEventgroup,
                             static_cast<std::uint16_t>(0x3000 + k), static_cast<std::uint16_t>(k), 1, 5,
                             static_cast<std::uint32_t>(0xE0000 + k), static_cast<std::uint8_t>(k % 4), 1);
            append_ipv4_opt(o, nanotins::kSdOptIpv4Multicast, 0xE0000001u, 17, 30490);
            append_config_opt(o, static_cast<std::uint8_t>(1 + (i % 5)));
            return assemble(sd, 0xFFFF, 0x8100, sd_payload(e.b, o.b));
        }
        case 4: {  // a non-SD SOME/IP message on the SD port -> SomeipNode emitted, zero SD children
            Vec e;
            append_entry(e, nanotins::kSdEntryOfferService, 0x9999, 1, 1, 1, 1, 0, 0);  // ignored (not SD)
            return assemble(sd, 0x1111, 0x0001, sd_payload(e.b, {}));
        }
        default: {  // plain UDP on a non-SOME/IP port -> no SomeipNode at all
            return assemble(0x0035, 0xFFFF, 0x8100, sd_payload({}, {}));
        }
    }
}

bool entries_equal(const nanotins::someip_sd_entry_table& a, const nanotins::someip_sd_entry_table& b) {
    return a.packet_id == b.packet_id && a.entry_index == b.entry_index && a.type == b.type &&
           a.index_1st_opts == b.index_1st_opts && a.index_2nd_opts == b.index_2nd_opts &&
           a.num_opt_1 == b.num_opt_1 && a.num_opt_2 == b.num_opt_2 && a.service_id == b.service_id &&
           a.instance_id == b.instance_id && a.major_version == b.major_version && a.ttl == b.ttl &&
           a.minor_version == b.minor_version;
}
bool options_equal(const nanotins::someip_sd_option_table& a, const nanotins::someip_sd_option_table& b) {
    return a.packet_id == b.packet_id && a.option_index == b.option_index && a.length == b.length &&
           a.type == b.type && a.l4proto == b.l4proto && a.port == b.port && a.address == b.address;
}
bool kids_equal(const nanotins::someip_sd_child_tables& a, const nanotins::someip_sd_child_tables& b) {
    return entries_equal(a.entry, b.entry) && options_equal(a.option, b.option);
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

    // Reference: sequential decode of fixed + SD child tables, packet by packet.
    nanotins::dag_tables<G> ref_tabs;
    nanotins::someip_sd_child_tables ref_kids;
    for (const auto& p : pkts) {
        nanotins::dag_decode_packet_with_someip_sd<G>(p.packet_id, p.data, p.size, ref_tabs, ref_kids, root);
    }

    // Bulk child tables, serial executor.
    nanotins::someip_sd_child_tables kids_serial;
    nanotins::someip_sd_bulk<G>(pkts, kids_serial, root, [](std::size_t nt, std::size_t n, auto k) {
        nanotins::serial_for_each(nt, n, k);
    });

    // Bulk child tables, thread-pool executor (the real parallel scatter).
    nanotins::someip_sd_child_tables kids_pool;
    exec::static_thread_pool pool{4};
    auto sched = pool.get_scheduler();
    nanotins::someip_sd_bulk<G>(pkts, kids_pool, root, [&](std::size_t nt, std::size_t n, auto k) {
        nanotins::bulk_for_each(sched, nt, n, k);
    });

    CHECK(kids_equal(ref_kids, kids_serial));
    CHECK(kids_equal(ref_kids, kids_pool));

    // sanity: the batch actually produced a lot of entry + option rows.
    CHECK(ref_kids.entry.size() > N / 4);
    CHECK(ref_kids.option.size() > N / 4);

    std::printf("someip_sd_bulk: ok (serial == bulk == pool; %zu packets, %zu entries, %zu options)\n", N,
                ref_kids.entry.size(), ref_kids.option.size());
    return 0;
}
