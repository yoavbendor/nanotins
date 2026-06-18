// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Yoav Bendor

// SOME/IP Phase 1: the fixed 16-byte message header as a wire_spec, wired into the DAG under UDP/TCP on the
// well-known SOME/IP-SD port. Covers:
//   T1  struct_view / read_field over the 16-byte header == hand-decoded big-endian values
//   T2  DAG walk: eth/ipv4/udp:30490 -> SomeipNode emitted at the post-UDP offset; columnar decode matches
//   T3  src-port match: a SOME/IP source port (reply direction) also dispatches
//   T4  negative: a non-SOME/IP UDP port leaves UDP a leaf (no SOME/IP row) — parity with the old behavior
//   T5  TCP transport: eth/ipv4/tcp:30490 -> SomeipNode at the post-TCP offset

#include "nanotins/dag_decode.hpp"
#include "nanotins/spec_dag.hpp"
#include "nanotins/wire_spec.hpp"

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <vector>

using namespace nanotins::literals;

namespace {

#define CHECK(cond)                                                            \
    do {                                                                       \
        if (!(cond)) {                                                         \
            std::fprintf(stderr, "FAIL %s:%d %s\n", __FILE__, __LINE__, #cond); \
            std::exit(1);                                                      \
        }                                                                      \
    } while (0)

void put8(std::vector<std::uint8_t>& b, std::size_t off, std::uint8_t v) { b[off] = v; }
void put16(std::vector<std::uint8_t>& b, std::size_t off, std::uint16_t v) {
    b[off] = static_cast<std::uint8_t>(v >> 8);
    b[off + 1] = static_cast<std::uint8_t>(v);
}
void put32(std::vector<std::uint8_t>& b, std::size_t off, std::uint32_t v) {
    b[off] = static_cast<std::uint8_t>(v >> 24);
    b[off + 1] = static_cast<std::uint8_t>(v >> 16);
    b[off + 2] = static_cast<std::uint8_t>(v >> 8);
    b[off + 3] = static_cast<std::uint8_t>(v);
}

// Write a SOME/IP header (host values) big-endian at `off`.
void put_someip(std::vector<std::uint8_t>& b, std::size_t off, std::uint16_t svc, std::uint16_t method,
                std::uint32_t len, std::uint16_t client, std::uint16_t session, std::uint8_t proto,
                std::uint8_t iface, std::uint8_t mtype, std::uint8_t rc) {
    put16(b, off + 0, svc);
    put16(b, off + 2, method);
    put32(b, off + 4, len);
    put16(b, off + 8, client);
    put16(b, off + 10, session);
    put8(b, off + 12, proto);
    put8(b, off + 13, iface);
    put8(b, off + 14, mtype);
    put8(b, off + 15, rc);
}

using G = nanotins::L2L3Graph;
constexpr int kSomeip = nanotins::node_id_v<nanotins::SomeipNode, G>;
constexpr int kUdp = nanotins::node_id_v<nanotins::UdpNode, G>;
constexpr int kTcp = nanotins::node_id_v<nanotins::TcpNode, G>;

// The (node-id, offset) trace the DAG produces from the Ethernet root.
std::vector<std::pair<int, std::size_t>> dag_trace(const std::vector<std::uint8_t>& b) {
    std::vector<std::pair<int, std::size_t>> t;
    nanotins::walk<G>(nanotins::kEthRoot, b.data(), b.size(),
                      [&](auto Ic, std::size_t off) { t.emplace_back(static_cast<int>(decltype(Ic)::value), off); });
    return t;
}

// Build eth/ipv4/(udp|tcp) framing with the given L4 ports, leaving room for a SOME/IP header at l4+l4len.
// Returns the SOME/IP offset. proto: 17 UDP (l4len 8) or 6 TCP (l4len 20).
std::size_t build_l4(std::vector<std::uint8_t>& b, std::uint8_t proto, std::uint16_t src, std::uint16_t dst) {
    put16(b, 12, 0x0800);  // ethertype IPv4
    put8(b, 14, 0x45);     // version 4, IHL 5 (20-byte header)
    put8(b, 23, proto);    // IPv4 protocol (offset 14 + 9)
    const std::size_t l4 = 34;
    put16(b, l4 + 0, src);
    put16(b, l4 + 2, dst);
    if (proto == 6) {
        put8(b, l4 + 12, 0x50);  // TCP data_offset 5 (20-byte header)
        return l4 + 20;
    }
    return l4 + 8;  // UDP
}

}  // namespace

int main() {
    // ---- T1: the 16-byte header, struct_view / read_field == hand values ----
    {
        std::vector<std::uint8_t> b(nanotins::kSomeipHeaderLen, 0);
        put_someip(b, 0, 0x1234, 0x5678, 0x00000020, 0x0042, 0x0007, 0x01, 0x02, 0x80, 0x00);
        nanotins::struct_view<nanotins::SomeipSpec> v(b.data());
        CHECK(v("service_id"_fld) == 0x1234);
        CHECK(v("method_id"_fld) == 0x5678);
        CHECK(v("length"_fld) == 0x20);
        CHECK(v("client_id"_fld) == 0x0042);
        CHECK(v("session_id"_fld) == 0x0007);
        CHECK(v("protocol_version"_fld) == 0x01);
        CHECK(v("interface_version"_fld) == 0x02);
        CHECK(v("message_type"_fld) == nanotins::kSomeipResponse);
        CHECK(v("return_code"_fld) == 0x00);
        CHECK(nanotins::spec_size<nanotins::SomeipSpec>() == 16);
    }

    // ---- T2: DAG walk eth/ipv4/udp:30490 -> SomeipNode; columnar decode matches ----
    {
        std::vector<std::uint8_t> b(58, 0);  // 42 framing + 16 SOME/IP
        const std::size_t so = build_l4(b, 17, 0x9000, nanotins::kSomeipSdPort);
        CHECK(so == 42);
        put_someip(b, so, nanotins::kSomeipSdServiceId, nanotins::kSomeipSdMethodId, 0x10, 0x0000, 0x0001,
                   0x01, 0x01, nanotins::kSomeipNotification, 0x00);

        const auto t = dag_trace(b);
        CHECK(t.size() == 4);                                   // eth, ipv4, udp, someip
        CHECK(t.back().first == kSomeip && t.back().second == so);

        nanotins::dag_tables<G> tabs;
        nanotins::dag_decode_packet<G>(/*packet_id=*/7, b.data(), b.size(), tabs);
        auto& st = std::get<kSomeip>(tabs);
        CHECK(st.size() == 1);
        CHECK(st.packet_id[0] == 7);
        CHECK(st.template column<0>()[0] == nanotins::kSomeipSdServiceId);  // service_id
        CHECK(st.template column<1>()[0] == nanotins::kSomeipSdMethodId);   // method_id
        CHECK(st.template column<2>()[0] == 0x10u);                         // length
        CHECK(st.template column<4>()[0] == 0x0001);                       // session_id
        CHECK(st.template column<7>()[0] == nanotins::kSomeipNotification);  // message_type
    }

    // ---- T3: source-port match (reply direction) also dispatches ----
    {
        std::vector<std::uint8_t> b(58, 0);
        const std::size_t so = build_l4(b, 17, nanotins::kSomeipSdPort, 0x9000);  // SD port as SOURCE
        put_someip(b, so, 0x1111, 0x2222, 0x08, 0, 0, 0x01, 0x01, nanotins::kSomeipResponse, 0x00);
        const auto t = dag_trace(b);
        CHECK(t.size() == 4 && t.back().first == kSomeip);
    }

    // ---- T4: negative — a non-SOME/IP UDP port keeps UDP a leaf (no SOME/IP row) ----
    {
        std::vector<std::uint8_t> b(58, 0);
        build_l4(b, 17, 0x9000, 0x0035);  // dst port 53 (DNS), not SOME/IP
        const auto t = dag_trace(b);
        CHECK(t.size() == 3);                 // eth, ipv4, udp — stops at UDP
        CHECK(t.back().first == kUdp);
    }

    // ---- T5: TCP transport — eth/ipv4/tcp:30490 -> SomeipNode at the post-TCP offset ----
    {
        std::vector<std::uint8_t> b(70, 0);  // 54 framing (20-byte TCP) + 16 SOME/IP
        const std::size_t so = build_l4(b, 6, 0x9000, nanotins::kSomeipSdPort);
        CHECK(so == 54);
        put_someip(b, so, 0x1234, 0x0001, 0x08, 0, 0, 0x01, 0x01, nanotins::kSomeipRequest, 0x00);
        const auto t = dag_trace(b);
        CHECK(t.size() == 4);
        CHECK(t.back().first == kSomeip && t.back().second == so);
        CHECK(t[2].first == kTcp);
    }

    std::printf("someip: ok (T1 header oracle, T2 udp DAG+decode, T3 src-port, T4 negative leaf, T5 tcp)\n");
    return 0;
}
