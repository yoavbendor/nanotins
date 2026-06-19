// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Yoav Bendor

// SOME/IP-SD Phase 2: the entries + options child tables decoded off a SomeipNode carrying the SD message
// (Message ID 0xFFFF8100). Covers:
//   T1  one OfferService entry + one IPv4 endpoint option -> correct entry & option rows (incl. endpoint
//       address/proto/port decode), via dag_decode_packet_with_someip_sd
//   T2  count_packet_someip_sd_children == the rows actually emitted (count/scatter parity)
//   T3  IPv6 endpoint option decode (16-byte address)
//   T4  negative: a non-SD SOME/IP message (service_id != 0xFFFF) yields no SD children
//   T5  truncation: a packet clipped mid-option still emits the entry and stops cleanly (no OOB)

#include "nanotins/someip_sd.hpp"

#include <array>
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

void put8(std::vector<std::uint8_t>& b, std::size_t o, std::uint8_t v) { b[o] = v; }
void put16(std::vector<std::uint8_t>& b, std::size_t o, std::uint16_t v) {
    b[o] = static_cast<std::uint8_t>(v >> 8);
    b[o + 1] = static_cast<std::uint8_t>(v);
}
void put32(std::vector<std::uint8_t>& b, std::size_t o, std::uint32_t v) {
    b[o] = static_cast<std::uint8_t>(v >> 24);
    b[o + 1] = static_cast<std::uint8_t>(v >> 16);
    b[o + 2] = static_cast<std::uint8_t>(v >> 8);
    b[o + 3] = static_cast<std::uint8_t>(v);
}

constexpr std::size_t kSo = 42;  // SOME/IP header offset (eth 14 + ipv4 20 + udp 8)

// Lay eth/ipv4/udp:30490 framing into a buffer sized for the SOME/IP message + SD payload at kSo.
void frame(std::vector<std::uint8_t>& b) {
    put16(b, 12, 0x0800);                              // ethertype IPv4
    put8(b, 14, 0x45);                                 // IPv4 v4 IHL5
    put8(b, 23, 17);                                   // protocol UDP
    put16(b, kSo - 8 + 2, nanotins::kSomeipSdPort);    // UDP dst_port 30490 (udp at offset 34, dst at 36)
}

// Write the 16-byte SOME/IP-SD header (service 0xFFFF / method 0x8100) at kSo with the given payload length.
void put_sd_someip(std::vector<std::uint8_t>& b, std::uint32_t payload_len, std::uint16_t service = 0xFFFF,
                   std::uint16_t method = 0x8100) {
    put16(b, kSo + 0, service);
    put16(b, kSo + 2, method);
    put32(b, kSo + 4, 8u + payload_len);  // length covers Request ID..payload (= 8 + payload)
    put8(b, kSo + 12, 0x01);              // protocol_version
    put8(b, kSo + 13, 0x01);              // interface_version
    put8(b, kSo + 14, nanotins::kSomeipNotification);
    put8(b, kSo + 15, 0x00);
}

}  // namespace

int main() {
    using G = nanotins::L2L3Graph;

    // ---- T1: OfferService entry + IPv4 endpoint option ----
    {
        // SD payload = preamble(8) + 1 entry(16) + opt_len(4) + 1 ipv4-endpoint option(12) = 40 bytes.
        const std::uint32_t entries_len = 16, options_len = 12, sd_len = 8 + entries_len + 4 + options_len;
        std::vector<std::uint8_t> b(kSo + 16 + sd_len, 0);
        frame(b);
        put_sd_someip(b, sd_len);

        const std::size_t sd = kSo + 16;
        put8(b, sd + 0, 0xC0);                 // flags: reboot + unicast
        put32(b, sd + 4, entries_len);         // entries array length
        const std::size_t e = sd + 8;          // entry 0
        put8(b, e + 0, nanotins::kSdEntryOfferService);  // type 0x01
        put8(b, e + 1, 0x00);                  // index 1st opts
        put8(b, e + 2, 0x00);                  // index 2nd opts
        put8(b, e + 3, 0x10);                  // num_opt_1=1, num_opt_2=0
        put16(b, e + 4, 0x1234);               // service id
        put16(b, e + 6, 0x0001);               // instance id
        put8(b, e + 8, 0x02);                  // major version
        put8(b, e + 9, 0x00);
        put8(b, e + 10, 0x00);
        put8(b, e + 11, 0x03);                 // ttl = 3
        put32(b, e + 12, 0x0000000A);          // minor version = 10
        const std::size_t ol = e + 16;         // options length word
        put32(b, ol, options_len);
        const std::size_t o = ol + 4;          // option 0 (IPv4 endpoint)
        put16(b, o + 0, 0x0009);               // length 9
        put8(b, o + 2, nanotins::kSdOptIpv4Endpoint);  // type 0x04
        put8(b, o + 3, 0x00);                  // reserved
        put8(b, o + 4, 192); put8(b, o + 5, 168); put8(b, o + 6, 1); put8(b, o + 7, 5);  // 192.168.1.5
        put8(b, o + 8, 0x00);                  // reserved
        put8(b, o + 9, 0x11);                  // L4 proto = UDP (17)
        put16(b, o + 10, 30402);               // port

        nanotins::dag_tables<G> tabs;
        nanotins::someip_sd_child_tables kids;
        nanotins::dag_decode_packet_with_someip_sd<G>(/*pid=*/1, b.data(), b.size(), tabs, kids);

        // the SomeipNode fixed row still lands
        auto& st = std::get<nanotins::node_id_v<nanotins::SomeipNode, G>>(tabs);
        CHECK(st.size() == 1);

        CHECK(kids.entry.size() == 1);
        CHECK(kids.entry.type[0] == nanotins::kSdEntryOfferService);
        CHECK(kids.entry.entry_index[0] == 0);
        CHECK(kids.entry.num_opt_1[0] == 1 && kids.entry.num_opt_2[0] == 0);
        CHECK(kids.entry.service_id[0] == 0x1234);
        CHECK(kids.entry.instance_id[0] == 0x0001);
        CHECK(kids.entry.major_version[0] == 0x02);
        CHECK(kids.entry.ttl[0] == 3);
        CHECK(kids.entry.minor_version[0] == 0x0A);

        CHECK(kids.option.size() == 1);
        CHECK(kids.option.length[0] == 9);
        CHECK(kids.option.type[0] == nanotins::kSdOptIpv4Endpoint);
        CHECK(kids.option.l4proto[0] == 0x11);
        CHECK(kids.option.port[0] == 30402);
        const auto& a = kids.option.address[0];
        CHECK(a[0] == 192 && a[1] == 168 && a[2] == 1 && a[3] == 5);
        CHECK(a[4] == 0 && a[15] == 0);  // IPv4 lives in the first 4 bytes, rest zero

        // ---- T2: count == emitted rows ----
        const auto cnt = nanotins::count_packet_someip_sd_children<G>(nanotins::kEthRoot, b.data(), b.size());
        CHECK(cnt.entry == kids.entry.size());
        CHECK(cnt.option == kids.option.size());
    }

    // ---- T3: IPv6 endpoint option (16-byte address) ----
    {
        const std::uint32_t entries_len = 16, options_len = 24, sd_len = 8 + entries_len + 4 + options_len;
        std::vector<std::uint8_t> b(kSo + 16 + sd_len, 0);
        frame(b);
        put_sd_someip(b, sd_len);
        const std::size_t sd = kSo + 16;
        put32(b, sd + 4, entries_len);
        const std::size_t e = sd + 8;
        put8(b, e + 0, nanotins::kSdEntrySubscribeEventgroup);
        const std::size_t ol = e + 16;
        put32(b, ol, options_len);
        const std::size_t o = ol + 4;          // IPv6 endpoint option (24 bytes)
        put16(b, o + 0, 0x0015);               // length 21
        put8(b, o + 2, nanotins::kSdOptIpv6Endpoint);  // type 0x06
        for (int i = 0; i < 16; ++i) put8(b, o + 4 + i, static_cast<std::uint8_t>(0xA0 + i));
        put8(b, o + 21, 0x06);                 // L4 proto = TCP
        put16(b, o + 22, 40000);               // port

        nanotins::someip_sd_child_tables kids;
        const std::uint8_t* end = b.data() + b.size();
        nanotins::emit_sd_children(2, b.data(), kSo, b.size(), end, kids);
        CHECK(kids.entry.size() == 1 && kids.entry.type[0] == nanotins::kSdEntrySubscribeEventgroup);
        CHECK(kids.option.size() == 1);
        CHECK(kids.option.type[0] == nanotins::kSdOptIpv6Endpoint);
        CHECK(kids.option.l4proto[0] == 0x06 && kids.option.port[0] == 40000);
        const auto& a = kids.option.address[0];
        for (int i = 0; i < 16; ++i) CHECK(a[i] == static_cast<std::uint8_t>(0xA0 + i));
    }

    // ---- T4: negative — a non-SD SOME/IP message yields no SD children ----
    {
        std::vector<std::uint8_t> b(kSo + 16 + 40, 0);
        frame(b);
        put_sd_someip(b, 40, /*service=*/0x1111, /*method=*/0x0001);  // NOT the SD message id
        nanotins::someip_sd_child_tables kids;
        nanotins::emit_sd_children(3, b.data(), kSo, b.size(), b.data() + b.size(), kids);
        CHECK(kids.entry.size() == 0 && kids.option.size() == 0);
        const auto cnt = nanotins::count_packet_someip_sd_children<G>(nanotins::kEthRoot, b.data(), b.size());
        CHECK(cnt.entry == 0 && cnt.option == 0);
    }

    // ---- T5: truncation — clip mid-option; the entry still emits, the option walk stops (no OOB) ----
    {
        const std::uint32_t entries_len = 16, options_len = 12, sd_len = 8 + entries_len + 4 + options_len;
        std::vector<std::uint8_t> full(kSo + 16 + sd_len, 0);
        frame(full);
        put_sd_someip(full, sd_len);
        const std::size_t sd = kSo + 16;
        put32(full, sd + 4, entries_len);
        put8(full, sd + 8, nanotins::kSdEntryOfferService);
        const std::size_t ol = sd + 8 + 16;
        put32(full, ol, options_len);
        put16(full, ol + 4, 0x0009);
        put8(full, ol + 6, nanotins::kSdOptIpv4Endpoint);
        // clip the buffer so the option's value is cut short
        std::vector<std::uint8_t> b(full.begin(), full.begin() + (ol + 4 + 5));

        nanotins::someip_sd_child_tables kids;
        nanotins::emit_sd_children(4, b.data(), kSo, b.size(), b.data() + b.size(), kids);
        CHECK(kids.entry.size() == 1);    // the entry fits and is emitted
        CHECK(kids.option.size() == 0);   // the option is truncated -> not emitted, no OOB read
    }

    std::printf("someip_sd: ok (T1 offer+ipv4 opt, T2 count parity, T3 ipv6 opt, T4 non-SD, T5 truncation)\n");
    return 0;
}
