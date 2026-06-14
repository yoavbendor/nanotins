// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Yoav Bendor

// Smoke test for the pcapng2json core: build a synthetic pcapng in memory (one real Ethernet/IPv4/UDP
// frame), run the conversion in-process, and check the NDJSON shape + decoded fields. No external capture
// file and no subprocess needed.

#include "pcapng2json.hpp"

#include "pcap_fixtures.hpp"  // pcapfix::Builder / append_block / shb_body / idb_body / epb_body

#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <string>
#include <vector>

#define CHECK(cond)                                                            \
    do {                                                                       \
        if (!(cond)) {                                                         \
            std::fprintf(stderr, "FAIL %s:%d %s\n", __FILE__, __LINE__, #cond); \
            std::exit(1);                                                      \
        }                                                                      \
    } while (0)

namespace {

// One Ethernet + IPv4 + UDP frame, fixed big-endian wire bytes (independent of the pcapng container's
// byte order). UDP 1234 -> 53, 10.0.0.1 -> 10.0.0.2, 4-byte payload.
std::vector<std::uint8_t> udp_frame() {
    std::vector<std::uint8_t> f = {
        // Ethernet: dst, src, ethertype=0x0800
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x08, 0x00,
        // IPv4: v/ihl=0x45, dscp=0, total_len=32, id=0, flags/frag=0, ttl=64, proto=17(UDP), csum=0
        0x45, 0x00, 0x00, 0x20, 0x00, 0x00, 0x00, 0x00, 0x40, 0x11, 0x00, 0x00,
        0x0a, 0x00, 0x00, 0x01,  // src 10.0.0.1
        0x0a, 0x00, 0x00, 0x02,  // dst 10.0.0.2
        // UDP: src=1234(0x04D2), dst=53(0x0035), len=12, csum=0
        0x04, 0xd2, 0x00, 0x35, 0x00, 0x0c, 0x00, 0x00,
        // payload
        0xde, 0xad, 0xbe, 0xef};
    return f;
}

std::vector<std::uint8_t> build_capture(bool le) {
    const std::vector<std::uint8_t> frame = udp_frame();
    pcapfix::Builder b(le);
    pcapfix::append_block(b, pcapblocks::kBlockTypeShb, pcapfix::shb_body(le));
    pcapfix::append_block(b, pcapblocks::kBlockTypeIdb, pcapfix::idb_body(le, /*link_type=*/1, /*tsresol=*/6));
    pcapfix::append_block(b, pcapblocks::kBlockTypeEpb,
                          pcapfix::epb_body(le, /*iface=*/0, /*ts=*/0x0000000100000002ULL,
                                            static_cast<std::uint32_t>(frame.size()),
                                            static_cast<std::uint32_t>(frame.size()), frame, /*flags=*/0));
    return b.bytes;
}

bool contains(const std::string& hay, const char* needle) { return hay.find(needle) != std::string::npos; }

}  // namespace

int main() {
    for (bool le : {true, false}) {
        const std::vector<std::uint8_t> cap = build_capture(le);
        std::string out, err;
        CHECK(pcapng2json::to_ndjson(pcapblocks::Bytes(cap.data(), cap.size()), out, err));
        CHECK(err.empty());

        // Exactly one packet -> one NDJSON line.
        CHECK(!out.empty());
        CHECK(out.back() == '\n');
        CHECK(std::count(out.begin(), out.end(), '\n') == 1);

        // L1 fields + decoded layers.
        CHECK(contains(out, "\"packet_id\":0"));
        CHECK(contains(out, "\"link_type\":1"));
        CHECK(contains(out, "\"type\":\"ethernet\""));
        CHECK(contains(out, "\"ethertype\":\"0x0800\""));
        CHECK(contains(out, "\"type\":\"ipv4\""));
        CHECK(contains(out, "\"src\":\"10.0.0.1\""));
        CHECK(contains(out, "\"dst\":\"10.0.0.2\""));
        CHECK(contains(out, "\"protocol\":17"));
        CHECK(contains(out, "\"type\":\"udp\""));
        CHECK(contains(out, "\"src_port\":1234"));
        CHECK(contains(out, "\"dst_port\":53"));
    }

    std::printf("pcapng2json: ok (Ethernet/IPv4/UDP decode, LE + BE containers)\n");
    return 0;
}
