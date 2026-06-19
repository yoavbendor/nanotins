// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Yoav Bendor

// In-process smoke test for the dpar example core: build a synthetic eth/ipv4/udp packet carrying SOME/IP-
// TLV members, wrap it in a one-packet pcapng, run a rules text through the Engine, and check the NDJSON +
// stats. Exercises the full "lib user brings a parser + a CLI rule drives it" path without spawning the CLI.

#include "dpar_example.hpp"

#include "nanotins/pcap_blocks.hpp"
#include "pcap_fixtures.hpp"

#include <cstdint>
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

void put8(std::vector<std::uint8_t>& b, std::size_t off, std::uint8_t v) { b[off] = v; }
void put16(std::vector<std::uint8_t>& b, std::size_t off, std::uint16_t v) {
    b[off] = static_cast<std::uint8_t>(v >> 8);
    b[off + 1] = static_cast<std::uint8_t>(v);
}
void put_tag(std::vector<std::uint8_t>& b, std::uint8_t wt, std::uint16_t id) {
    b.push_back(static_cast<std::uint8_t>((wt << 4) | ((id >> 8) & 0x0F)));
    b.push_back(static_cast<std::uint8_t>(id & 0xFF));
}

std::vector<std::uint8_t> build_udp(std::uint16_t src, std::uint16_t dst,
                                    const std::vector<std::uint8_t>& payload) {
    std::vector<std::uint8_t> b(42, 0);
    put16(b, 12, 0x0800);
    put8(b, 14, 0x45);
    put8(b, 23, 17);
    put16(b, 34, src);
    put16(b, 36, dst);
    put16(b, 38, static_cast<std::uint16_t>(8 + payload.size()));
    b.insert(b.end(), payload.begin(), payload.end());
    return b;
}

// Wrap one Ethernet frame in a minimal little-endian pcapng (SHB + IDB link_type 1 + one EPB).
std::vector<std::uint8_t> one_packet_pcapng(const std::vector<std::uint8_t>& frame) {
    pcapfix::Builder b(true);
    pcapfix::append_block(b, pcapblocks::kBlockTypeShb, pcapfix::shb_body(true));
    pcapfix::append_block(b, pcapblocks::kBlockTypeIdb, pcapfix::idb_body(true, 1, 6));
    pcapfix::append_block(b, pcapblocks::kBlockTypeEpb,
                          pcapfix::epb_body(true, 0, 0, static_cast<std::uint32_t>(frame.size()),
                                            static_cast<std::uint32_t>(frame.size()), frame, 0));
    return b.bytes;
}

void run_capture(dpar_example::Engine& engine, const std::vector<std::uint8_t>& cap) {
    std::string err;
    std::vector<pcapblocks::BlockRef> refs;
    CHECK(pcapblocks::scan_blocks(pcapblocks::Bytes(cap.data(), cap.size()), refs, err));
    std::uint64_t pid = 0;
    for (const pcapblocks::BlockRef& ref : refs) {
        if (ref.kind != pcapblocks::Kind::Epb && ref.kind != pcapblocks::Kind::PcapRecord) {
            continue;
        }
        pcapblocks::EpbView e{};
        if (pcapblocks::parse_epb(pcapblocks::Bytes(cap.data(), cap.size()), ref, e)) {
            engine.run(cap.data() + e.payload_file_offset, e.caplen, pid++);
        }
    }
}

}  // namespace

int main() {
    // A UDP packet whose payload is two SOME/IP-TLV members.
    std::vector<std::uint8_t> payload;
    put_tag(payload, 0, 0x011);
    payload.push_back(0x42);
    put_tag(payload, 5, 0x022);
    payload.push_back(0x01);
    payload.push_back(0x99);
    const auto frame = build_udp(0, 9999, payload);
    const auto cap = one_packet_pcapng(frame);

    // ---- the headline rule end-to-end --------------------------------------------------------------
    {
        dpar_example::Engine engine;
        auto cr = engine.load_rules(
            "udp.src_port == 0 && udp.dst_port == 9999 => someip_tlv udp_payload XYZtlv\n");
        CHECK(cr.ok);
        CHECK(engine.rule_count() == 1);

        run_capture(engine, cap);

        std::string out;
        engine.dump_ndjson(out);
        // Two members => two NDJSON rows, both from the someip_tlv table with rule_id 0.
        CHECK(out.find("\"table\":\"someip_tlv\"") != std::string::npos);
        CHECK(out.find("\"data_id\":17") != std::string::npos);   // 0x011
        CHECK(out.find("\"data_id\":34") != std::string::npos);   // 0x022
        CHECK(out.find("\"rule_id\":0") != std::string::npos);
        std::size_t lines = 0;
        for (char ch : out) {
            if (ch == '\n') ++lines;
        }
        CHECK(lines == 2);

        CHECK(engine.stats().packets_seen == 1);
        CHECK(engine.stats().packets_matched_any == 1);
        CHECK(engine.stats().rows_emitted == 2);
    }

    // ---- a non-matching rule emits nothing (opt-in / no false fire) --------------------------------
    {
        dpar_example::Engine engine;
        CHECK(engine.load_rules("udp.dst_port == 1234 => someip_tlv udp_payload none\n").ok);
        run_capture(engine, cap);
        std::string out;
        engine.dump_ndjson(out);
        CHECK(out.empty());
        CHECK(engine.stats().packets_matched_any == 0);
    }

    std::printf("dpar_example: ok (headline rule end-to-end over pcapng, NDJSON rows, stats, no false fire)\n");
    return 0;
}
