// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Yoav Bendor

// In-process tests for the LLDP example: the bounded lldp_cursor (TLV walk, End-TLV stop, truncation),
// and the full "user parser applied via a DPAR rule" path (eth/0x88CC frame -> one-packet pcapng -> the
// Engine -> per-TLV rows + NDJSON). Exercises the example without spawning the CLI.

#include "lldp.hpp"

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

using lldp_example::LldpTlvRow;
using lldp_example::lldp_cursor;
using lldp_example::lldp_tlv_record;

// Append one LLDP TLV: 2-byte header [type:7][length:9] (big-endian) then the value bytes.
void put_tlv(std::vector<std::uint8_t>& b, std::uint16_t type, const std::vector<std::uint8_t>& value) {
    const std::uint16_t hdr = static_cast<std::uint16_t>((type << 9) | (value.size() & 0x01FF));
    b.push_back(static_cast<std::uint8_t>(hdr >> 8));
    b.push_back(static_cast<std::uint8_t>(hdr & 0xFF));
    b.insert(b.end(), value.begin(), value.end());
}
std::vector<std::uint8_t> bytes_of(const char* s) {
    return std::vector<std::uint8_t>(s, s + std::char_traits<char>::length(s));
}

// A canonical LLDPDU: Chassis ID (MAC), Port ID ("Gi0/1"), TTL=120, System Name ("switch01"), End.
std::vector<std::uint8_t> build_lldpdu() {
    std::vector<std::uint8_t> b;
    put_tlv(b, lldp_example::kLldpChassisId, {4, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55});  // subtype 4 (MAC)
    {
        std::vector<std::uint8_t> v = {5};  // subtype 5 (interface name)
        auto name = bytes_of("Gi0/1");
        v.insert(v.end(), name.begin(), name.end());
        put_tlv(b, lldp_example::kLldpPortId, v);
    }
    put_tlv(b, lldp_example::kLldpTtl, {0x00, 0x78});  // 120 seconds
    put_tlv(b, lldp_example::kLldpSysName, bytes_of("switch01"));
    put_tlv(b, lldp_example::kLldpEnd, {});  // End of LLDPDU
    return b;
}

// Wrap an LLDPDU as the payload of an Ethernet frame (EtherType 0x88CC, 14-byte header).
std::vector<std::uint8_t> build_eth_lldp(const std::vector<std::uint8_t>& lldpdu) {
    std::vector<std::uint8_t> f(14, 0);
    const std::uint8_t dst[6] = {0x01, 0x80, 0xC2, 0x00, 0x00, 0x0E};  // LLDP multicast
    for (int i = 0; i < 6; ++i) {
        f[i] = dst[i];
    }
    f[12] = static_cast<std::uint8_t>(lldp_example::kLldpEtherType >> 8);
    f[13] = static_cast<std::uint8_t>(lldp_example::kLldpEtherType & 0xFF);
    f.insert(f.end(), lldpdu.begin(), lldpdu.end());
    return f;
}

std::vector<std::uint8_t> one_packet_pcapng(const std::vector<std::uint8_t>& frame) {
    pcapfix::Builder b(true);
    pcapfix::append_block(b, pcapblocks::kBlockTypeShb, pcapfix::shb_body(true));
    pcapfix::append_block(b, pcapblocks::kBlockTypeIdb, pcapfix::idb_body(true, 1, 6));  // link_type 1 = Ethernet
    pcapfix::append_block(b, pcapblocks::kBlockTypeEpb,
                          pcapfix::epb_body(true, 0, 0, static_cast<std::uint32_t>(frame.size()),
                                            static_cast<std::uint32_t>(frame.size()), frame, 0));
    return b.bytes;
}

void run_capture(lldp_example::Engine& engine, const std::vector<std::uint8_t>& cap) {
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

std::string head_ascii(const LldpTlvRow& r) {
    std::string s;
    const std::size_t n = r.tlv_length < r.value_head.size() ? r.tlv_length : r.value_head.size();
    for (std::size_t i = 0; i < n; ++i) {
        s += static_cast<char>(r.value_head[i]);
    }
    return s;
}

}  // namespace

int main() {
    // ---- 1: the lldp_cursor walks a TLV sequence, stops at the End TLV ------------------------------
    {
        const auto pdu = build_lldpdu();
        lldp_cursor c{pdu.data(), pdu.data() + pdu.size()};
        lldp_tlv_record r{};
        std::vector<lldp_tlv_record> recs;
        while (c.next(r)) {
            recs.push_back(r);
        }
        CHECK(recs.size() == 4);  // chassis, port, ttl, sysname — End is NOT emitted (it terminates)
        CHECK(recs[0].type == lldp_example::kLldpChassisId && recs[0].length == 7 && recs[0].value[0] == 4);
        CHECK(recs[1].type == lldp_example::kLldpPortId && recs[1].value[0] == 5);
        CHECK(recs[2].type == lldp_example::kLldpTtl && recs[2].length == 2 &&
              recs[2].value[0] == 0x00 && recs[2].value[1] == 0x78);
        CHECK(recs[3].type == lldp_example::kLldpSysName && recs[3].length == 8);
    }

    // ---- 2: truncation — a TLV claiming more bytes than remain stops the walk, no OOB --------------
    {
        std::vector<std::uint8_t> b;
        put_tlv(b, lldp_example::kLldpSysName, bytes_of("ok"));  // a clean TLV
        // a header claiming length 100 with no value bytes:
        const std::uint16_t hdr = static_cast<std::uint16_t>((lldp_example::kLldpSysDesc << 9) | 100);
        b.push_back(static_cast<std::uint8_t>(hdr >> 8));
        b.push_back(static_cast<std::uint8_t>(hdr & 0xFF));
        lldp_cursor c{b.data(), b.data() + b.size()};
        lldp_tlv_record r{};
        int count = 0;
        while (c.next(r)) {
            ++count;
        }
        CHECK(count == 1);  // only the first TLV; the truncated one is refused
    }

    // ---- 3: end-to-end — the rule applies LLDP over the L2 payload, rows are correct ---------------
    {
        const auto cap = one_packet_pcapng(build_eth_lldp(build_lldpdu()));
        lldp_example::Engine engine;
        CHECK(engine.load_rules("eth.ethertype == 0x88CC => lldp eth_payload \"lldp\"\n").ok);
        CHECK(engine.rule_count() == 1);

        run_capture(engine, cap);

        const auto& rows = engine.table();
        CHECK(rows.size() == 4);
        // Chassis ID: subtype 4, value_offset 0 (first TLV value sits at payload start).
        CHECK(rows[0].tlv_type == lldp_example::kLldpChassisId && rows[0].subtype == 4);
        CHECK(rows[0].value_offset == 2);  // 2-byte TLV header precedes the value
        // Port ID: subtype 5, name visible in value_head after the subtype byte.
        CHECK(rows[1].tlv_type == lldp_example::kLldpPortId && rows[1].subtype == 5);
        CHECK(head_ascii(rows[1]) == std::string("\x05") + "Gi0/1");
        // TTL = 120.
        CHECK(rows[2].tlv_type == lldp_example::kLldpTtl &&
              (rows[2].value_head[0] << 8 | rows[2].value_head[1]) == 120);
        // System Name is fully visible in value_head.
        CHECK(rows[3].tlv_type == lldp_example::kLldpSysName);
        CHECK(head_ascii(rows[3]) == "switch01");
        // Every row carries the packet + rule discriminator.
        for (const auto& row : rows) {
            CHECK(row.packet_id == 0 && row.rule_id == 0);
        }

        CHECK(engine.stats().packets_seen == 1);
        CHECK(engine.stats().packets_matched_any == 1);
        CHECK(engine.stats().rows_emitted == 4);

        // NDJSON renders the system name in the ascii preview.
        std::string out;
        engine.dump_ndjson(out);
        CHECK(out.find("\"type_name\":\"system_name\"") != std::string::npos);
        CHECK(out.find("\"ascii\":\"switch01\"") != std::string::npos);
        std::size_t lines = 0;
        for (char ch : out) {
            if (ch == '\n') ++lines;
        }
        CHECK(lines == 4);
    }

    // ---- 4: a non-LLDP frame (different EtherType) produces no rows (no false fire) -----------------
    {
        auto frame = build_eth_lldp(build_lldpdu());
        frame[12] = 0x08;  // change EtherType to 0x0800 (IPv4) -> the rule must not match
        frame[13] = 0x00;
        const auto cap = one_packet_pcapng(frame);
        lldp_example::Engine engine;
        CHECK(engine.load_rules("eth.ethertype == 0x88CC => lldp eth_payload \"lldp\"\n").ok);
        run_capture(engine, cap);
        CHECK(engine.table().empty());
        CHECK(engine.stats().packets_matched_any == 0);
    }

    std::printf("lldp: ok (cursor walk+End stop, truncation, end-to-end eth_payload rule, no false fire)\n");
    return 0;
}
