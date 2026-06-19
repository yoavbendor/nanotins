// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Yoav Bendor

// DPAR matching engine (nanotins/dpar.hpp), standalone over the dependency-light core (no boost / SoA /
// Arrow). Covers:
//   1  build_field_catalog resolves udp/ipv4/someip fields to the right offset/width/endian; bad names absent
//   2  read_field_runtime == struct_view/read_field for every catalogued field (the parity oracle)
//   3  every comparator (== < > <= >=); a missing layer makes a predicate false (no false match)
//   4  the headline rule (udp.src_port==0 && udp.dst_port==9999 => someip_tlv udp_payload) fires and hands
//      over the correct region bytes (verified by running someip_tlv_cursor on it)
//   5  multi-rule all-match: rules route to their own parser_kind index, deterministic order
//   6  init-time validation rejects unknown field / bad op / operand overflow / unknown parser / region
//   7  observability counters (matched, rows_emitted, packets_matched_any, rules_evaluated)
//   8  truncation: a clipped payload yields a bounded region, never OOB
//   9  opt-in: an empty ruleset does no work and emits nothing
//  10  extensibility: a rule may name any palette Kind by string; the index is resolved and routed

#include "nanotins/dpar.hpp"
#include "nanotins/someip_tlv.hpp"
#include "nanotins/wire_spec.hpp"

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <string>
#include <vector>

using namespace nanotins::literals;
namespace dpar = nanotins::dpar;

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

// Append a 2-byte big-endian SOME/IP TLV tag (reserved(1) | wire_type(3) | data_id(12)).
void put_tag(std::vector<std::uint8_t>& b, std::uint8_t wt, std::uint16_t id) {
    b.push_back(static_cast<std::uint8_t>((wt << 4) | ((id >> 8) & 0x0F)));
    b.push_back(static_cast<std::uint8_t>(id & 0xFF));
}

// Build eth/ipv4/udp framing (UDP at byte 34, payload at 42) with the given ports + a trailing payload.
// Ports are arbitrary — DPAR triggers on the config rule, not a wire-known port, so SOME/IP need not frame.
std::vector<std::uint8_t> build_udp(std::uint16_t src, std::uint16_t dst,
                                    const std::vector<std::uint8_t>& payload) {
    std::vector<std::uint8_t> b(42, 0);
    put16(b, 12, 0x0800);  // ethertype IPv4
    put8(b, 14, 0x45);     // version 4, IHL 5
    put8(b, 23, 17);       // protocol UDP
    put16(b, 34, src);
    put16(b, 36, dst);
    put16(b, 38, static_cast<std::uint16_t>(8 + payload.size()));  // UDP length
    b.insert(b.end(), payload.begin(), payload.end());
    return b;
}

// A recording sink: captures every (kind, pid, rule_id, region) handed over by the matcher.
struct Hit {
    std::uint16_t kind;
    std::uint64_t pid;
    std::uint32_t rule_id;
    std::vector<std::uint8_t> region;
};

}  // namespace

int main() {
    using G = nanotins::L2L3Graph;
    const auto cat = dpar::build_l2l3_catalog();

    // ---- 1: catalog resolves fields to the right location -------------------------------------------
    {
        const dpar::CatalogEntry* dp = dpar::find_field(cat, "udp", "dst_port");
        CHECK(dp != nullptr);
        CHECK(dp->ref.offset == 2 && dp->ref.byte_width == 2 && dp->ref.big_endian == 1 &&
              dp->ref.is_bitfield == 0);
        CHECK(dp->ref.node_id == static_cast<std::uint16_t>(nanotins::node_id_v<nanotins::UdpNode, G>));

        const dpar::CatalogEntry* ihl = dpar::find_field(cat, "ipv4", "ihl");
        CHECK(ihl != nullptr && ihl->ref.is_bitfield == 1 && ihl->ref.bit_offset == 4 &&
              ihl->ref.bit_width == 4 && ihl->ref.byte_width == 1);

        const dpar::CatalogEntry* svc = dpar::find_field(cat, "someip", "service_id");
        CHECK(svc != nullptr && svc->ref.offset == 0 && svc->ref.byte_width == 2);

        // A byte-array field (an address) is not a predicate target -> absent from the catalog.
        CHECK(dpar::find_field(cat, "ipv4", "src") == nullptr);
        // Bogus names are absent.
        CHECK(dpar::find_field(cat, "udp", "nope") == nullptr);
        CHECK(dpar::find_field(cat, "nope", "dst_port") == nullptr);
    }

    // ---- 2: read_field_runtime parity vs struct_view, over a real packet ----------------------------
    {
        auto b = build_udp(0x1234, 0x5678, {0xAA, 0xBB});
        nanotins::struct_view<nanotins::UdpSpec> uv(b.data() + 34);
        const dpar::CatalogEntry* sp = dpar::find_field(cat, "udp", "src_port");
        const dpar::CatalogEntry* dpf = dpar::find_field(cat, "udp", "dst_port");
        CHECK(dpar::read_field_runtime(b.data() + 34, sp->ref) == uv("src_port"_fld));
        CHECK(dpar::read_field_runtime(b.data() + 34, dpf->ref) == uv("dst_port"_fld));

        // bit-fields: ipv4 version/ihl at byte 14 (0x45 -> version 4, ihl 5).
        nanotins::struct_view<nanotins::Ipv4Spec> iv(b.data() + 14);
        const dpar::CatalogEntry* ver = dpar::find_field(cat, "ipv4", "version");
        const dpar::CatalogEntry* ih = dpar::find_field(cat, "ipv4", "ihl");
        CHECK(dpar::read_field_runtime(b.data() + 14, ver->ref) == iv("version"_fld));
        CHECK(dpar::read_field_runtime(b.data() + 14, ih->ref) == iv("ihl"_fld));
        CHECK(dpar::read_field_runtime(b.data() + 14, ver->ref) == 4);
        CHECK(dpar::read_field_runtime(b.data() + 14, ih->ref) == 5);
    }

    // Parser palette names used by the matching tests (mirrors the real palette without pulling in SoA).
    const std::vector<std::string> parsers = {"someip_tlv", "raw_tlv", "oddtlv"};

    // A reusable runner: compile a rules text, run it over one packet, record the hits.
    auto run_rules = [&](const std::string& text, const std::vector<std::uint8_t>& pkt, std::uint64_t pid,
                         dpar::EngineStats& stats) {
        std::vector<Hit> hits;
        dpar::CompileResult cr = dpar::compile_rules(text, cat, parsers);
        CHECK(cr.ok);
        dpar::dpar_match<G>(cr.rules, pkt.data(), pkt.size(), pid, stats,
                            [&](std::uint16_t kind, std::uint64_t p, std::uint32_t rid,
                                const std::uint8_t* b, const std::uint8_t* e) -> std::size_t {
                                hits.push_back(Hit{kind, p, rid,
                                                   std::vector<std::uint8_t>(b, e)});
                                return static_cast<std::size_t>(e - b);  // pretend 1 row per byte for stats
                            });
        return hits;
    };

    // ---- 3: comparators + missing-layer safety ------------------------------------------------------
    {
        auto pkt = build_udp(0, 9999, {0x01});
        dpar::EngineStats st;
        // eq true, then a battery of comparators on dst_port (9999).
        auto hits = run_rules(
            "udp.dst_port == 9999 => someip_tlv udp_payload t1\n"
            "udp.dst_port < 10000 => someip_tlv udp_payload t2\n"
            "udp.dst_port > 9998  => someip_tlv udp_payload t3\n"
            "udp.dst_port <= 9999 => someip_tlv udp_payload t4\n"
            "udp.dst_port >= 9999 => someip_tlv udp_payload t5\n"
            "udp.dst_port == 1234 => someip_tlv udp_payload t6\n"          // no match (wrong value)
            "tcp.dst_port == 9999 => someip_tlv tcp_payload t7\n",         // no match (no TCP layer present)
            pkt, 1, st);
        CHECK(hits.size() == 5);  // rules 0..4 match, 5 and 6 do not
        CHECK(st.rules_evaluated == 7);
        CHECK(st.packets_matched_any == 1);
    }

    // ---- 4: the headline rule + correct region bytes ------------------------------------------------
    {
        // UDP payload = two SOME/IP-TLV members: an 8-bit base (id 1, value 0x42) and a len8 (id 2, "ab").
        std::vector<std::uint8_t> payload;
        put_tag(payload, 0, 0x001);
        payload.push_back(0x42);
        put_tag(payload, 5, 0x002);
        payload.push_back(0x02);
        payload.push_back('a');
        payload.push_back('b');

        auto pkt = build_udp(0, 9999, payload);
        dpar::EngineStats st;
        auto hits =
            run_rules("udp.src_port == 0 && udp.dst_port == 9999 => someip_tlv udp_payload XYZtlv\n", pkt, 7, st);
        CHECK(hits.size() == 1);
        CHECK(hits[0].kind == 0);  // someip_tlv index
        CHECK(hits[0].pid == 7);
        CHECK(hits[0].rule_id == 0);
        // The region must be exactly the UDP payload (byte 42 onward).
        CHECK(hits[0].region == payload);
        // ...and it parses as the two TLV members we wrote.
        nanotins::someip_tlv_cursor c{hits[0].region.data(), hits[0].region.data() + hits[0].region.size()};
        nanotins::someip_tlv_record r{};
        CHECK(c.next(r) && r.data_id == 0x001 && r.wire_type == 0 && r.length == 1 && r.value[0] == 0x42);
        CHECK(c.next(r) && r.data_id == 0x002 && r.wire_type == 5 && r.length == 2 && r.value[1] == 'b');
        CHECK(!c.next(r));
    }

    // ---- 5: multi-rule all-match routes to distinct parser_kind indices -----------------------------
    {
        auto pkt = build_udp(100, 9999, {0xDE, 0xAD});
        dpar::EngineStats st;
        auto hits = run_rules(
            "udp.dst_port == 9999 => someip_tlv udp_payload a\n"
            "udp.dst_port == 9999 => raw_tlv    udp_payload b\n"
            "udp.dst_port == 9999 => oddtlv     udp_payload c\n",
            pkt, 0, st);
        CHECK(hits.size() == 3);
        CHECK(hits[0].kind == 0 && hits[1].kind == 1 && hits[2].kind == 2);  // someip_tlv, raw_tlv, oddtlv
        CHECK(hits[0].rule_id == 0 && hits[1].rule_id == 1 && hits[2].rule_id == 2);
    }

    // ---- 5b: the L2 eth_payload region (anchor eth, +14) — used by link-layer parsers like LLDP -----
    {
        // An Ethernet frame with EtherType 0x88CC (LLDP) and a 3-byte payload after the 14-byte header.
        // 0x88CC has no DAG edge, so the walk stops at eth (present), and eth_payload begins at byte 14.
        std::vector<std::uint8_t> pkt(14 + 3, 0);
        put16(pkt, 12, 0x88CC);
        pkt[14] = 0xAA;
        pkt[15] = 0xBB;
        pkt[16] = 0xCC;
        dpar::EngineStats st;
        auto hits = run_rules("eth.ethertype == 0x88CC => raw_tlv eth_payload lldpish\n", pkt, 0, st);
        CHECK(hits.size() == 1);
        CHECK(hits[0].kind == 1);  // raw_tlv
        CHECK((hits[0].region == std::vector<std::uint8_t>{0xAA, 0xBB, 0xCC}));  // exactly the L2 payload
    }

    // ---- 5c: the vlan_payload region (anchor vlan, +4) — 802.1Q-tagged link-layer payload -----------
    {
        // eth(0x8100) + 802.1Q tag (TCI + inner ethertype 0x88CC at byte 16) + a 3-byte payload at 18.
        // The walk descends eth -> vlan and stops (inner 0x88CC has no edge), so vlan is present at 14.
        std::vector<std::uint8_t> pkt(18 + 3, 0);
        put16(pkt, 12, 0x8100);   // eth EtherType = 802.1Q
        put16(pkt, 16, 0x88CC);   // inner (post-tag) EtherType = LLDP
        pkt[18] = 0xDE;
        pkt[19] = 0xAD;
        pkt[20] = 0xBE;
        dpar::EngineStats st;
        auto hits = run_rules("vlan.inner_ethertype == 0x88CC => raw_tlv vlan_payload tagged\n", pkt, 0, st);
        CHECK(hits.size() == 1);
        CHECK(hits[0].kind == 1);  // raw_tlv
        CHECK((hits[0].region == std::vector<std::uint8_t>{0xDE, 0xAD, 0xBE}));  // payload after the VLAN tag
    }

    // ---- 6: init-time validation collects every problem --------------------------------------------
    {
        dpar::CompileResult cr = dpar::compile_rules(
            "udp.bogus == 1 => someip_tlv udp_payload x\n"           // unknown field
            "udp.dst_port ~~ 1 => someip_tlv udp_payload x\n"        // bad comparator
            "udp.dst_port == 70000 => someip_tlv udp_payload x\n"    // overflow (16-bit field)
            "udp.dst_port == 1 => no_such_parser udp_payload x\n"    // unknown parser
            "udp.dst_port == 1 => someip_tlv no_region x\n",         // unknown region
            cat, parsers);
        CHECK(!cr.ok);
        CHECK(cr.rules.empty());
        CHECK(cr.errors.size() == 5);
    }
    {
        // A well-formed file compiles cleanly (and assigns sequential rule_ids).
        dpar::CompileResult cr = dpar::compile_rules(
            "# a comment line\n"
            "udp.dst_port == 9999 => someip_tlv udp_payload first\n"
            "\n"
            "ipv4.ttl >= 1 => raw_tlv udp_payload second\n",
            cat, parsers);
        CHECK(cr.ok);
        CHECK(cr.rules.size() == 2);
        CHECK(cr.rules[0].rule_id == 0 && cr.rules[1].rule_id == 1);
        CHECK(std::string(cr.rules[0].name) == "first");
        CHECK(cr.rules[1].parser_kind == 1);  // raw_tlv
    }

    // ---- 7: observability counters ------------------------------------------------------------------
    {
        dpar::CompileResult cr = dpar::compile_rules(
            "udp.dst_port == 9999 => someip_tlv udp_payload hit\n"
            "udp.dst_port == 1234 => someip_tlv udp_payload miss\n",
            cat, parsers);
        CHECK(cr.ok);
        dpar::EngineStats st;
        for (std::uint64_t i = 0; i < 3; ++i) {
            auto pkt = build_udp(0, 9999, {0xAA, 0xBB, 0xCC});  // 3-byte region
            dpar::dpar_match<G>(cr.rules, pkt.data(), pkt.size(), i, st,
                                [&](std::uint16_t, std::uint64_t, std::uint32_t, const std::uint8_t* b,
                                    const std::uint8_t* e) { return static_cast<std::size_t>(e - b); });
        }
        CHECK(st.packets_seen == 3);
        CHECK(st.packets_matched_any == 3);
        CHECK(st.rules_evaluated == 6);  // 2 rules x 3 packets
        CHECK(st.per_rule[0].matched == 3 && st.per_rule[0].rows_emitted == 9);  // 3 bytes x 3 packets
        CHECK(st.per_rule[1].matched == 0 && st.per_rule[1].rows_emitted == 0);
        CHECK(st.rows_emitted == 9);
    }

    // ---- 8: truncated payload -> bounded region, never OOB ------------------------------------------
    {
        auto pkt = build_udp(0, 9999, {0x01, 0x02, 0x03, 0x04});
        pkt.resize(44);  // clip so only 2 payload bytes remain captured
        dpar::EngineStats st;
        auto hits = run_rules("udp.dst_port == 9999 => someip_tlv udp_payload t\n", pkt, 0, st);
        CHECK(hits.size() == 1);
        CHECK(hits[0].region.size() == 2);  // region clamped to captured bytes (44 - 42)
    }

    // ---- 9: opt-in — empty ruleset does no work -----------------------------------------------------
    {
        std::vector<dpar::Rule> none;
        dpar::EngineStats st;
        auto pkt = build_udp(0, 9999, {0x01});
        bool called = false;
        dpar::dpar_match<G>(none, pkt.data(), pkt.size(), 0, st,
                            [&](std::uint16_t, std::uint64_t, std::uint32_t, const std::uint8_t*,
                                const std::uint8_t*) {
                                called = true;
                                return std::size_t{0};
                            });
        CHECK(!called);
        CHECK(st.packets_seen == 0 && st.rules_evaluated == 0 && st.rows_emitted == 0);
    }

    // ---- 10: extensibility — any palette name resolves + routes by index ----------------------------
    {
        // "oddtlv" is a downstream Kind (index 2 here); a rule names it like any built-in.
        auto pkt = build_udp(0, 9999, {0x01});
        dpar::EngineStats st;
        auto hits = run_rules("udp.dst_port == 9999 => oddtlv udp_payload mine\n", pkt, 0, st);
        CHECK(hits.size() == 1 && hits[0].kind == 2);
    }

    std::printf(
        "dpar: ok (catalog, read_field parity, comparators+missing-layer, headline rule region, "
        "multi-rule routing, validation, observability, truncation, opt-in, extensibility)\n");
    return 0;
}
