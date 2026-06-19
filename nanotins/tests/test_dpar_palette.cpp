// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Yoav Bendor

// DPAR parser palette + engine (nanotins/dpar_palette.hpp): the boost/SoA tier on top of the matching
// engine. Covers:
//   P1  the built-in someip_tlv Kind emits SomeipTlvRow rows into its SoA-backed table with the right
//       discriminator (rule_id) when the headline rule fires
//   P2  one table per Kind, shared by every rule selecting it; rows discriminated by rule_id
//   P3  a DOWNSTREAM user Kind (defined here, not in nanotins) composes into the palette and is selectable
//       by name from a rule — the "bring your own parser, no fork" guarantee
//   P4  end-to-end engine: load_rules + run over packets, observability counters, materialize to soatins::soa

#include "nanotins/dpar_palette.hpp"

#include "soatins/reflect.hpp"

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <string>
#include <vector>

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

// ---- a DOWNSTREAM user Kind: defined in this TU, not in nanotins. It walks SOME/IP-TLV members and, for
// each len16 "array descriptor" member, parses its elements with the simple TLV cursor — exactly the
// "build your own parser on the lib cursors + struct->SoA->Arrow" path. ------------------------------
struct OddTlvRow {
    std::uint64_t packet_id;
    std::uint32_t rule_id;
    std::uint32_t elem_index;
    std::uint16_t array_id;
    std::uint16_t elem_size;
    std::uint16_t elem_count;
    std::uint16_t elem_data_id;
};
BOOST_DESCRIBE_STRUCT(OddTlvRow, (), (packet_id, rule_id, elem_index, array_id, elem_size, elem_count, elem_data_id))

struct OddTlvKind {
    using Row = OddTlvRow;
    static constexpr const char* name() { return "oddtlv"; }
    static std::size_t emit(std::uint64_t pid, std::uint32_t rule_id, const std::uint8_t* p,
                            const std::uint8_t* end, std::vector<Row>& out) {
        nanotins::someip_tlv_cursor c{p, end};
        nanotins::someip_tlv_record r{};
        std::size_t n = 0;
        while (c.next(r)) {
            if (r.wire_type == nanotins::kSomeipTlvWtLen16 && r.length >= 4 && r.value != nullptr) {
                const std::uint16_t esz = static_cast<std::uint16_t>((r.value[0] << 8) | r.value[1]);
                const std::uint16_t cnt = static_cast<std::uint16_t>((r.value[2] << 8) | r.value[3]);
                const std::uint8_t* q = r.value + 4;
                for (std::uint16_t i = 0; i < cnt && q + esz <= end; ++i) {
                    nanotins::someip_tlv_cursor ec{q, q + esz};
                    nanotins::someip_tlv_record er{};
                    if (ec.next(er)) {
                        out.push_back(Row{pid, rule_id, i, r.data_id, esz, cnt, er.data_id});
                        ++n;
                    }
                    q += esz;
                }
            }
        }
        return n;
    }
};

}  // namespace

int main() {
    using G = nanotins::L2L3Graph;

    // ---- P1/P2/P4: built-in someip_tlv Kind, end-to-end via the engine ------------------------------
    {
        dpar::dpar_engine<G, dpar::DefaultPalette> engine;  // built-ins: someip_tlv, raw_tlv
        dpar::CompileResult cr = engine.load_rules(
            "udp.dst_port == 9999 => someip_tlv udp_payload A\n"
            "udp.dst_port == 9999 => someip_tlv udp_payload B\n");  // two rules, same Kind/table
        CHECK(cr.ok);
        CHECK(engine.rule_count() == 2);

        // payload: two SOME/IP-TLV members.
        std::vector<std::uint8_t> payload;
        put_tag(payload, 0, 0x011);
        payload.push_back(0x42);
        put_tag(payload, 5, 0x022);
        payload.push_back(0x01);
        payload.push_back(0x99);

        auto pkt = build_udp(0, 9999, payload);
        engine.run(pkt.data(), pkt.size(), /*pid=*/5);

        auto& table = std::get<0>(engine.palette.tables);  // SomeipTlvRow table
        CHECK(table.size() == 4);  // 2 members x 2 rules
        // rows 0,1 from rule 0; rows 2,3 from rule 1 (deterministic rule order).
        CHECK(table[0].rule_id == 0 && table[0].data_id == 0x011 && table[0].member_index == 0);
        CHECK(table[1].rule_id == 0 && table[1].data_id == 0x022 && table[1].length == 1);
        CHECK(table[2].rule_id == 1 && table[2].data_id == 0x011);
        CHECK(table[3].rule_id == 1 && table[3].data_id == 0x022);
        CHECK(table[0].packet_id == 5);

        CHECK(engine.stats.packets_matched_any == 1);
        CHECK(engine.stats.per_rule[0].rows_emitted == 2 && engine.stats.per_rule[1].rows_emitted == 2);

        // raw_tlv table stayed empty (no rule selected it) — pay only for what you use.
        CHECK(std::get<1>(engine.palette.tables).empty());

        // The described Row materializes into a soatins::soa for Arrow with zero glue.
        auto& rows = std::get<0>(engine.palette.tables);
        soatins::soa<dpar::SomeipTlvRow> s;
        s.resize(rows.size());
        for (std::size_t i = 0; i < rows.size(); ++i) {
            s.store(i, rows[i]);
        }
        CHECK(s.size() == 4);
        CHECK(s.column<0>()[0] == 5);  // packet_id column
    }

    // ---- P3: a downstream user Kind composed into the palette, selected by a rule -------------------
    {
        using MyPalette = dpar::parser_palette<dpar::SomeipTlvKind, dpar::RawTlvKind, OddTlvKind>;
        dpar::dpar_engine<G, MyPalette> engine;
        dpar::CompileResult cr = engine.load_rules("udp.dst_port == 9999 => oddtlv udp_payload mine\n");
        CHECK(cr.ok);

        // payload: one len16 "array" member: elem_size=3, count=2, then 2 elements each a 1-byte TLV base
        // member (8-bit base => tag(2) + value(1) = 3 bytes per element).
        std::vector<std::uint8_t> arr;
        arr.push_back(0x00); arr.push_back(0x03);  // elem_size = 3
        arr.push_back(0x00); arr.push_back(0x02);  // count = 2
        // element 0: 8-bit base, id 0x100, value 0xAA
        arr.push_back(static_cast<std::uint8_t>((0 << 4) | 0x01)); arr.push_back(0x00); arr.push_back(0xAA);
        // element 1: 8-bit base, id 0x101, value 0xBB
        arr.push_back(static_cast<std::uint8_t>((0 << 4) | 0x01)); arr.push_back(0x01); arr.push_back(0xBB);

        std::vector<std::uint8_t> payload;
        put_tag(payload, nanotins::kSomeipTlvWtLen16, 0x055);  // len16 array descriptor, id 0x055
        payload.push_back(static_cast<std::uint8_t>(arr.size() >> 8));
        payload.push_back(static_cast<std::uint8_t>(arr.size()));
        payload.insert(payload.end(), arr.begin(), arr.end());

        auto pkt = build_udp(0, 9999, payload);
        engine.run(pkt.data(), pkt.size(), 1);

        auto& odd = std::get<2>(engine.palette.tables);  // OddTlvRow table
        CHECK(odd.size() == 2);
        CHECK(odd[0].array_id == 0x055 && odd[0].elem_count == 2 && odd[0].elem_size == 3);
        CHECK(odd[0].elem_data_id == 0x100 && odd[0].elem_index == 0);
        CHECK(odd[1].elem_data_id == 0x101 && odd[1].elem_index == 1);
    }

    // ---- bonus: opt-in — a constructed engine with no rules loaded does nothing ---------------------
    {
        dpar::dpar_engine<G, dpar::DefaultPalette> engine;
        auto pkt = build_udp(0, 9999, {0x01, 0x02});
        engine.run(pkt.data(), pkt.size(), 0);
        CHECK(engine.stats.packets_seen == 0);
        CHECK(std::get<0>(engine.palette.tables).empty());
    }

    std::printf("dpar_palette: ok (someip_tlv rows+discriminator, per-Kind table, user Kind, soa materialize, opt-in)\n");
    return 0;
}
